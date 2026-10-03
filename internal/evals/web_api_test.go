//go:build evals

package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/worker"
)

func TestWebAPIFixtureBehavior(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is needed to exercise the fixture")
	}
	const script = `import runpy, sys
from http.cookies import SimpleCookie
sys.path.insert(0, '../../evals/fixtures/web-api-app/services/site')
m = runpy.run_path('../../evals/fixtures/web-api-app/services/site/server.py')
dispatch = m['dispatch']
assert dispatch('GET', '/api/email?email=attacker@example.test', {})[0] == 401
status, headers, _ = dispatch('POST', '/login', {}, 'username=demo&password=demo-password')
assert status == 200
cookie = SimpleCookie(headers['Set-Cookie'])
session = {'Cookie': 'session=' + cookie['session'].value, 'Origin': 'https://attacker.test'}
assert dispatch('GET', '/api/email?email=attacker@example.test', session)[0] == 200
_, _, account = dispatch('GET', '/api/account', session)
assert account['email'] == 'attacker@example.test'
assert dispatch('POST', '/api/display-name', session, 'name=changed&csrf=' + account['csrf'])[0] == 403
session['Origin'] = m['ORIGIN']
assert dispatch('POST', '/api/display-name', session, 'name=changed')[0] == 403
assert dispatch('POST', '/api/display-name', session, 'name=changed&csrf=' + account['csrf'])[0] == 200
`
	if output, err := exec.CommandContext(t.Context(), python, "-B", "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, output)
	}
}

func TestWebAPIAuditLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, fixture := range []string{"web-api-app", "web-api-client"} {
		t.Run(fixture, func(t *testing.T) {
			scenario := Scenario{Skill: "audit-web", Fixture: "fixtures/" + fixture}
			if fixture == "web-api-app" {
				scenario = loadLiveScenario(t, "../../evals/web-api-session.yaml")
			}
			status, findings := runAuditScenario(t, scenario)
			if fixture == "web-api-client" && (status != "not-applicable" || findings != 0) {
				t.Fatalf("client status=%s findings=%d", status, findings)
			}
		})
	}
}

func skipUnlessLiveEvals(t *testing.T) {
	t.Helper()
	if os.Getenv("SCRUTINEER_RUN_EVALS") != "1" {
		t.Skip("set SCRUTINEER_RUN_EVALS=1 to execute model-backed skill evals")
	}
}

func loadLiveScenario(t *testing.T, path string) Scenario {
	t.Helper()
	scenario, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	return scenario
}

// runAuditScenario runs an audit scenario live, failing on required misses or
// unexpected findings. It returns the report's review status and finding count.
func runAuditScenario(t *testing.T, scenario Scenario) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	runner := Runner{Runner: worker.LocalClaude{}, SkillsRoot: "../../skills", EvalsRoot: "../../evals", WorkRoot: t.TempDir(), Model: os.Getenv("SCRUTINEER_EVAL_MODEL")}
	result, err := runner.RunScenario(ctx, scenario)
	if err != nil {
		t.Fatal(err)
	}
	if result.FailedRequired != 0 || result.Unexpected != 0 {
		t.Fatalf("required misses=%d unexpected=%d report=%s", result.FailedRequired, result.Unexpected, result.Report)
	}
	var report struct {
		ReviewStatus string            `json:"review_status"`
		Findings     []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(result.Report), &report); err != nil {
		t.Fatal(err)
	}
	return report.ReviewStatus, len(report.Findings)
}

type webModeCase struct {
	name, fixture, subPath string
	web, registry, skipWeb bool
}

func TestWebAPITriageLive(t *testing.T) {
	skipUnlessLiveEvals(t)
	for _, tc := range []webModeCase{
		{name: "application", fixture: "web-api-app", web: true},
		{name: "client dependency", fixture: "web-api-client"},
		{name: "scoped application", fixture: "web-api-app", subPath: "services/site", web: true},
		{name: "scoped client", fixture: "web-api-app", subPath: "tools/client"},
		{name: "overlapping modes", fixture: "web-api-registry", web: true, registry: true},
		{name: "active audit", fixture: "web-api-app", web: true, skipWeb: true},
	} {
		t.Run(tc.name, func(t *testing.T) { runWebModeCase(t, tc) })
	}
}

func runWebModeCase(t *testing.T, tc webModeCase) {
	t.Helper()
	counts, report := runTriageModeCase(t, triageScan{fixture: tc.fixture, subPath: tc.subPath, activeSkill: "audit-web", activeHere: tc.skipWeb})
	for skill, want := range map[string]bool{"audit-web": tc.web && !tc.skipWeb, "audit-authz": tc.web, "audit-injection": tc.registry, "audit-package-manager": tc.registry, "threat-model": true} {
		if got := counts["/api/repositories/1/skills/"+skill+"/run"] > 0; got != want {
			t.Errorf("%s enqueued=%t want=%t; report=%s", skill, got, want, report)
		}
	}
	assertWebModeReport(t, tc, report)
}

// triageScan describes one triage run. The fake API always lists activeSkill
// as running, in the scan's own scope when activeHere is set and in another
// subproject otherwise.
type triageScan struct {
	fixture, subPath, activeSkill string
	activeHere                    bool
}

// runTriageModeCase runs triage over a fixture against a fake Scrutineer API
// and returns how often each enqueue path was requested plus the report.
func runTriageModeCase(t *testing.T, scan triageScan) (map[string]int, string) {
	t.Helper()
	subPath := scan.subPath
	requests := make(chan string, 100)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if serveTriageValidateReport(t, w, r) {
			return
		}
		if r.Method == http.MethodPost {
			var scope struct {
				SubPath string `json:"sub_path"`
				Ref     string `json:"ref"`
			}
			if err := json.NewDecoder(r.Body).Decode(&scope); err != nil {
				t.Errorf("enqueue body: %v", err)
			}
			if scope.SubPath != subPath || scope.Ref != "release" {
				t.Errorf("enqueue scope=%+v want subpath=%q ref=release", scope, subPath)
			}
			select {
			case requests <- r.URL.Path:
			default:
				t.Error("too many enqueue requests")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"id":1}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/scans") {
			activeScope := "elsewhere"
			if scan.activeHere {
				activeScope = subPath
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{{"skill_name": scan.activeSkill, "status": "running", "ref": "release", "sub_path": activeScope}})
			return
		}
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	runner := Runner{Runner: triageModeRunner{apiBase: server.URL + "/api", subPath: subPath, ref: "release", maxTurns: 32}, SkillsRoot: "../../skills", EvalsRoot: "../../evals", WorkRoot: t.TempDir(), Model: os.Getenv("SCRUTINEER_EVAL_MODEL")}
	result, err := runner.RunScenario(ctx, Scenario{Skill: "triage", Fixture: "fixtures/" + scan.fixture})
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	for len(requests) > 0 {
		counts[<-requests]++
	}
	for path, count := range counts {
		if count != 1 {
			t.Errorf("%s enqueued %d times", path, count)
		}
	}
	return counts, result.Report
}

func assertWebModeReport(t *testing.T, tc webModeCase, raw string) {
	t.Helper()
	var report struct {
		Modes []struct {
			Name     string   `json:"name"`
			Evidence []string `json:"evidence"`
		} `json:"modes"`
	}
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatal(err)
	}
	modes := make(map[string]bool)
	for _, mode := range report.Modes {
		if modes[mode.Name] || len(mode.Evidence) == 0 {
			t.Errorf("duplicate or unevidenced mode=%+v", mode)
		}
		modes[mode.Name] = true
	}
	if modes["web-api"] != tc.web || modes["package-manager"] != tc.registry {
		t.Fatalf("modes=%v want web=%t registry=%t", modes, tc.web, tc.registry)
	}
}
