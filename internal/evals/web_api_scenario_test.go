//go:build evals

package evals

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// judgeOutcomes scores a report holding findings with the default judge and
// returns the required misses and unexpected results Runner would count.
func judgeOutcomes(t *testing.T, sc Scenario, findings ...Finding) (failedRequired, unexpected int) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"findings": findings})
	if err != nil {
		t.Fatal(err)
	}
	matches, err := HeuristicJudge{}.Judge(sc, string(raw))
	if err != nil {
		t.Fatal(err)
	}
	var result Result
	tallyMatches(&result, matches)
	return result.FailedRequired, result.Unexpected
}

// fixtureLocation returns path:line for the first fixture line containing
// needle, so a finding stays pointed at the right code when the fixture moves.
func fixtureLocation(t *testing.T, fixture, path, needle string) string {
	t.Helper()
	raw, err := os.ReadFile("../../evals/fixtures/" + fixture + "/" + path)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(line, needle) {
			return fmt.Sprintf("%s:%d", path, i+1)
		}
	}
	t.Fatalf("%s has no line containing %q", path, needle)
	return ""
}

// The default judge must count a cross-site request forgery false positive on
// the guarded display-name handler as unexpected however the model titles it,
// while a correct finding on the email endpoint that only contrasts itself
// with that handler still passes.
func TestWebAPISessionScenarioRejectsGuardedHandlerFalsePositive(t *testing.T) {
	scenario, err := LoadScenario("../../evals/web-api-session.yaml")
	if err != nil {
		t.Fatal(err)
	}
	truePositive := Finding{
		Title:      "Cross-site account email update",
		CWE:        "CWE-352",
		Location:   fixtureLocation(t, "web-api-app", "services/site/server.py", `account["email"] = values.get("email"`),
		Trace:      "GET /api/email carries the victim's SameSite=Lax session cookie on a top-level navigation and writes the supplied email.",
		Validation: "Unlike update_display_name in display_name.py, which checks Origin and a session token, this GET handler has neither.",
	}
	falsePositive := Finding{
		Title:    "Display name update lacks CSRF protection",
		CWE:      "CWE-352",
		Location: fixtureLocation(t, "web-api-app", "services/site/display_name.py", "def update_display_name"),
		Trace:    "POST /api/display-name changes the account name from a form submission.",
	}
	if missed, extra := judgeOutcomes(t, scenario, truePositive); missed != 0 || extra != 0 {
		t.Errorf("true positive only: missed=%d unexpected=%d, want 0 and 0", missed, extra)
	}
	if missed, extra := judgeOutcomes(t, scenario, truePositive, falsePositive); missed != 0 || extra != 1 {
		t.Errorf("false positive on the guarded handler: missed=%d unexpected=%d, want 0 and 1", missed, extra)
	}
	if missed, extra := judgeOutcomes(t, scenario, falsePositive); missed != 1 || extra != 1 {
		t.Errorf("false positive alone: missed=%d unexpected=%d, want 1 and 1", missed, extra)
	}
}

// judgeOutcomes counts a forbidden report term as unexpected, as Runner does.
func TestJudgeOutcomesCountsMustNotContain(t *testing.T) {
	scenario := Scenario{MustNotContain: []string{"npm postinstall"}}
	if _, extra := judgeOutcomes(t, scenario, Finding{Title: "Install runs npm postinstall scripts"}); extra != 1 {
		t.Errorf("forbidden term: unexpected=%d, want 1", extra)
	}
	if _, extra := judgeOutcomes(t, scenario, Finding{Title: "Launcher names escape the prefix"}); extra != 0 {
		t.Errorf("clean report: unexpected=%d, want 0", extra)
	}
}
