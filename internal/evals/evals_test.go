//go:build evals

package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/llm"
	"scrutineer/internal/worker"
)

func TestLoadScenarios(t *testing.T) {
	scenarios, err := LoadScenarios("../../evals")
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) < 3 {
		t.Fatalf("scenarios = %d, want at least 3", len(scenarios))
	}
	for _, sc := range scenarios {
		if sc.Skill == "" || sc.Fixture == "" {
			t.Fatalf("invalid scenario: %+v", sc)
		}
		if _, err := os.Stat(filepath.Join("../../evals", sc.Fixture)); err != nil {
			t.Fatalf("%s fixture %q missing: %v", sc.Path, sc.Fixture, err)
		}
	}
}

func TestAuthOmissionScenario(t *testing.T) {
	sc, err := LoadScenario("../../evals/security-deep-dive-auth-omission.yaml")
	if err != nil {
		t.Fatal(err)
	}
	report := `{"findings":[{"title":"Session omission bypass","severity":"High","cwe":"CWE-306","location":"app.py:18","trace":"session_cookie skips validation before serve_account_data."}]}`
	results, err := (HeuristicJudge{}).Judge(sc, report)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || !results[0].Matched || !results[1].Matched {
		t.Fatalf("scenario results = %+v, want passing positive and negative assertions", results)
	}
}

func TestLoadScenarioDefaultsRequiredButAllowsOptional(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scenario.yaml")
	if err := os.WriteFile(path, []byte(`given: optional case
fixture: fixtures/x
skill: security-deep-dive
should_find:
  - finding: required by default
    evidence_contains:
      - buildQuery
  - finding: optional miss
    required: false
must_not_contain:
  - Rails::ActiveRecord
`), 0o644); err != nil {
		t.Fatal(err)
	}
	sc, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sc.ShouldFind[0].Required {
		t.Fatal("first should_find should default to required")
	}
	if sc.ShouldFind[1].Required {
		t.Fatal("explicit required:false should stay optional")
	}
	if got := sc.ShouldFind[0].Evidence; len(got) != 1 || got[0] != "buildQuery" {
		t.Fatalf("evidence_contains = %#v, want [buildQuery]", got)
	}
	if got := sc.MustNotContain; len(got) != 1 || got[0] != "Rails::ActiveRecord" {
		t.Fatalf("must_not_contain = %#v, want [Rails::ActiveRecord]", got)
	}
}

func TestLoadScenarioRejectsUnknownAssertionField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scenario.yaml")
	if err := os.WriteFile(path, []byte(`given: typo case
fixture: fixtures/x
skill: security-deep-dive
should_find:
  - finding: typo
    severty: High
`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadScenario(path)
	if err == nil || !strings.Contains(err.Error(), "severty") {
		t.Fatalf("LoadScenario error = %v, want unknown severty field", err)
	}
}

func TestScenarioValidate(t *testing.T) {
	tests := []struct {
		name string
		sc   Scenario
	}{
		{
			name: "missing fixture",
			sc: Scenario{
				Path:       "case.yaml",
				Given:      "x",
				Skill:      "security-deep-dive",
				ShouldFind: []Assertion{{Finding: "x"}},
			},
		},
		{
			name: "no assertions",
			sc: Scenario{
				Path:    "case.yaml",
				Given:   "x",
				Fixture: "fixtures/x",
				Skill:   "security-deep-dive",
			},
		},
		{
			name: "blank should_find",
			sc: Scenario{
				Path:       "case.yaml",
				Given:      "x",
				Fixture:    "fixtures/x",
				Skill:      "security-deep-dive",
				ShouldFind: []Assertion{{}},
			},
		},
		{
			name: "blank should_not_find",
			sc: Scenario{
				Path:          "case.yaml",
				Given:         "x",
				Fixture:       "fixtures/x",
				Skill:         "security-deep-dive",
				ShouldNotFind: []Assertion{{}},
			},
		},
		{
			name: "blank evidence term",
			sc: Scenario{
				Path:    "case.yaml",
				Given:   "x",
				Fixture: "fixtures/x",
				Skill:   "security-deep-dive",
				ShouldFind: []Assertion{{
					Finding:  "x",
					Evidence: []string{""},
				}},
			},
		},
		{
			name: "blank must_not_contain term",
			sc: Scenario{
				Path:           "case.yaml",
				Given:          "x",
				Fixture:        "fixtures/x",
				Skill:          "security-deep-dive",
				ShouldFind:     []Assertion{{Finding: "x"}},
				MustNotContain: []string{""},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.sc.validate(); err == nil {
				t.Fatal("validate succeeded, want error")
			}
		})
	}
}

func TestScenarioValidateAllowsMustNotContainOnly(t *testing.T) {
	sc := Scenario{
		Path:           "case.yaml",
		Given:          "x",
		Fixture:        "fixtures/x",
		Skill:          "security-deep-dive",
		MustNotContain: []string{"Rails::ActiveRecord"},
	}
	if err := sc.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil", err)
	}
}

func TestScenarioValidateNamesInvalidAssertion(t *testing.T) {
	sc := Scenario{
		Path:    "case.yaml",
		Given:   "x",
		Fixture: "fixtures/x",
		Skill:   "security-deep-dive",
		ShouldFind: []Assertion{{
			Finding:  "SQL injection",
			Evidence: []string{""},
		}},
	}
	err := sc.validate()
	if err == nil || !strings.Contains(err.Error(), "should_find[0] (SQL injection)") {
		t.Fatalf("validate() = %v, want assertion index and label", err)
	}
}

func TestHeuristicJudge(t *testing.T) {
	sc := Scenario{
		ShouldFind: []Assertion{{
			Finding:  "SQL injection",
			Severity: "High",
			CWE:      "CWE-89",
			Path:     "app.py",
			Evidence: []string{"buildQuery", "username parameter"},
			Required: true,
		}},
		ShouldNotFind: []Assertion{{Finding: "unused import"}},
	}
	report := `{"findings":[{"title":"SQL injection in buildQuery","severity":"High","cwe":"CWE-89","location":"app.py:8","trace":"The username parameter reaches buildQuery."}]}`
	got, err := (HeuristicJudge{}).Judge(sc, report)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("results = %d, want 2", len(got))
	}
	for _, r := range got {
		if !r.Matched {
			t.Fatalf("assertion did not pass: %+v", r)
		}
	}
}

func TestAssertionMatchesFinding(t *testing.T) {
	baseFinding := Finding{Title: "SQL injection in buildQuery", Severity: "high", CWE: "cwe-89", Location: "app.py:12:3"}
	tests := []struct {
		name string
		a    Assertion
		f    Finding
		want bool
	}{
		{name: "full match", a: Assertion{Finding: "sql injection", Severity: "High", CWE: "CWE-89", Path: "app.py"}, want: true},
		{name: "title mismatch", a: Assertion{Finding: "command injection"}, want: false},
		{name: "severity mismatch", a: Assertion{Severity: "Low"}, want: false},
		{name: "cwe mismatch", a: Assertion{CWE: "CWE-78"}, want: false},
		{name: "path mismatch", a: Assertion{Path: "other.py"}, want: false},
		{name: "evidence match", a: Assertion{Evidence: []string{"buildQuery"}}, want: true},
		{name: "evidence mismatch", a: Assertion{Evidence: []string{"missing function"}}, want: false},
		{name: "CWE is not evidence", a: Assertion{Evidence: []string{"CWE-89"}}, want: false},
		{
			name: "path avoids file prefix false positive",
			a:    Assertion{Path: "app.py"},
			f:    Finding{Title: "backup", Location: "app.py.bak:1"},
			want: false,
		},
		{
			name: "directory prefix match",
			a:    Assertion{Path: "pkg"},
			f:    Finding{Title: "nested", Location: "pkg/app.py:1"},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.f
			if f.Title == "" && f.Location == "" {
				f = baseFinding
			}
			if got := assertionMatchesFinding(tc.a, f); got != tc.want {
				t.Fatalf("assertionMatchesFinding() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHeuristicJudgeMustNotContain(t *testing.T) {
	sc := Scenario{MustNotContain: []string{"Rails::ActiveRecord", "ghost.py"}}
	passingReport := `{"findings":[{"title":"SQL injection","location":"app.py:7"}]}`
	got, err := (HeuristicJudge{}).Judge(sc, passingReport)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Matched || !got[1].Matched {
		t.Fatalf("must_not_contain should pass: %+v", got)
	}

	failingReport := `{"findings":[],"summary":"Rails::ActiveRecord is in scope"}`
	got, err = (HeuristicJudge{}).Judge(sc, failingReport)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Matched || !strings.Contains(got[0].Reason, "unexpectedly contains") {
		t.Fatalf("must_not_contain should fail: %+v", got[0])
	}
}

func TestHeuristicJudgeFailures(t *testing.T) {
	sc := Scenario{
		ShouldFind:    []Assertion{{Finding: "SQL injection", Required: true}},
		ShouldNotFind: []Assertion{{Finding: "debug endpoint"}},
	}
	report := `{"findings":[{"title":"debug endpoint exposed","severity":"Medium","location":"debug.py:1"}]}`
	got, err := (HeuristicJudge{}).Judge(sc, report)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("results = %d, want 2", len(got))
	}
	if got[0].Matched {
		t.Fatalf("should_find unexpectedly matched: %+v", got[0])
	}
	if got[1].Matched {
		t.Fatalf("should_not_find hit should fail the assertion: %+v", got[1])
	}
}

func TestRunnerStagesSkillAndScoresReport(t *testing.T) {
	sc, err := LoadScenario("../../evals/security-deep-dive-sqli.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := Runner{
		Runner:     fakeSkillRunner{report: validDeepDiveReport()},
		SkillsRoot: "../../skills",
		EvalsRoot:  "../../evals",
		WorkRoot:   t.TempDir(),
		Model:      "test-model",
	}
	res, err := r.RunScenario(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if res.FailedRequired != 0 || res.Unexpected != 0 {
		t.Fatalf("unexpected failures: %+v", res)
	}
	if res.Cost.USD != 0.01 || res.Cost.Turns != 1 || res.Cost.InputTokens != 10 {
		t.Fatalf("cost not accumulated: %+v", res.Cost)
	}
}

func TestRunnerAddsUsageJudgeCost(t *testing.T) {
	sc := mustLoadScenario(t, "../../evals/security-deep-dive-sqli.yaml")
	r := Runner{
		Runner:     fakeSkillRunner{report: validDeepDiveReport()},
		SkillsRoot: "../../skills",
		EvalsRoot:  "../../evals",
		WorkRoot:   t.TempDir(),
		Judge: usageJudgeStub{
			matches: []AssertionResult{{Kind: assertionShouldFind, Matched: true, Required: true}},
			cost:    Cost{USD: 0.02, Turns: 1, InputTokens: 20, OutputTokens: 5},
		},
	}
	res, err := r.RunScenario(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Cost.USD != 0.03 || res.Cost.Turns != 2 || res.Cost.InputTokens != 30 || res.Cost.OutputTokens != 7 {
		t.Fatalf("cost = %+v, want skill and judge usage combined", res.Cost)
	}
}

func TestModelJudgeReturnsOrderedVerdictsAndUsage(t *testing.T) {
	server := modelJudgeServer(t, `{"verdicts":[{"index":1,"passed":false,"reason":"prohibited finding is present"},{"index":0,"passed":true,"reason":"finding has the required evidence"}]}`)
	defer server.Close()

	judge := ModelJudge{Options: llm.Options{
		Endpoint:  server.URL + "/v1/messages",
		APIKey:    "test-key",
		Model:     "claude-haiku-4-5",
		MaxTokens: 64,
	}}
	sc := Scenario{
		Given:         "a test scenario",
		Skill:         "security-deep-dive",
		ShouldFind:    []Assertion{{Finding: "SQL injection", Required: true}},
		ShouldNotFind: []Assertion{{Finding: "debug endpoint"}},
	}
	matches, cost, err := judge.JudgeWithUsage(context.Background(), sc, `{"findings":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 || !matches[0].Matched || matches[1].Matched {
		t.Fatalf("matches = %+v, want ordered model verdicts", matches)
	}
	if cost.Turns != 1 || cost.InputTokens != 10 || cost.OutputTokens != 4 || cost.CacheReadTokens != 3 || cost.CacheWriteTokens != 2 || cost.USD <= 0 {
		t.Fatalf("cost = %+v, want model usage and priced cost", cost)
	}
}

func TestModelJudgeRejectsIncompleteVerdicts(t *testing.T) {
	server := modelJudgeServer(t, `{"verdicts":[{"index":0,"passed":true,"reason":"one"}]}`)
	defer server.Close()
	judge := ModelJudge{Options: llm.Options{
		Endpoint:  server.URL + "/v1/messages",
		APIKey:    "test-key",
		Model:     "claude-haiku-4-5",
		MaxTokens: 64,
	}}
	_, _, err := judge.JudgeWithUsage(context.Background(), Scenario{
		Given:         "test",
		Skill:         "security-deep-dive",
		ShouldFind:    []Assertion{{Finding: "one"}},
		ShouldNotFind: []Assertion{{Finding: "two"}},
	}, `{"findings":[]}`)
	if err == nil || !strings.Contains(err.Error(), "verdicts, want 2") {
		t.Fatalf("JudgeWithUsage() error = %v, want incomplete-verdict error", err)
	}
}

func TestRunnerRejectsSchemaInvalidReport(t *testing.T) {
	sc, err := LoadScenario("../../evals/security-deep-dive-sqli.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := Runner{
		Runner:     fakeSkillRunner{report: `{"findings":[{"title":"SQL injection in buildQuery","severity":"High","cwe":"CWE-89","location":"app.py:7"}]}`},
		SkillsRoot: "../../skills",
		EvalsRoot:  "../../evals",
		WorkRoot:   t.TempDir(),
	}
	_, err = r.RunScenario(context.Background(), sc)
	if err == nil || !strings.Contains(err.Error(), "failed report validation") {
		t.Fatalf("RunScenario error = %v, want report validation failure", err)
	}
}

func TestRunnerRejectsIncompleteDeepDiveInventory(t *testing.T) {
	sc, err := LoadScenario("../../evals/security-deep-dive-sqli.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := Runner{
		Runner:     fakeSkillRunner{report: incompleteDeepDiveReport()},
		SkillsRoot: "../../skills",
		EvalsRoot:  "../../evals",
		WorkRoot:   t.TempDir(),
	}
	_, err = r.RunScenario(context.Background(), sc)
	if err == nil || !strings.Contains(err.Error(), "inventory sink S1 has no disposition") {
		t.Fatalf("RunScenario error = %v, want unresolved inventory failure", err)
	}
}

func TestMassAssignmentScenario(t *testing.T) {
	sc := mustLoadScenario(t, "../../evals/security-deep-dive-mass-assignment.yaml")
	report := `{"findings":[{
  "title":"Mass assignment in update_account",
  "cwe":"CWE-915",
  "location":"account.py:10",
  "trace":"request.get_json() supplies body, and account.update(body) copies role without an allow-list."
}]}`
	got, err := (HeuristicJudge{}).Judge(sc, report)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("results = %d, want 2", len(got))
	}
	for _, result := range got {
		if !result.Matched {
			t.Fatalf("mass-assignment assertion did not pass: %+v", result)
		}
	}

	safeReport := `{"findings":[{
  "title":"Mass assignment in update_profile",
  "cwe":"CWE-915",
  "location":"profile.py:14",
  "trace":"update_profile uses account.update(editable) and overwrites owner_id."
}]}`
	got, err = (HeuristicJudge{}).Judge(sc, safeReport)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("safe results = %d, want 2", len(got))
	}
	if got[1].Kind != assertionShouldNotFind {
		t.Fatalf("safe result kind = %q, want %q", got[1].Kind, assertionShouldNotFind)
	}
	if got[1].Matched {
		t.Fatalf("allow-listed endpoint unexpectedly passed should_not_find: %+v", got[1])
	}
}

func TestRunnerCountsMustNotContainFailure(t *testing.T) {
	sc, err := LoadScenario("../../evals/security-deep-dive-sqli.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sc.MustNotContain = []string{"username parameter"}
	r := Runner{
		Runner:     fakeSkillRunner{report: validDeepDiveReport()},
		SkillsRoot: "../../skills",
		EvalsRoot:  "../../evals",
		WorkRoot:   t.TempDir(),
	}
	res, err := r.RunScenario(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if res.Unexpected != 1 {
		t.Fatalf("unexpected = %d, want 1: %+v", res.Unexpected, res.Matches)
	}
}

func TestRunFixtures(t *testing.T) {
	if os.Getenv("SCRUTINEER_RUN_EVALS") != "1" {
		t.Skip("set SCRUTINEER_RUN_EVALS=1 to execute model-backed skill evals")
	}
	scenarios, err := LoadScenarios("../../evals")
	if err != nil {
		t.Fatal(err)
	}
	r := Runner{
		Runner:     worker.LocalClaude{},
		SkillsRoot: "../../skills",
		EvalsRoot:  "../../evals",
		WorkRoot:   t.TempDir(),
		Model:      os.Getenv("SCRUTINEER_EVAL_MODEL"),
	}
	if os.Getenv("SCRUTINEER_EVAL_JUDGE") == "model" {
		judgeModel := os.Getenv("SCRUTINEER_EVAL_JUDGE_MODEL")
		if judgeModel == "" {
			judgeModel = r.Model
		}
		r.Judge = ModelJudge{Options: llm.Options{
			APIKey:    os.Getenv("ANTHROPIC_API_KEY"),
			Model:     judgeModel,
			MaxTokens: modelJudgeMaxTokens,
		}}
	}
	results, err := r.RunAll(context.Background(), scenarios)
	if err != nil {
		t.Fatal(err)
	}
	for _, res := range results {
		t.Logf("%s: assertions=%d required_misses=%d optional_misses=%d unexpected=%d cost=$%.4f turns=%d",
			res.Scenario.Path, res.AssertionTotal, res.FailedRequired, res.OptionalMisses, res.Unexpected, res.Cost.USD, res.Cost.Turns)
		if res.FailedRequired > 0 || res.Unexpected > 0 {
			t.Fail()
		}
	}
}

type usageJudgeStub struct {
	matches []AssertionResult
	cost    Cost
}

func (j usageJudgeStub) Judge(Scenario, string) ([]AssertionResult, error) {
	return j.matches, nil
}

func (j usageJudgeStub) JudgeWithUsage(context.Context, Scenario, string) ([]AssertionResult, Cost, error) {
	return j.matches, j.cost, nil
}

func modelJudgeServer(t *testing.T, verdicts string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
			t.Fatalf("request = %s %s, want POST /v1/messages", r.Method, r.URL.Path)
		}
		var request struct {
			OutputConfig struct {
				Format struct {
					Type   string          `json:"type"`
					Schema json.RawMessage `json:"schema"`
				} `json:"format"`
			} `json:"output_config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.OutputConfig.Format.Type != "json_schema" || !json.Valid(request.OutputConfig.Format.Schema) {
			t.Fatalf("structured output = %+v, want valid JSON schema", request.OutputConfig.Format)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"content":[{"type":"text","text":%q}],"usage":{"input_tokens":10,"output_tokens":4,"cache_read_input_tokens":3,"cache_creation_input_tokens":2}}`, verdicts)
	}))
}

func TestRunnerRejectsFixtureTraversal(t *testing.T) {
	r := Runner{EvalsRoot: "../../evals"}
	for _, fixture := range []string{"../outside", "/tmp/repo", "C:/repo"} {
		_, err := r.fixturePath(Scenario{Path: "case.yaml", Fixture: fixture})
		if err == nil {
			t.Fatalf("fixturePath(%q) succeeded, want error", fixture)
		}
	}
}

func TestRunAllContinuesAfterScenarioError(t *testing.T) {
	scenarios := []Scenario{
		{Path: "bad.yaml", Fixture: "../bad", Skill: "security-deep-dive"},
		mustLoadScenario(t, "../../evals/security-deep-dive-sqli.yaml"),
	}
	r := Runner{
		Runner:     fakeSkillRunner{report: validDeepDiveReport()},
		SkillsRoot: "../../skills",
		EvalsRoot:  "../../evals",
		WorkRoot:   t.TempDir(),
	}
	results, err := r.RunAll(context.Background(), scenarios)
	if err == nil {
		t.Fatal("RunAll error = nil, want joined error")
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].Error == "" {
		t.Fatalf("first result missing error: %+v", results[0])
	}
	if results[1].Error != "" || results[1].FailedRequired != 0 {
		t.Fatalf("second scenario should still run successfully: %+v", results[1])
	}
}

func mustLoadScenario(t *testing.T, path string) Scenario {
	t.Helper()
	sc, err := LoadScenario(path)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func validDeepDiveReport() string {
	return `{
  "repository": "https://example.com/eval",
  "commit": "abcdef1",
  "spec_version": 13,
  "model": "test-model",
  "date": "2026-07-09",
  "languages": ["Python"],
  "boundaries": [{
    "actor": "HTTP client",
    "trusted": "no",
    "controls": "No input validation before query construction",
    "source": "app.py"
  }],
  "method": {
    "scope": "./src",
    "grep_patterns": [],
    "inventory_count": 2,
    "ruled_out_count": 1,
    "unresolved_count": 0,
    "notes": ["Python fixture: no memory-unsafe primitives to enumerate."]
  },
  "inventory": [{
    "id": "S1",
    "location": "app.py:7",
    "class": "Validation",
    "boundary": "HTTP client",
    "consumes": "username query parameter"
  }, {
    "id": "S2",
    "location": "app.py:1",
    "class": "Validation",
    "boundary": "HTTP client",
    "consumes": "unused import"
  }],
  "findings": [{
    "id": "F1",
    "sinks": ["S1"],
    "title": "SQL injection in buildQuery",
    "severity": "High",
    "cwe": "CWE-89",
    "location": "app.py:7",
    "reachability": "reachable",
    "quality_tier": "high",
    "trace": "The username parameter is concatenated into SQL.",
    "boundary": "Untrusted HTTP input crosses into SQL execution.",
    "validation": "Manual review of app.py shows string concatenation in buildQuery.",
    "rating": "High impact and directly reachable."
  }],
  "ruled_out": [{
    "sinks": ["S2"],
    "step": 6,
    "reason": "No additional sinks were present in the fixture."
  }]
}`
}

func incompleteDeepDiveReport() string {
	return `{
  "repository": "https://example.com/eval",
  "commit": "abcdef1",
  "spec_version": 13,
  "model": "test-model",
  "date": "2026-07-09",
  "languages": ["Python"],
  "boundaries": [{
    "actor": "HTTP client",
    "trusted": "no",
    "controls": "No input validation before query construction",
    "source": "app.py"
  }],
  "method": {
    "scope": "./src",
    "grep_patterns": [],
    "inventory_count": 1,
    "ruled_out_count": 0,
    "unresolved_count": 0,
    "notes": ["Python fixture: no memory-unsafe primitives to enumerate."]
  },
  "inventory": [{
    "id": "S1",
    "location": "app.py:7",
    "class": "Validation",
    "boundary": "HTTP client",
    "consumes": "username query parameter"
  }],
  "findings": [],
  "ruled_out": []
}`
}

type fakeSkillRunner struct {
	report string
	err    error
}

func (f fakeSkillRunner) RunSkill(ctx context.Context, sj worker.SkillJob, emit func(worker.Event)) (worker.SkillResult, error) {
	if f.err != nil {
		return worker.SkillResult{}, f.err
	}
	if sj.Name == "" || sj.SkillDir == "" || sj.OutputFile == "" {
		return worker.SkillResult{}, os.ErrInvalid
	}
	if _, err := os.Stat(filepath.Join(sj.WorkRoot, "src")); err != nil {
		return worker.SkillResult{}, err
	}
	if _, err := os.Stat(filepath.Join(sj.SkillDir, "SKILL.md")); err != nil {
		return worker.SkillResult{}, err
	}
	if err := runGit(ctx, filepath.Join(sj.WorkRoot, "src"), "rev-parse", "--verify", "HEAD"); err != nil {
		return worker.SkillResult{}, err
	}
	emit(worker.Event{
		Kind:    worker.KindResult,
		CostUSD: 0.01,
		Turns:   1,
		Usage:   worker.Usage{InputTokens: 10, OutputTokens: 2},
	})
	return worker.SkillResult{Commit: "abc", Report: f.report}, nil
}

func (fakeSkillRunner) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, ".claude", "skills", name)
}

var _ worker.SkillRunner = fakeSkillRunner{}
