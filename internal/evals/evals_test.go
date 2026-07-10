//go:build evals

package evals

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if err == nil || !strings.Contains(err.Error(), "failed schema validation") {
		t.Fatalf("RunScenario error = %v, want schema validation failure", err)
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
  "spec_version": 1,
  "model": "test-model",
  "date": "2026-07-09",
  "languages": ["Python"],
  "boundaries": [{
    "actor": "HTTP client",
    "trusted": "no",
    "controls": "No input validation before query construction",
    "source": "app.py"
  }],
  "inventory": [{
    "id": "S1",
    "location": "app.py:7",
    "class": "Validation",
    "consumes": "username query parameter"
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
    "sinks": ["S1"],
    "step": 6,
    "reason": "No additional sinks were present in the fixture."
  }]
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
