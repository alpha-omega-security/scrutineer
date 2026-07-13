//go:build evals

package evals

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scenario is one YAML eval file under evals/. It points at a fixture
// repository and names the skill whose output should be judged.
type Scenario struct {
	Path           string      `yaml:"-"`
	Given          string      `yaml:"given"`
	Fixture        string      `yaml:"fixture"`
	Skill          string      `yaml:"skill"`
	ShouldFind     []Assertion `yaml:"should_find"`
	ShouldNotFind  []Assertion `yaml:"should_not_find"`
	MustNotContain []string    `yaml:"must_not_contain"`
}

// Assertion describes one expected positive or negative condition. Negative
// assertions may be a scalar string in YAML; positives usually use fields.
type Assertion struct {
	Finding     string   `yaml:"finding"`
	Severity    string   `yaml:"severity"`
	CWE         string   `yaml:"cwe"`
	Path        string   `yaml:"path"`
	Evidence    []string `yaml:"evidence_contains"`
	Required    bool     `yaml:"required"`
	requiredSet bool
}

func (a *Assertion) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		a.Finding = strings.TrimSpace(value.Value)
		return nil
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		switch value.Content[i].Value {
		case "finding", "severity", "cwe", "path", "evidence_contains", "required":
		default:
			return fmt.Errorf("unknown assertion field %q", value.Content[i].Value)
		}
	}
	var out struct {
		Finding  string   `yaml:"finding"`
		Severity string   `yaml:"severity"`
		CWE      string   `yaml:"cwe"`
		Path     string   `yaml:"path"`
		Evidence []string `yaml:"evidence_contains"`
		Required *bool    `yaml:"required"`
	}
	if err := value.Decode(&out); err != nil {
		return err
	}
	a.Finding = out.Finding
	a.Severity = out.Severity
	a.CWE = out.CWE
	a.Path = out.Path
	a.Evidence = out.Evidence
	if out.Required != nil {
		a.Required = *out.Required
		a.requiredSet = true
	}
	return nil
}

func (a Assertion) label() string {
	for _, v := range []string{a.Finding, a.CWE, a.Path, a.Severity} {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	for _, term := range a.Evidence {
		if strings.TrimSpace(term) != "" {
			return strings.TrimSpace(term)
		}
	}
	return "<empty assertion>"
}

func (s Scenario) validate() error {
	var missing []string
	if strings.TrimSpace(s.Given) == "" {
		missing = append(missing, "given")
	}
	if strings.TrimSpace(s.Fixture) == "" {
		missing = append(missing, "fixture")
	}
	if strings.TrimSpace(s.Skill) == "" {
		missing = append(missing, "skill")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s missing %s", s.Path, strings.Join(missing, ", "))
	}
	if len(s.ShouldFind) == 0 && len(s.ShouldNotFind) == 0 && len(s.MustNotContain) == 0 {
		return fmt.Errorf("%s has no assertions", s.Path)
	}
	if err := validateAssertions(s.Path, assertionShouldFind, s.ShouldFind); err != nil {
		return err
	}
	if err := validateAssertions(s.Path, assertionShouldNotFind, s.ShouldNotFind); err != nil {
		return err
	}
	for i, term := range s.MustNotContain {
		if strings.TrimSpace(term) == "" {
			return fmt.Errorf("%s must_not_contain[%d]: empty term", s.Path, i)
		}
	}
	return nil
}

func validateAssertions(path, kind string, assertions []Assertion) error {
	for i, a := range assertions {
		if a.empty() {
			return fmt.Errorf("%s %s[%d] (%s): empty assertion", path, kind, i, a.label())
		}
		if err := a.validateEvidence(); err != nil {
			return fmt.Errorf("%s %s[%d] (%s): invalid evidence_contains: %w", path, kind, i, a.label(), err)
		}
	}
	return nil
}

func (a Assertion) empty() bool {
	return strings.TrimSpace(a.Finding) == "" &&
		strings.TrimSpace(a.Severity) == "" &&
		strings.TrimSpace(a.CWE) == "" &&
		strings.TrimSpace(a.Path) == "" &&
		len(a.Evidence) == 0
}

func (a Assertion) validateEvidence() error {
	for _, term := range a.Evidence {
		if strings.TrimSpace(term) == "" {
			return fmt.Errorf("empty term")
		}
	}
	return nil
}

// Finding is the subset of report.json finding fields the eval judge needs.
type Finding struct {
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	CWE         string   `json:"cwe"`
	Location    string   `json:"location"`
	Locations   []string `json:"locations"`
	Trace       string   `json:"trace"`
	Boundary    string   `json:"boundary"`
	Validation  string   `json:"validation"`
	Rating      string   `json:"rating"`
	Description string   `json:"description"`
	Affected    string   `json:"affected"`
	PriorArt    string   `json:"prior_art"`
	Reach       string   `json:"reach"`
}

type report struct {
	Findings []Finding `json:"findings"`
}

// Result is the per-scenario output from Runner.
type Result struct {
	Scenario       Scenario
	Commit         string
	Report         string
	AssertionTotal int
	FailedRequired int
	OptionalMisses int
	Unexpected     int
	Matches        []AssertionResult
	Cost           Cost
	Error          string
}

// AssertionResult is one judged assertion.
type AssertionResult struct {
	Assertion Assertion
	Kind      string
	Matched   bool
	Required  bool
	Reason    string
}

// Cost captures the model usage emitted by the skill runner.
type Cost struct {
	USD              float64
	Turns            int
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	CacheWriteTokens int
}
