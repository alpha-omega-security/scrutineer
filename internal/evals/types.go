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
	Path          string      `yaml:"-"`
	Given         string      `yaml:"given"`
	Fixture       string      `yaml:"fixture"`
	Skill         string      `yaml:"skill"`
	ShouldFind    []Assertion `yaml:"should_find"`
	ShouldNotFind []Assertion `yaml:"should_not_find"`
}

// Assertion describes one expected positive or negative condition. Negative
// assertions may be a scalar string in YAML; positives usually use fields.
type Assertion struct {
	Finding     string `yaml:"finding"`
	Severity    string `yaml:"severity"`
	CWE         string `yaml:"cwe"`
	Path        string `yaml:"path"`
	Required    bool   `yaml:"required"`
	requiredSet bool
}

func (a *Assertion) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		a.Finding = strings.TrimSpace(value.Value)
		return nil
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		switch value.Content[i].Value {
		case "finding", "severity", "cwe", "path", "required":
		default:
			return fmt.Errorf("unknown assertion field %q", value.Content[i].Value)
		}
	}
	var out struct {
		Finding  string `yaml:"finding"`
		Severity string `yaml:"severity"`
		CWE      string `yaml:"cwe"`
		Path     string `yaml:"path"`
		Required *bool  `yaml:"required"`
	}
	if err := value.Decode(&out); err != nil {
		return err
	}
	a.Finding = out.Finding
	a.Severity = out.Severity
	a.CWE = out.CWE
	a.Path = out.Path
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
	if len(s.ShouldFind) == 0 && len(s.ShouldNotFind) == 0 {
		return fmt.Errorf("%s has no assertions", s.Path)
	}
	for _, a := range s.ShouldFind {
		if a.empty() {
			return fmt.Errorf("%s has an empty should_find assertion", s.Path)
		}
	}
	for _, a := range s.ShouldNotFind {
		if a.empty() {
			return fmt.Errorf("%s has an empty should_not_find assertion", s.Path)
		}
	}
	return nil
}

func (a Assertion) empty() bool {
	return strings.TrimSpace(a.Finding) == "" &&
		strings.TrimSpace(a.Severity) == "" &&
		strings.TrimSpace(a.CWE) == "" &&
		strings.TrimSpace(a.Path) == ""
}

// Finding is the subset of report.json finding fields the eval judge needs.
type Finding struct {
	Title     string   `json:"title"`
	Severity  string   `json:"severity"`
	CWE       string   `json:"cwe"`
	Location  string   `json:"location"`
	Locations []string `json:"locations"`
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
