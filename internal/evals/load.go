//go:build evals

package evals

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const minExperimentVariants = 2

type fixtureScenarios map[string]Scenario

// LoadScenarios reads every top-level .yaml/.yml file under root.
func LoadScenarios(root string) ([]Scenario, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read evals dir: %w", err)
	}
	var scenarios []Scenario
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(root, name)
		sc, err := LoadScenario(path)
		if err != nil {
			return nil, err
		}
		scenarios = append(scenarios, sc)
	}
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].Path < scenarios[j].Path })
	if err := validateExperimentPairs(scenarios); err != nil {
		return nil, err
	}
	return scenarios, nil
}

func validateExperimentPairs(scenarios []Scenario) error {
	experiments := make(map[string]map[string]fixtureScenarios)
	for _, sc := range scenarios {
		if sc.Experiment == "" {
			continue
		}
		variants := experiments[sc.Experiment]
		if variants == nil {
			variants = make(map[string]fixtureScenarios)
			experiments[sc.Experiment] = variants
		}
		fixtures := variants[sc.Variant]
		if fixtures == nil {
			fixtures = make(fixtureScenarios)
			variants[sc.Variant] = fixtures
		}
		if previous, exists := fixtures[sc.Fixture]; exists {
			return fmt.Errorf("experiment %q variant %q repeats fixture %q in %s and %s",
				sc.Experiment, sc.Variant, sc.Fixture, previous.Path, sc.Path)
		}
		fixtures[sc.Fixture] = sc
	}

	for experiment, variants := range experiments {
		if len(variants) < minExperimentVariants {
			return fmt.Errorf("experiment %q has %d variant; need at least 2", experiment, len(variants))
		}
		variantNames := make([]string, 0, len(variants))
		for variant := range variants {
			variantNames = append(variantNames, variant)
		}
		sort.Strings(variantNames)
		baselineName := variantNames[0]
		baseline := variants[baselineName]
		for _, variant := range variantNames[1:] {
			if err := validateExperimentVariant(experiment, baselineName, variant, baseline, variants[variant]); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateExperimentVariant(experiment, baselineName, variant string, baseline, candidate fixtureScenarios) error {
	if missing, extra := fixtureDifference(baseline, candidate); len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("experiment %q variants %q and %q use different fixtures (missing=%v extra=%v)",
			experiment, baselineName, variant, missing, extra)
	}
	for fixture, baselineScenario := range baseline {
		candidateScenario := candidate[fixture]
		if baselineScenario.Given != candidateScenario.Given {
			return fmt.Errorf("experiment %q variants %q and %q use different given text for fixture %q",
				experiment, baselineName, variant, fixture)
		}
		if !sameScenarioRubric(baselineScenario, candidateScenario) {
			return fmt.Errorf("experiment %q variants %q and %q use different assertions for fixture %q",
				experiment, baselineName, variant, fixture)
		}
	}
	return nil
}

func fixtureDifference(want, got fixtureScenarios) (missing, extra []string) {
	for fixture := range want {
		if _, ok := got[fixture]; !ok {
			missing = append(missing, fixture)
		}
	}
	for fixture := range got {
		if _, ok := want[fixture]; !ok {
			extra = append(extra, fixture)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func sameScenarioRubric(a, b Scenario) bool {
	return sameAssertions(a.ShouldFind, b.ShouldFind) &&
		sameAssertions(a.ShouldNotFind, b.ShouldNotFind) &&
		slices.Equal(a.MustNotContain, b.MustNotContain)
}

func sameAssertions(a, b []Assertion) bool {
	if len(a) != len(b) {
		return false
	}
	matched := make([]bool, len(b))
	for _, assertion := range a {
		found := false
		for i, candidate := range b {
			if matched[i] || !sameAssertion(assertion, candidate) {
				continue
			}
			matched[i] = true
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

func sameAssertion(a, b Assertion) bool {
	return a.Finding == b.Finding &&
		a.Severity == b.Severity &&
		a.CWE == b.CWE &&
		a.Path == b.Path &&
		a.SinkClass == b.SinkClass &&
		a.Required == b.Required &&
		slices.Equal(a.Evidence, b.Evidence)
}

// LoadScenario parses one scenario YAML file.
func LoadScenario(path string) (Scenario, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, fmt.Errorf("read scenario %s: %w", path, err)
	}
	var sc Scenario
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&sc); err != nil {
		return Scenario{}, fmt.Errorf("parse scenario %s: %w", path, err)
	}
	sc.Path = path
	if err := sc.validate(); err != nil {
		return Scenario{}, err
	}
	for i := range sc.ShouldFind {
		if !sc.ShouldFind[i].requiredSet {
			sc.ShouldFind[i].Required = true
		}
	}
	return sc, nil
}
