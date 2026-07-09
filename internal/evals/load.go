//go:build evals

package evals

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	return scenarios, nil
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
