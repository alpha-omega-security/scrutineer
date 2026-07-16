// Package repoconfig parses the analyst-authored scan configuration attached
// to a repository.
package repoconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"

	"scrutineer/internal/skills"
)

// Config is the durable, repository-specific input to model-backed scans.
// It is stored as YAML on db.Repository and staged as JSON in context.json.
type Config struct {
	FocusAreas    []FocusArea `yaml:"focus_areas,omitempty" json:"focus_areas,omitempty"`
	KnownBugs     []string    `yaml:"known_bugs,omitempty" json:"known_bugs,omitempty"`
	AttackSurface string      `yaml:"attack_surface,omitempty" json:"attack_surface,omitempty"`
	Skip          []string    `yaml:"skip,omitempty" json:"skip,omitempty"`
}

// FocusArea is an analyst-defined code region and the security property worth
// investigating there.
type FocusArea struct {
	Name    string   `yaml:"name" json:"name"`
	Paths   []string `yaml:"paths" json:"paths"`
	Surface string   `yaml:"surface" json:"surface"`
}

// EncodeFocusAreaJSON validates a focus area and returns the stable payload
// stored on an individual scan. Keeping the complete area on the scan means a
// queued audit cannot silently change scope after an analyst edits the repo
// configuration.
func EncodeFocusAreaJSON(area FocusArea) (string, error) {
	normalised, err := NormaliseFocusArea(area)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(normalised)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeFocusAreaJSON validates the focus area persisted on an individual
// scan. Empty is handled by callers as an unscoped scan.
func DecodeFocusAreaJSON(raw string) (FocusArea, error) {
	var area FocusArea
	if err := json.Unmarshal([]byte(raw), &area); err != nil {
		return FocusArea{}, err
	}
	return NormaliseFocusArea(area)
}

// NormaliseFocusArea applies the same validation and path normalisation used
// by repository scan_config to one focus area.
func NormaliseFocusArea(area FocusArea) (FocusArea, error) {
	cfg := Config{FocusAreas: []FocusArea{area}}
	if err := cfg.validate(); err != nil {
		return FocusArea{}, err
	}
	return cfg.FocusAreas[0], nil
}

// Parse decodes and validates the YAML stored on a repository. Empty input is
// an intentionally unconfigured repository.
func Parse(raw string) (Config, error) {
	if strings.TrimSpace(raw) == "" {
		return Config{}, nil
	}
	dec := yaml.NewDecoder(bytes.NewBufferString(raw))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, fmt.Errorf("multiple YAML documents are not supported")
		}
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Normalise validates YAML and returns its stable, readable representation
// together with the parsed value. Empty input clears the configuration.
func Normalise(raw string) (string, Config, error) {
	cfg, err := Parse(raw)
	if err != nil {
		return "", Config{}, err
	}
	if cfg.Empty() {
		return "", cfg, nil
	}
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return "", Config{}, err
	}
	return string(b), cfg, nil
}

// Empty reports whether no repository-specific scan guidance is configured.
func (c Config) Empty() bool {
	return len(c.FocusAreas) == 0 && len(c.KnownBugs) == 0 &&
		strings.TrimSpace(c.AttackSurface) == "" && len(c.Skip) == 0
}

func (c Config) validate() error {
	for i, area := range c.FocusAreas {
		if strings.TrimSpace(area.Name) == "" {
			return fmt.Errorf("focus_areas[%d].name is required", i)
		}
		if len(area.Paths) == 0 {
			return fmt.Errorf("focus_areas[%d].paths is required", i)
		}
		if strings.TrimSpace(area.Surface) == "" {
			return fmt.Errorf("focus_areas[%d].surface is required", i)
		}
		if err := validatePatterns(fmt.Sprintf("focus_areas[%d].paths", i), area.Paths); err != nil {
			return err
		}
	}
	for i, bug := range c.KnownBugs {
		if strings.TrimSpace(bug) == "" {
			return fmt.Errorf("known_bugs[%d] is empty", i)
		}
	}
	return validatePatterns("skip", c.Skip)
}

func validatePatterns(field string, patterns []string) error {
	for i := range patterns {
		pattern := patterns[i]
		pattern = strings.TrimSpace(strings.ReplaceAll(pattern, "\\", "/"))
		patterns[i] = pattern
		if pattern == "" {
			return fmt.Errorf("%s[%d] is empty", field, i)
		}
		if path.IsAbs(pattern) || hasWindowsVolume(pattern) || hasParentPathSegment(pattern) {
			return fmt.Errorf("%s[%d] must be relative to the repository root", field, i)
		}
		if err := skills.ValidateGlob(pattern); err != nil {
			return fmt.Errorf("%s[%d] is not a valid glob: %w", field, i, err)
		}
	}
	return nil
}

func hasWindowsVolume(p string) bool {
	return len(p) >= 2 && p[1] == ':'
}

func hasParentPathSegment(p string) bool {
	return strings.Contains("/"+p+"/", "/../") || p == ".."
}
