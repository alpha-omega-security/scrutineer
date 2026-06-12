// Package config loads scrutineer's YAML config file. The config is
// opt-in: without a config file, every value falls back to its compile-
// time default (see the flag definitions in cmd/scrutineer/main.go).
// Config overrides those defaults; command-line flags still win when set.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is the path scrutineer checks for when -config is not set.
// Keeping it alongside the binary makes "drop a config next to it" work.
const DefaultPath = "./scrutineer.yaml"

// Config mirrors the supported YAML keys. Every field is optional; missing
// fields leave the corresponding flag at its built-in default.
type Config struct {
	Addr         string   `yaml:"addr"`
	Data         string   `yaml:"data"`
	Effort       string   `yaml:"effort"`
	DefaultModel string   `yaml:"default_model"`
	Models       []Model  `yaml:"models"`
	Skills       []string `yaml:"skills"`
	SkillsRepo   string   `yaml:"skills_repo"`
	NoDocker     *bool    `yaml:"no_docker"`
	// Hardened enforces the strictest sandbox mode: docker is required (no
	// --no-docker fallback), egress is restricted to *.anthropic.com plus
	// host.docker.internal, the container rootfs is read-only, and the
	// runner attaches to an internal docker network whose only route out
	// is scrutineer's allowlisting proxy. egress_allow is ignored under
	// hardened mode; the operator must drop hardened to widen it.
	Hardened    *bool  `yaml:"hardened"`
	RunnerImage string `yaml:"runner_image"`
	ProfilesDir string `yaml:"profiles_dir"`
	// EgressAllow extends the docker runner's egress proxy allowlist with
	// extra hostnames. Entries are appended to worker.DefaultEgressAllow,
	// not replacing it. "*.example.com" matches subdomains.
	EgressAllow []string `yaml:"egress_allow"`
	// Concurrency controls how many scans the worker runs in parallel.
	// 0 or negative leaves the built-in default (see queue.DefaultWorkerConcurrency).
	Concurrency int `yaml:"concurrency"`
	// Clone selects the clone-depth strategy: "shallow" (default, --depth 1)
	// or "full" (no depth limit). Empty means use the built-in default.
	Clone string `yaml:"clone"`
	// ScanTimeout is the wall-clock limit for a single scan, as a Go
	// duration string ("30m", "1h"). Empty leaves the built-in default.
	ScanTimeout string `yaml:"scan_timeout"`
	// MaxTurns is passed as --max-turns to claude-code. 0 means no limit.
	MaxTurns int `yaml:"max_turns"`
	// AnthropicBaseURL overrides the default Anthropic API endpoint. When
	// set, the hostname is automatically added to the egress allowlist and
	// the value is passed as ANTHROPIC_BASE_URL to the claude-code process.
	// Falls back to the ANTHROPIC_BASE_URL environment variable if empty.
	AnthropicBaseURL string `yaml:"anthropic_base_url"`
	// Theme selects the colour scheme: "claude" (default), "ocean-breeze",
	// "catppuccin", "sunset-horizon", "midnight-bloom", or "northern-lights".
	Theme string `yaml:"theme"`
	// ForkOrg is the GitHub organisation the fork skill stages scanned
	// repositories into as private repos and files finding issues against.
	// Empty disables the fork skill (it will refuse to run without a target
	// org).
	ForkOrg string `yaml:"fork_org"`
	// MetadataDir is the path inside a staging repo where scrutineer keeps
	// its per-project metadata (repo-level metadata.yaml plus one directory
	// per finding). Empty defaults to `.scrutineer/`. Operators with a
	// different consortium-flavoured convention can override it (e.g.
	// `.ossprey/`), which keeps the rest of the codebase neutral.
	MetadataDir string `yaml:"metadata_dir"`
	// SchemaStrict makes a skill report that fails JSON-schema validation
	// fail the scan. When false (the default) the validator output is
	// emitted to the scan log and the kind-specific parser still runs.
	// Intended as a development aid while iterating on a skill.
	SchemaStrict *bool `yaml:"schema_strict"`
}

// ParseScanTimeout validates and parses a scan_timeout string. Empty
// returns 0 (caller keeps its default); anything else must be a positive
// time.Duration.
func ParseScanTimeout(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("scan_timeout: %w", err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("scan_timeout: must be positive, got %q", s)
	}
	return d, nil
}

// ValidateClone returns an error when s is neither empty, "shallow", nor
// "full". Exposed so the CLI flag can use the same rule as the YAML field.
func ValidateClone(s string) error {
	switch s {
	case "", "shallow", "full":
		return nil
	default:
		return fmt.Errorf("clone: must be \"shallow\" or \"full\", got %q", s)
	}
}

// Model is a display-name plus the claude model id it resolves to. The
// shape matches web.Model so main.go can pipe one into the other without
// the two packages depending on each other.
type Model struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
}

// Themes lists every valid theme name.
var Themes = []string{"claude", "ocean-breeze", "catppuccin", "sunset-horizon", "midnight-bloom", "northern-lights"}

// ValidateTheme returns an error when s is not a known theme name.
// Empty is valid (caller keeps the default).
func ValidateTheme(s string) error {
	if s == "" || slices.Contains(Themes, s) {
		return nil
	}
	return fmt.Errorf("theme: unknown %q", s)
}

// Load reads a YAML config from path. Returns (nil, nil) when the file
// does not exist and the caller passed "" or DefaultPath — making config
// fully opt-in. Explicit paths that don't exist are an error.
func Load(path string) (*Config, error) {
	explicit := path != "" && path != DefaultPath
	if path == "" {
		path = DefaultPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			return nil, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := ValidateClone(c.Clone); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if _, err := ParseScanTimeout(c.ScanTimeout); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := ValidateTheme(c.Theme); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}
