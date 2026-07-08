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
	// Backend selects the agent CLI the container runner execs:
	// "claude" (default) or "codex". Empty leaves the built-in default
	// (claude). Non-claude backends require the containerised runner;
	// --no-container with a non-claude backend is rejected at startup.
	// Validated against worker.HarnessByName so the set of accepted
	// values stays in one place.
	Backend string `yaml:"backend"`
	// NoContainer disables the containerised runner so claude runs directly on
	// the host (no isolation). NoDocker is the pre-rename alias, still honoured
	// so existing configs keep working; no_container wins when both are set
	// (coalesced in Load).
	NoContainer *bool `yaml:"no_container"`
	NoDocker    *bool `yaml:"no_docker"`
	// Runtime selects the container engine: "docker" (default), "podman", or
	// "apple" (Apple's container runtime, experimental). Empty leaves the
	// built-in default (docker). Rootless podman is detected automatically and gets
	// --userns=keep-id so bind-mount output stays host-owned. There is no
	// auto-detection: a non-docker host must set this (or pass --runtime)
	// explicitly.
	Runtime string `yaml:"runtime"`
	// SELinux controls bind-mount relabeling for the container runner: "auto"
	// (default/empty -- relabel only when SELinux is detected on the host), "on"
	// (always), or "off" (never). On an SELinux-enabled host the runner must
	// relabel its bind mounts (":z") or the container cannot read the clone or
	// write its output. Non-SELinux hosts are unaffected. See docs/podman.md.
	SELinux string `yaml:"selinux"`
	// Hardened enforces the strictest sandbox mode: a container runtime is
	// required (no --no-container fallback), egress is restricted to the
	// harness's model API plus the runtime's host endpoint, the container rootfs is
	// read-only, and the runner attaches to an internal network whose only route
	// out is scrutineer's allowlisting proxy. egress_allow is ignored under
	// hardened mode; the operator must drop hardened to widen it.
	Hardened *bool `yaml:"hardened"`
	// HardenedRuntimeOnly applies the non-network half of hardened mode
	// (read-only rootfs + no-new-privileges + the 2 GiB post-clone workspace cap)
	// without the per-scan --internal network, so it works under rootless podman
	// where full --hardened does not. See docs/podman.md.
	HardenedRuntimeOnly *bool `yaml:"hardened_runtime_only"`
	// HardenedRootlessRuntime is the deprecated alias for HardenedRuntimeOnly.
	HardenedRootlessRuntime *bool  `yaml:"hardened_rootless_runtime"`
	RunnerImage             string `yaml:"runner_image"`
	ProfilesDir             string `yaml:"profiles_dir"`
	// EgressAllow extends the container runner's egress proxy allowlist with
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
	// ModelBaseURL overrides the default model API endpoint for the
	// active backend. When set, the hostname is automatically added to
	// the egress allowlist. Each harness applies it its own way (claude:
	// ANTHROPIC_BASE_URL env; codex: -c openai_base_url=...). For
	// compatibility, only the claude backend also falls back to the
	// ANTHROPIC_BASE_URL environment variable when this is unset.
	ModelBaseURL string `yaml:"model_base_url"`
	// LegacyAnthropicBaseURL is the former name of ModelBaseURL, kept so
	// existing configs keep working. Load merges it into ModelBaseURL
	// when that is unset; remove after one release.
	LegacyAnthropicBaseURL string `yaml:"anthropic_base_url"`
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
	// DowngradeOnOverage falls the model tier back from max/high to the mid tier
	// for newly enqueued scans while the Claude subscription is past its included
	// quota (on overage), restoring it when the window resets. Only a
	// subscription token reports overage. Off by default; the switch is logged
	// and shown on the jobs page and /usage.
	DowngradeOnOverage *bool `yaml:"downgrade_on_overage"`
	// RecipientsFile is a flat text file of public keys (one per line,
	// age X25519 or SSH) used to encrypt format=bundle exports. Empty
	// disables encrypted export.
	RecipientsFile string `yaml:"recipients_file"`
	// IdentityFile is an age identity file or SSH private key used to
	// decrypt encrypted imports. Empty disables encrypted import.
	IdentityFile string `yaml:"identity_file"`
	// AutoRejectMissedCount is the threshold of consecutive missed rescans at
	// which an open finding is automatically transitioned to 'rejected'.
	// 0 (the default) means this feature is disabled.
	AutoRejectMissedCount int `yaml:"auto_reject_missed_count"`
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

// ValidateRuntime returns an error when s is neither empty, "docker", "podman",
// nor "apple". Exposed so the CLI flag can use the same rule as the YAML
// field.
func ValidateRuntime(s string) error {
	switch s {
	case "", "docker", "podman", "apple":
		return nil
	default:
		return fmt.Errorf("runtime: must be \"docker\", \"podman\", or \"apple\", got %q", s)
	}
}

// ValidateSELinux returns an error when s is not one of "", "auto", "on", or
// "off". Exposed so the CLI flag can use the same rule as the YAML field.
func ValidateSELinux(s string) error {
	switch s {
	case "", "auto", "on", "off":
		return nil
	default:
		return fmt.Errorf("selinux: must be \"auto\", \"on\", or \"off\", got %q", s)
	}
}

// Model is a display-name plus the model id it resolves to. The shape
// matches web.Model so main.go can pipe one into the other without the
// two packages depending on each other. Tier optionally tags the entry
// as the default for one of the mid/high/max model tiers so operators
// with a non-Anthropic model list get sensible tier defaults without
// setting each one in /settings.
type Model struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
	Tier string `yaml:"tier"`
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

// Efforts lists every valid effort level, fastest first. These are the only
// values `claude --effort` accepts. Mirror of web.Efforts (which owns the
// display labels); a cross-check test in the web package guards against drift.
var Efforts = []string{"low", "medium", "high", "xhigh", "max"}

// ValidateEffort returns an error when s is not a known effort level. Empty
// is valid (caller keeps the default). Exposed so the CLI flag can use the
// same rule as the YAML field.
func ValidateEffort(s string) error {
	if s == "" || slices.Contains(Efforts, s) {
		return nil
	}
	return fmt.Errorf("effort: unknown %q", s)
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
	// no_container is the canonical key; no_docker is the retained alias.
	// Fold the alias into NoContainer so the rest of the code reads one field.
	if c.NoContainer == nil {
		c.NoContainer = c.NoDocker
	}
	// model_base_url replaced anthropic_base_url; fold the old key so
	// existing configs keep working. Remove after one release.
	if c.ModelBaseURL == "" && c.LegacyAnthropicBaseURL != "" {
		c.ModelBaseURL = c.LegacyAnthropicBaseURL
	}
	if err := ValidateClone(c.Clone); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := ValidateRuntime(c.Runtime); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := ValidateSELinux(c.SELinux); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if _, err := ParseScanTimeout(c.ScanTimeout); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := ValidateTheme(c.Theme); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := ValidateEffort(c.Effort); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}
