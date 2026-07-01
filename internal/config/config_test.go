package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scrutineer.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad_absentDefaultPathIsNoError(t *testing.T) {
	// ./scrutineer.yaml doesn't exist in a t.TempDir CWD. Switch into one.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	_ = os.Chdir(t.TempDir())

	c, err := Load("")
	if err != nil {
		t.Fatalf("err=%v, want nil", err)
	}
	if c != nil {
		t.Errorf("config=%+v, want nil", c)
	}
}

func TestLoad_explicitMissingPathIsError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for explicit missing path")
	}
}

func TestLoad_parsesFields(t *testing.T) {
	path := write(t, `
addr: 0.0.0.0:9000
data: /var/lib/scrutineer
effort: medium
default_model: claude-sonnet-4-6
models:
  - name: Sonnet 4.6
    id:   claude-sonnet-4-6
  - name: Opus
    id:   claude-opus-4-6
skills:
  - ./skills
  - /srv/skills
skills_repo: https://github.com/org/skills
no_container: true
hardened: true
runner_image: custom-runner
egress_allow:
  - artifactory.internal
  - "*.mycorp.net"
concurrency: 8
clone: full
scan_timeout: 30m
max_turns: 200
fork_org: fork-central
metadata_dir: .ossprey/
`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "0.0.0.0:9000" || c.DefaultModel != "claude-sonnet-4-6" {
		t.Errorf("flat fields: %+v", c)
	}
	if len(c.Models) != 2 || c.Models[0].Name != "Sonnet 4.6" {
		t.Errorf("models: %+v", c.Models)
	}
	if len(c.Skills) != 2 {
		t.Errorf("skills: %+v", c.Skills)
	}
	if c.NoContainer == nil || !*c.NoContainer {
		t.Errorf("no_container: %v", c.NoContainer)
	}
	if c.Hardened == nil || !*c.Hardened {
		t.Errorf("hardened: %v", c.Hardened)
	}
	if c.Concurrency != 8 {
		t.Errorf("concurrency: %d", c.Concurrency)
	}
	if len(c.EgressAllow) != 2 || c.EgressAllow[0] != "artifactory.internal" || c.EgressAllow[1] != "*.mycorp.net" {
		t.Errorf("egress_allow: %+v", c.EgressAllow)
	}
	if c.Clone != "full" {
		t.Errorf("clone: %q, want full", c.Clone)
	}
	if c.ScanTimeout != "30m" || c.MaxTurns != 200 {
		t.Errorf("scan_timeout=%q max_turns=%d", c.ScanTimeout, c.MaxTurns)
	}
	if c.ForkOrg != "fork-central" {
		t.Errorf("fork_org=%q, want fork-central", c.ForkOrg)
	}
	if c.MetadataDir != ".ossprey/" {
		t.Errorf("metadata_dir=%q, want .ossprey/", c.MetadataDir)
	}
}

func TestLoad_noContainerAlias(t *testing.T) {
	// no_docker is the retained pre-rename alias; Load folds it into NoContainer.
	aliasOnly, err := Load(write(t, "no_docker: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if aliasOnly.NoContainer == nil || !*aliasOnly.NoContainer {
		t.Errorf("no_docker alias did not set NoContainer: %v", aliasOnly.NoContainer)
	}

	// no_container is canonical and wins when both keys are present.
	both, err := Load(write(t, "no_container: false\nno_docker: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if both.NoContainer == nil || *both.NoContainer {
		t.Errorf("no_container should win over no_docker: %v", both.NoContainer)
	}
}

func TestParseScanTimeout(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{"0", 0, true},
		{"-5m", 0, true},
		{"banana", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseScanTimeout(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseScanTimeout(%q) err = %v", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseScanTimeout(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestLoad_rejectsInvalidScanTimeout(t *testing.T) {
	path := write(t, "scan_timeout: nope\n")
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid scan_timeout value")
	}
}

func TestLoad_rejectsInvalidClone(t *testing.T) {
	path := write(t, "clone: fast\n")
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid clone value")
	}
}

func TestValidateRuntime(t *testing.T) {
	for _, name := range []string{"", "docker", "podman", "apple"} {
		if err := ValidateRuntime(name); err != nil {
			t.Errorf("ValidateRuntime(%q) = %v, want nil", name, err)
		}
	}
	if err := ValidateRuntime("containerd"); err == nil {
		t.Error("expected error for unknown runtime")
	}
}

func TestLoad_rejectsUnparseable(t *testing.T) {
	path := write(t, "addr: [this is not valid yaml: for a string")
	if _, err := Load(path); err == nil {
		t.Error("expected parse error")
	}
}

func TestValidateTheme(t *testing.T) {
	for _, name := range []string{"", "claude", "ocean-breeze", "catppuccin", "sunset-horizon", "midnight-bloom", "northern-lights"} {
		if err := ValidateTheme(name); err != nil {
			t.Errorf("ValidateTheme(%q) = %v, want nil", name, err)
		}
	}
	if err := ValidateTheme("nope"); err == nil {
		t.Error("expected error for unknown theme")
	}
}

func TestLoad_rejectsInvalidTheme(t *testing.T) {
	path := write(t, "theme: nope\n")
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid theme value")
	}
}

func TestLoad_parsesTheme(t *testing.T) {
	path := write(t, "theme: catppuccin\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Theme != "catppuccin" {
		t.Errorf("theme=%q, want catppuccin", c.Theme)
	}
}

func TestValidateEffort(t *testing.T) {
	for _, name := range []string{"", "low", "medium", "high", "xhigh", "max"} {
		if err := ValidateEffort(name); err != nil {
			t.Errorf("ValidateEffort(%q) = %v, want nil", name, err)
		}
	}
	if err := ValidateEffort("superhigh"); err == nil {
		t.Error("expected error for unknown effort")
	}
}

func TestLoad_rejectsInvalidEffort(t *testing.T) {
	path := write(t, "effort: superhigh\n")
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid effort value")
	}
}

func TestLoad_parsesEffort(t *testing.T) {
	path := write(t, "effort: max\n")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Effort != "max" {
		t.Errorf("effort=%q, want max", c.Effort)
	}
}
