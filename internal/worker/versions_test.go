package worker

import "testing"

func TestParseToolVersions(t *testing.T) {
	out := "zizmor=zizmor 1.24.1\n" +
		"semgrep=1.167.0\n" +
		"claude=2.1.123 (Claude Code)\n"
	got := parseToolVersions(out)
	if got.Zizmor != "1.24.1" {
		t.Errorf("Zizmor = %q, want 1.24.1", got.Zizmor)
	}
	if got.Semgrep != "1.167.0" {
		t.Errorf("Semgrep = %q, want 1.167.0", got.Semgrep)
	}
	if got.Claude != "2.1.123" {
		t.Errorf("Claude = %q, want 2.1.123", got.Claude)
	}
}

func TestParseToolVersions_missingTools(t *testing.T) {
	// A tool that is absent prints an empty value after the "=".
	got := parseToolVersions("zizmor=\nsemgrep=\nclaude=\n")
	if got != (RunnerToolVersions{}) {
		t.Errorf("expected zero value for empty versions, got %+v", got)
	}
}

func TestRunnerImageName(t *testing.T) {
	if got := RunnerImageName(DockerRunner{Image: "example/runner:1"}); got != "example/runner:1" {
		t.Errorf("RunnerImageName(custom) = %q, want example/runner:1", got)
	}
	if got := RunnerImageName(DockerRunner{}); got != DefaultRunnerImage {
		t.Errorf("RunnerImageName(default) = %q, want %q", got, DefaultRunnerImage)
	}
	if got := RunnerImageName(LocalClaude{}); got != "" {
		t.Errorf("RunnerImageName(local) = %q, want empty", got)
	}
	if got := RunnerImageName(nil); got != "" {
		t.Errorf("RunnerImageName(nil) = %q, want empty", got)
	}
}
