package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseToolVersions(t *testing.T) {
	out := "zizmor=zizmor 1.26.1\n" +
		"semgrep=1.167.0\n" +
		"harness=2.1.123 (Claude Code)\n"
	got := parseToolVersions(out)
	if got.Zizmor != "1.26.1" {
		t.Errorf("Zizmor = %q, want 1.26.1", got.Zizmor)
	}
	if got.Semgrep != "1.167.0" {
		t.Errorf("Semgrep = %q, want 1.167.0", got.Semgrep)
	}
	if got.Harness != "2.1.123" {
		t.Errorf("Harness = %q, want 2.1.123", got.Harness)
	}
}

func TestQueryToolsScript_usesHarnessBinary(t *testing.T) {
	// The active backend's binary is interpolated so adding a harness
	// requires no edit here.
	s := queryToolsScript("codex")
	if !strings.Contains(s, "$(codex --version") {
		t.Errorf("script = %q, want codex --version", s)
	}
	if strings.Contains(s, "claude") {
		t.Errorf("script = %q; must not hardcode a harness name", s)
	}
}

func TestParseToolVersions_missingTools(t *testing.T) {
	// A tool that is absent prints an empty value after the "=".
	got := parseToolVersions("zizmor=\nsemgrep=\nharness=\n")
	if got != (RunnerToolVersions{}) {
		t.Errorf("expected zero value for empty versions, got %+v", got)
	}
}

func TestRunnerImageName(t *testing.T) {
	if got := RunnerImageName(ContainerRunner{Image: "example/runner:1"}); got != "example/runner:1" {
		t.Errorf("RunnerImageName(custom) = %q, want example/runner:1", got)
	}
	if got := RunnerImageName(ContainerRunner{}); got != DefaultRunnerImage {
		t.Errorf("RunnerImageName(default) = %q, want %q", got, DefaultRunnerImage)
	}
	if got := RunnerImageName(LocalClaude{}); got != "" {
		t.Errorf("RunnerImageName(local) = %q, want empty", got)
	}
	if got := RunnerImageName(nil); got != "" {
		t.Errorf("RunnerImageName(nil) = %q, want empty", got)
	}
}

func TestRuntimeServerVersion_Apple(t *testing.T) {
	fakeContainer(t)
	got := RuntimeServerVersion(context.Background(), ContainerRuntime{Bin: "apple"})
	if got != "Apple container 1.2.3" {
		t.Errorf("RuntimeServerVersion(apple) = %q, want Apple container 1.2.3", got)
	}
}

func TestQueryRunnerToolVersions_AppleSkipsMissingImage(t *testing.T) {
	logPath := fakeContainer(t)
	got := QueryRunnerToolVersions(context.Background(), ContainerRuntime{Bin: "apple"}, "missing:latest", "claude")
	if got != (RunnerToolVersions{}) {
		t.Errorf("QueryRunnerToolVersions(missing image) = %+v, want zero value", got)
	}
	log := readFakeContainerLog(t, logPath)
	if !strings.Contains(log, "image inspect missing:latest") {
		t.Fatalf("expected local image probe, log = %q", log)
	}
	if strings.Contains(log, "\nrun ") || strings.HasPrefix(log, "run ") {
		t.Fatalf("missing Apple image should not trigger container run, log = %q", log)
	}
}

func TestQueryRunnerToolVersions_AppleRunsLocalImageWithoutPullNever(t *testing.T) {
	logPath := fakeContainer(t)
	got := QueryRunnerToolVersions(context.Background(), ContainerRuntime{Bin: "apple"}, "present:latest", "claude")
	if got.Zizmor != "1.2.3" || got.Semgrep != "4.5.6" || got.Harness != "7.8.9" {
		t.Fatalf("QueryRunnerToolVersions(local image) = %+v", got)
	}
	log := readFakeContainerLog(t, logPath)
	if !strings.Contains(log, "run --progress none --rm") {
		t.Errorf("Apple run should suppress progress, log = %q", log)
	}
	if strings.Contains(log, "--pull never") {
		t.Errorf("Apple run must not use Docker/Podman pull policy, log = %q", log)
	}
}

func fakeContainer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "container.log")
	appleBinary := ContainerRuntime{Bin: "apple"}.bin()
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$SCRUTINEER_FAKE_CONTAINER_LOG"
if [ "$1" = "--version" ]; then
  echo "container CLI version 1.2.3 (build: release)"
  exit 0
fi
if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then
  [ "$3" = "present:latest" ]
  exit $?
fi
if [ "$1" = "run" ]; then
  echo "zizmor=zizmor 1.2.3"
  echo "semgrep=4.5.6"
  echo "harness=some-cli 7.8.9 (build abc)"
  exit 0
fi
exit 64
`
	bin := filepath.Join(dir, appleBinary)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SCRUTINEER_FAKE_CONTAINER_LOG", logPath)
	return logPath
}

func readFakeContainerLog(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
