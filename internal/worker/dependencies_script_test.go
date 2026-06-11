package worker

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDependenciesScriptNormalizesEmptyGitPkgsOutput(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want string
	}{
		{"null", "null", `{"dependencies":[]}` + "\n"},
		{"empty", "empty", `{"dependencies":[]}` + "\n"},
		{"array", "array", `{"dependencies":[{"name":"left-pad","ecosystem":"npm"}]}` + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runDependenciesScript(t, tc.mode)
			if err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			if out != tc.want {
				t.Fatalf("output = %q, want %q", out, tc.want)
			}
			schema, err := os.ReadFile("../../skills/dependencies/schema.json")
			if err != nil {
				t.Fatal(err)
			}
			if got := validateReportSchema(string(schema), out); got != "" {
				t.Fatalf("script output failed schema validation: %s\n%s", got, out)
			}
		})
	}
}

func TestDependenciesScriptRejectsNonArrayGitPkgsOutput(t *testing.T) {
	out, err := runDependenciesScript(t, "object")
	if err == nil {
		t.Fatalf("script succeeded with non-array output: %s", out)
	}
	if !strings.Contains(out, "want array") {
		t.Fatalf("output = %q, want array error", out)
	}
}

func runDependenciesScript(t *testing.T, mode string) (string, error) {
	t.Helper()
	script, err := filepath.Abs("../../skills/dependencies/scripts/index.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeGitPkgs := filepath.Join(bin, "git-pkgs")
	if err := os.WriteFile(fakeGitPkgs, []byte(`#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  init)
    exit 0
    ;;
  list)
    case "${GIT_PKGS_LIST_OUTPUT:-array}" in
      null)
        printf 'null\n'
        ;;
      empty)
        ;;
      object)
        printf '{"name":"left-pad"}\n'
        ;;
      array)
        printf '[{"name":"left-pad","ecosystem":"npm"}]\n'
        ;;
      *)
        echo "unknown mode: ${GIT_PKGS_LIST_OUTPUT}" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "unexpected git-pkgs command: $*" >&2
    exit 2
    ;;
esac
`), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GIT_PKGS_LIST_OUTPUT="+mode,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
