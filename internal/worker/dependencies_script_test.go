package worker

import (
	"encoding/json"
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

func TestDependenciesScriptResolvesMavenPropertyRequirements(t *testing.T) {
	out, err := runDependenciesScript(t, "maven")
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	var report struct {
		Dependencies []struct {
			Name                  string `json:"name"`
			Requirement           string `json:"requirement"`
			RequirementUnresolved bool   `json:"requirement_unresolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("parse report: %v\n%s", err, out)
	}
	got := map[string]struct {
		req        string
		unresolved bool
	}{}
	for _, dep := range report.Dependencies {
		got[dep.Name] = struct {
			req        string
			unresolved bool
		}{dep.Requirement, dep.RequirementUnresolved}
	}
	if got["org.openjdk.jmh:jmh-core"].req != "1.37" || got["org.openjdk.jmh:jmh-core"].unresolved {
		t.Fatalf("direct property not resolved: %+v", got["org.openjdk.jmh:jmh-core"])
	}
	if got["org.example:child"].req != "2.0.0" || got["org.example:child"].unresolved {
		t.Fatalf("parent project.version not resolved: %+v", got["org.example:child"])
	}
	if got["org.example:missing"].req != "${missing.version}" || !got["org.example:missing"].unresolved {
		t.Fatalf("missing property should be flagged unresolved: %+v", got["org.example:missing"])
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
	if mode == "maven" {
		writeMavenFixture(t, filepath.Join(root, "src"))
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
	      maven)
	        cat <<'JSON'
[{"name":"org.openjdk.jmh:jmh-core","ecosystem":"maven","requirement":"${jmh.version}","manifest_path":"pom.xml"},{"name":"org.example:child","ecosystem":"maven","requirement":"${project.version}","manifest_path":"module/pom.xml"},{"name":"org.example:missing","ecosystem":"maven","requirement":"${missing.version}","manifest_path":"pom.xml"}]
JSON
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

func writeMavenFixture(t *testing.T, src string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(src, "pom.xml"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>2.0.0</version>
  <properties>
    <jmh.version>1.37</jmh.version>
  </properties>
</project>
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(src, "module"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "module", "pom.xml"), []byte(`<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>2.0.0</version>
  </parent>
  <artifactId>child</artifactId>
</project>
`), 0o644); err != nil {
		t.Fatal(err)
	}
}
