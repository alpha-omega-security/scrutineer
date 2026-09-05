package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type scriptSection struct {
	Status string          `json:"status"`
	Error  string          `json:"error"`
	Result json.RawMessage `json:"result"`
}

type scriptEnvelope struct {
	SchemaVersion  int                      `json:"schema_version"`
	Commit         string                   `json:"commit"`
	GitPkgsVersion string                   `json:"git_pkgs_version"`
	Analyses       map[string]scriptSection `json:"analyses"`
}

// runAndDecodeDependenciesScript runs index.sh against the stub git-pkgs in
// the given scenario, validates the output against the bundled schema, and
// returns the parsed envelope.
func runAndDecodeDependenciesScript(t *testing.T, mode string) scriptEnvelope {
	t.Helper()
	out, err := runDependenciesScript(t, mode)
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	schema, err := os.ReadFile("../../skills/dependencies/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := ValidateReportSchema(string(schema), out); got != "" {
		t.Fatalf("schema: %s\n%s", got, out)
	}
	var env scriptEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse envelope: %v\n%s", err, out)
	}
	return env
}

func TestDependenciesScript_ok(t *testing.T) {
	env := runAndDecodeDependenciesScript(t, "ok")
	if env.SchemaVersion != 1 {
		t.Errorf("schema_version = %d", env.SchemaVersion)
	}
	if env.GitPkgsVersion != "git-pkgs 0.0.0-test" {
		t.Errorf("git_pkgs_version = %q", env.GitPkgsVersion)
	}
	// Only the two per-repo analyses run; the schema's additionalProperties:false
	// on the analyses object rejects anything else, so a stray section would
	// have failed the schema check above.
	if len(env.Analyses) != 2 {
		t.Errorf("analyses = %v, want inventory+sbom", env.Analyses)
	}
	for _, name := range []string{"inventory", "sbom"} {
		if env.Analyses[name].Status != "ok" {
			t.Errorf("%s status = %q: %s", name, env.Analyses[name].Status, env.Analyses[name].Error)
		}
	}
	var inv []map[string]any
	if err := json.Unmarshal(env.Analyses["inventory"].Result, &inv); err != nil || len(inv) != 1 || inv[0]["name"] != "left-pad" {
		t.Errorf("inventory result = %s", env.Analyses["inventory"].Result)
	}
	var bom map[string]any
	if err := json.Unmarshal(env.Analyses["sbom"].Result, &bom); err != nil || bom["bomFormat"] != "CycloneDX" {
		t.Errorf("sbom result = %s", env.Analyses["sbom"].Result)
	}
	// The stub records --skip-enrichment reaching the sbom command so no
	// registry is contacted from inside the scan.
	if got := bom["_saw_skip_enrichment"]; got != true {
		t.Errorf("sbom command not passed --skip-enrichment: %v", bom)
	}
}

func TestDependenciesScript_listNull(t *testing.T) {
	env := runAndDecodeDependenciesScript(t, "list-null")
	if s := env.Analyses["inventory"]; s.Status != "ok" || string(s.Result) != "[]" {
		t.Errorf("null list should normalise to ok/[]: %+v", s)
	}
}

func TestDependenciesScript_sectionFailure(t *testing.T) {
	env := runAndDecodeDependenciesScript(t, "sbom-fail")
	if s := env.Analyses["sbom"]; s.Status != "error" || s.Error == "" {
		t.Errorf("sbom exit 1 should be status=error: %+v", s)
	}
	if env.Analyses["inventory"].Status != "ok" {
		t.Error("failed sbom must not fail inventory")
	}
}

func runDependenciesScript(t *testing.T, mode string) (string, error) {
	t.Helper()
	skipWithoutPOSIXShell(t)
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
	if err := os.WriteFile(fakeGitPkgs, []byte(fakeGitPkgsScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("bash", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GP_MODE="+mode,
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// fakeGitPkgsScript stands in for the git-pkgs CLI. GP_MODE selects a
// scenario; every command not overridden by the scenario emits a minimal
// representative payload. The default arm rejects any command index.sh should
// no longer be running (licenses, vulns, outdated, deprecated).
const fakeGitPkgsScript = `#!/usr/bin/env bash
set -euo pipefail
mode="${GP_MODE:-ok}"
case "$1" in
  --version) echo "git-pkgs 0.0.0-test" ;;
  init) exit 0 ;;
  list)
    if [ "$mode" = "list-null" ]; then printf 'null\n'; exit 0; fi
    printf '[{"name":"left-pad","ecosystem":"npm","manifest_path":"package.json"}]\n'
    ;;
  sbom)
    if [ "$mode" = "sbom-fail" ]; then echo "sbom failed" >&2; exit 1; fi
    skip=false
    for a in "$@"; do [ "$a" = "--skip-enrichment" ] && skip=true; done
    printf '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"_saw_skip_enrichment":%s}\n' "$skip"
    ;;
  *)
    echo "unexpected git-pkgs command: $*" >&2
    exit 2
    ;;
esac
`
