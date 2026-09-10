package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestZizmorScriptPreservesWorkflowPaths(t *testing.T) {
	skipWithoutPOSIXShell(t)
	script, err := filepath.Abs("../../skills/zizmor/scripts/scan.py")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	workflows := filepath.Join(root, "src", ".github", "workflows")
	if err := os.MkdirAll(workflows, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fakeZizmor := filepath.Join(bin, "zizmor")
	if err := os.WriteFile(fakeZizmor, []byte(fakeZizmorScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("zizmor adapter failed: %v\n%s", err, out)
	}

	var report struct {
		Findings []struct {
			Location  string   `json:"location"`
			Locations []string `json:"locations"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, out)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %s", len(report.Findings), out)
	}
	want := []string{
		".github/workflows/ci.yml:44",
		".github/workflows/release.yml:18",
	}
	if !slices.Equal(report.Findings[0].Locations, want) {
		t.Errorf("locations = %q, want %q", report.Findings[0].Locations, want)
	}
	if report.Findings[0].Location != want[0] {
		t.Errorf("location = %q, want %q", report.Findings[0].Location, want[0])
	}
}

const fakeZizmorScript = `#!/usr/bin/env bash
cat <<'JSON'
[
  {
    "ident": "unpinned-uses",
    "desc": "unpinned action reference",
    "determinations": {"severity": "high"},
    "locations": [{
      "symbolic": {"key": {"Local": {"verbatim_path": ".github/workflows/ci.yml"}}},
      "concrete": {"location": {"start_point": {"row": 43}}}
    }]
  },
  {
    "ident": "unpinned-uses",
    "desc": "unpinned action reference",
    "determinations": {"severity": "high"},
    "locations": [{
      "symbolic": {"key": {"local": {"given_path": ".github/workflows/release.yml"}}},
      "concrete": {"location": {"start_point": {"row": 17}}}
    }]
  }
]
JSON
`
