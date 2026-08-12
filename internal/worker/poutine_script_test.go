package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestPoutineScriptGroupsByRule(t *testing.T) {
	script, err := filepath.Abs("../../skills/poutine/scripts/scan.py")
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
	fakePoutine := filepath.Join(bin, "poutine")
	if err := os.WriteFile(fakePoutine, []byte(fakePoutineScript), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("python3", script)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("poutine adapter failed: %v\n%s", err, out)
	}

	var report struct {
		Findings []struct {
			Title     string   `json:"title"`
			Severity  string   `json:"severity"`
			Location  string   `json:"location"`
			Locations []string `json:"locations"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, out)
	}
	// Three hits over two rules: the pair sharing untrusted_checkout_exec
	// collapses into one finding carrying both locations.
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: %s", len(report.Findings), out)
	}

	// Findings come out ordered by rule id, so debug_enabled precedes
	// untrusted_checkout_exec regardless of the order poutine emitted them.
	checkout := report.Findings[1]
	if checkout.Title != "Arbitrary Code Execution from Untrusted Code Checkout" {
		t.Errorf("title = %q, want the rule's title", checkout.Title)
	}
	if checkout.Severity != "High" {
		t.Errorf("severity = %q, want High for a poutine error", checkout.Severity)
	}
	want := []string{
		".github/workflows/ci.yml:44",
		".github/workflows/release.yml:18",
	}
	if !slices.Equal(checkout.Locations, want) {
		t.Errorf("locations = %q, want %q", checkout.Locations, want)
	}
	if checkout.Location != want[0] {
		t.Errorf("location = %q, want %q", checkout.Location, want[0])
	}

	// A finding poutine reports with no line is about the file as a whole, so
	// the bare path is the location rather than a fabricated `:0`.
	debug := report.Findings[0]
	if debug.Severity != "Low" {
		t.Errorf("severity = %q, want Low for a poutine note", debug.Severity)
	}
	if !slices.Equal(debug.Locations, []string{".gitlab-ci.yml"}) {
		t.Errorf("locations = %q, want the bare path", debug.Locations)
	}
}

const fakePoutineScript = `#!/usr/bin/env bash
cat <<'JSON'
{
  "findings": [
    {
      "rule_id": "untrusted_checkout_exec",
      "purl": "pkg:localrepo/localrepo/local?repository_url=.",
      "meta": {"path": ".github/workflows/ci.yml", "line": 44, "job": "build"}
    },
    {
      "rule_id": "untrusted_checkout_exec",
      "purl": "pkg:localrepo/localrepo/local?repository_url=.",
      "meta": {"path": ".github/workflows/release.yml", "line": 18, "job": "publish"}
    },
    {
      "rule_id": "debug_enabled",
      "purl": "pkg:localrepo/localrepo/local?repository_url=.",
      "meta": {"path": ".gitlab-ci.yml"}
    }
  ],
  "rules": {
    "untrusted_checkout_exec": {
      "id": "untrusted_checkout_exec",
      "title": "Arbitrary Code Execution from Untrusted Code Checkout",
      "description": "The workflow checks out untrusted code and executes it.",
      "level": "error"
    },
    "debug_enabled": {
      "id": "debug_enabled",
      "title": "CI Runner Debug Enabled",
      "description": "The workflow increases the verbosity of the runner.",
      "level": "note"
    }
  }
}
JSON
`
