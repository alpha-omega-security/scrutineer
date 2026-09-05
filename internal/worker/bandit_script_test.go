package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// banditReport is the subset of the adapter's envelope the tests assert on.
type banditReport struct {
	Findings []struct {
		Title      string   `json:"title"`
		Severity   string   `json:"severity"`
		Confidence string   `json:"confidence"`
		CWE        string   `json:"cwe"`
		Location   string   `json:"location"`
		Locations  []string `json:"locations"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"findings"`
	Notes string `json:"notes"`
	Error string `json:"error"`
}

func TestBanditScriptGroupsHitsPerTestID(t *testing.T) {
	root, argvLog := banditWorkspace(t, fakeBanditScript)
	report := runBanditAdapter(t, root, true)

	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(report.Findings), report.Findings)
	}
	shell := report.Findings[0]
	if shell.Title != "B602 subprocess_popen_with_shell_equals_true" {
		t.Errorf("title = %q", shell.Title)
	}
	// bandit reports paths as ./pkg/app.py; the prefix is stripped so the
	// location resolves against the checkout like every other skill's.
	want := []string{"other.py:5", "pkg/app.py:6"}
	if !slices.Equal(shell.Locations, want) {
		t.Errorf("locations = %q, want %q", shell.Locations, want)
	}
	if shell.Location != want[0] {
		t.Errorf("location = %q, want %q", shell.Location, want[0])
	}
	if shell.Severity != "High" || shell.Confidence != "high" || shell.CWE != "CWE-78" {
		t.Errorf("severity/confidence/cwe = %q/%q/%q, want High/high/CWE-78",
			shell.Severity, shell.Confidence, shell.CWE)
	}
	if len(shell.References) != 1 || !strings.Contains(shell.References[0].URL, "b602") {
		t.Errorf("references = %+v, want the bandit docs link", shell.References)
	}

	// A second hit of the same test id with a different message stays its own
	// finding: bandit interpolates the offending name when the matches differ.
	if got := report.Findings[1].Title; got != "B105 hardcoded_password_string" {
		t.Errorf("second finding title = %q", got)
	}

	// The exclude list has to reach bandit, or test and spec code lands in the
	// findings table.
	argv, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"*_test.py", "*/tests", "*/conftest.py", "__pycache__"} {
		if !strings.Contains(string(argv), want) {
			t.Errorf("bandit argv %q missing exclude %q", argv, want)
		}
	}
}

func TestBanditScriptReportsUnreadableFiles(t *testing.T) {
	root, _ := banditWorkspace(t, fakeBanditErrorsScript)
	report := runBanditAdapter(t, root, true)

	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
	// bandit exits zero on a file it could not parse, so an unreported error
	// is indistinguishable from a clean file.
	if !strings.Contains(report.Notes, "bad.py") {
		t.Errorf("notes = %q, want the unparsed file named", report.Notes)
	}
}

func TestBanditScriptWithoutTool(t *testing.T) {
	root, _ := banditWorkspace(t, "")
	report := runBanditAdapter(t, root, false)

	if len(report.Findings) != 0 {
		t.Fatalf("findings = %d, want 0", len(report.Findings))
	}
	if report.Error != "bandit not on PATH" {
		t.Errorf("error = %q, want %q", report.Error, "bandit not on PATH")
	}
}

func TestBanditScriptWithoutCheckout(t *testing.T) {
	root := t.TempDir()
	report := runBanditAdapter(t, root, false)

	if report.Error != "no ./src directory" {
		t.Errorf("error = %q, want %q", report.Error, "no ./src directory")
	}
}

// banditWorkspace builds a scan workspace with a ./src checkout and, when
// script is non-empty, a fake bandit on PATH that logs its argv. Returns the
// workspace root and the argv log path.
func banditWorkspace(t *testing.T, script string) (root, argvLog string) {
	t.Helper()
	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	argvLog = filepath.Join(root, "argv.log")
	if script == "" {
		return root, argvLog
	}
	body := strings.Replace(script, "@ARGV_LOG@", argvLog, 1)
	if err := os.WriteFile(filepath.Join(bin, "bandit"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return root, argvLog
}

func runBanditAdapter(t *testing.T, root string, onPath bool) banditReport {
	t.Helper()
	skipWithoutPOSIXShell(t)
	script, err := filepath.Abs("../../skills/bandit/scripts/scan.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script)
	cmd.Dir = root
	// The fake is prepended rather than isolated so its own shebang still
	// resolves; an empty PATH is what "bandit is not installed" looks like.
	path := ""
	if onPath {
		path = filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH")
	}
	cmd.Env = append(os.Environ(), "PATH="+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bandit adapter failed: %v\n%s", err, out)
	}
	var report banditReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, out)
	}
	return report
}

const fakeBanditScript = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "@ARGV_LOG@"
cat <<'JSON'
{
  "errors": [],
  "results": [
    {
      "filename": "./pkg/app.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
      "issue_severity": "HIGH",
      "issue_text": "subprocess call with shell=True identified, security issue.",
      "line_number": 6,
      "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b602_subprocess_popen_with_shell_equals_true.html",
      "test_id": "B602",
      "test_name": "subprocess_popen_with_shell_equals_true"
    },
    {
      "filename": "./other.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
      "issue_severity": "HIGH",
      "issue_text": "subprocess call with shell=True identified, security issue.",
      "line_number": 5,
      "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b602_subprocess_popen_with_shell_equals_true.html",
      "test_id": "B602",
      "test_name": "subprocess_popen_with_shell_equals_true"
    },
    {
      "filename": "./pkg/app.py",
      "issue_confidence": "MEDIUM",
      "issue_cwe": {"id": 259, "link": "https://cwe.mitre.org/data/definitions/259.html"},
      "issue_severity": "LOW",
      "issue_text": "Possible hardcoded password: 'hunter2'",
      "line_number": 13,
      "more_info": "https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html",
      "test_id": "B105",
      "test_name": "hardcoded_password_string"
    }
  ]
}
JSON
exit 1
`

const fakeBanditErrorsScript = `#!/usr/bin/env bash
printf '%s\n' "$*" >> "@ARGV_LOG@"
cat <<'JSON'
{
  "errors": [{"filename": "./bad.py", "reason": "syntax error while parsing AST from file"}],
  "results": []
}
JSON
exit 0
`
