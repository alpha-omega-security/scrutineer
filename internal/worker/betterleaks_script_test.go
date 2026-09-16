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

type betterleaksReport struct {
	Findings []struct {
		Title      string   `json:"title"`
		Severity   string   `json:"severity"`
		Confidence string   `json:"confidence"`
		CWE        string   `json:"cwe"`
		Location   string   `json:"location"`
		Locations  []string `json:"locations"`
		Trace      string   `json:"trace"`
	} `json:"findings"`
	Error string `json:"error"`
}

func TestBetterleaksScriptSanitizesFindings(t *testing.T) {
	root, argvLog := betterleaksWorkspace(t, fakeBetterleaksScript)
	report, raw := runBetterleaksAdapter(t, root, true)

	if len(report.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: %s", len(report.Findings), raw)
	}
	first := report.Findings[0]
	if first.Title != "gitlab-pat" || first.Severity != "High" || first.Confidence != "high" {
		t.Errorf("first finding = %+v", first)
	}
	if first.CWE != "" {
		t.Errorf("CWE = %q, want empty because Betterleaks does not assign one", first.CWE)
	}
	if first.Location != "config/app.env:9" || !slices.Equal(first.Locations, []string{"config/app.env:9"}) {
		t.Errorf("locations = %q / %q", first.Location, first.Locations)
	}
	if first.Trace != "Detected a GitLab personal access token." {
		t.Errorf("trace = %q", first.Trace)
	}
	for _, secret := range []string{"sensitive-value-that-must-be-removed", "captured-value-that-must-be-removed", "private commit text", "private@example.com"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("report retained sensitive Betterleaks field %q: %s", secret, raw)
		}
	}

	argv, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal(err)
	}
	wantArgv := []string{"git", ".", "--report-format", "json", "--report-path", "-", "--redact=100", "--exit-code", "0", "--no-banner"}
	gotArgv := strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n")
	if !slices.Equal(gotArgv, wantArgv) {
		t.Errorf("betterleaks argv = %q, want %q", gotArgv, wantArgv)
	}
}

func TestBetterleaksScriptWithoutTool(t *testing.T) {
	root, _ := betterleaksWorkspace(t, "")
	report, _ := runBetterleaksAdapter(t, root, false)

	if report.Error != "betterleaks not on PATH" {
		t.Errorf("error = %q, want %q", report.Error, "betterleaks not on PATH")
	}
}

func TestBetterleaksScriptAcceptsNullCleanReport(t *testing.T) {
	root, _ := betterleaksWorkspace(t, fakeBetterleaksCleanScript)
	report, raw := runBetterleaksAdapter(t, root, true)

	if len(report.Findings) != 0 || report.Error != "" {
		t.Errorf("clean report = %+v, raw = %s", report, raw)
	}
}

func TestBetterleaksScriptWithoutCheckout(t *testing.T) {
	report, _ := runBetterleaksAdapter(t, t.TempDir(), false)

	if report.Error != "no ./src directory" {
		t.Errorf("error = %q, want %q", report.Error, "no ./src directory")
	}
}

func betterleaksWorkspace(t *testing.T, script string) (root, argvLog string) {
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
	if err := os.WriteFile(filepath.Join(bin, "betterleaks"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return root, argvLog
}

func runBetterleaksAdapter(t *testing.T, root string, onPath bool) (betterleaksReport, []byte) {
	t.Helper()
	script, err := filepath.Abs("../../skills/betterleaks/scripts/scan.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script)
	cmd.Dir = root
	path := ""
	if onPath {
		path = filepath.Join(root, "bin") + string(os.PathListSeparator) + os.Getenv("PATH")
	}
	cmd.Env = append(os.Environ(), "PATH="+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("betterleaks adapter failed: %v\n%s", err, out)
	}
	var report betterleaksReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, out)
	}
	return report, out
}

const fakeBetterleaksScript = `#!/usr/bin/env bash
printf '%s\n' "$@" > "@ARGV_LOG@"
cat <<'JSON'
[
  {
    "RuleID": "gitlab-pat",
    "Description": "Detected a GitLab personal access token.",
    "StartLine": 9,
    "Match": "token=sensitive-value-that-must-be-removed",
    "Secret": "sensitive-value-that-must-be-removed",
    "CaptureGroups": {"token": "captured-value-that-must-be-removed"},
    "Attributes": {
      "confidence": "high",
      "git.message": "private commit text",
      "git.author_email": "private@example.com"
    },
    "File": "./config/app.env"
  },
  {
    "RuleID": "private-key",
    "Description": "Detected a private key.",
    "StartLine": 3,
    "Attributes": {"confidence": "low"},
    "File": "infra/key.pem"
  }
]
JSON
`

const fakeBetterleaksCleanScript = `#!/usr/bin/env bash
printf 'null\n'
`
