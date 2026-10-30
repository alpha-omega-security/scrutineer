package worker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/testutil"
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
		Rating     string   `json:"rating"`
	} `json:"findings"`
	Error string `json:"error"`
}

func TestBetterleaksScriptFixtureSeverity(t *testing.T) {
	skipWithoutPython3(t)
	cases := []struct {
		path, rule, validation, reason string
	}{
		{"auth_test.go", "generic-credential-uri", "", "test, fixture or example"},
		{"./pkg/auth_test.go", "private-key", "", "test, fixture or example"},
		{"testdata/sample.env", "gitlab-pat", "", "test, fixture or example"},
		{"vendor/scanner/testdata/secrets.tar!config.env", "gitlab-pat", "", "test, fixture or example"},
		{"lib/fixtures/keys.json", "generic-api-key", "", "test, fixture or example"},
		{"lib/__fixtures__/keys.json", "generic-api-key", "", "test, fixture or example"},
		{"examples/docker-compose.yml", "generic-credential-uri", "", "test, fixture or example"},
		{"example/config.yml", "generic-credential-uri", "", "test, fixture or example"},
		{`vendor\scanner\TestData\keys.json`, "generic-api-key", "", "test, fixture or example"},
		{".betterleaks.toml", "generic-api-key", "", "rule file"},
		{"vendor/scanner/config/betterleaks.toml", "generic-api-key", "", "rule file"},
		{".gitleaks.toml", "generic-api-key", "", "rule file"},
		{"config/gitleaks.toml", "generic-api-key", "", "rule file"},
		{"data/licenses.json", "generic-api-key", "", "license data"},
		{"testdata/live.env", "gitlab-pat", "valid", ""},
		{"config/app.env", "generic-api-key", "", ""},
		{"docker-compose.yml", "generic-credential-uri", "", ""},
		{"data/licenses.json", "gitlab-pat", "", ""},
		{"src/testdata_loader.go", "gitlab-pat", "", ""},
		{"src/examples.go", "gitlab-pat", "", ""},
		{"testdatabase/config.env", "gitlab-pat", "", ""},
		{"config/rules.toml", "gitlab-pat", "", ""},
		{"", "gitlab-pat", "", ""},
	}
	var detections []map[string]any
	for _, tc := range cases {
		detections = append(detections, map[string]any{
			"File": tc.path, "RuleID": tc.rule, "ValidationStatus": tc.validation,
			"StartLine": 2, "Secret": "synthetic-secret-value", "Match": "synthetic-secret-value",
			"Attributes": map[string]string{"confidence": "high"},
		})
	}
	data, err := json.Marshal(detections)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := betterleaksWorkspace(t, "#!/bin/sh\ncat <<'JSON'\n"+string(data)+"\nJSON\n")
	report, raw := runBetterleaksAdapter(t, root, true)
	if report.Error != "" || len(report.Findings) != len(cases) {
		t.Fatalf("unexpected report: %s", raw)
	}
	for i, tc := range cases {
		want := "High"
		if tc.reason != "" {
			want = "Low"
		}
		finding := report.Findings[i]
		if finding.Severity != want || !strings.Contains(finding.Rating, tc.reason) || !strings.HasPrefix(finding.Rating, want+" from Betterleaks") || finding.Confidence != "high" {
			t.Errorf("%s: finding = %+v, want %s with reason %q", tc.path, finding, want, tc.reason)
		}
	}
	if strings.Contains(string(raw), "synthetic-secret-value") {
		t.Fatal("adapter exposed a raw secret")
	}
}

func TestBetterleaksScriptGitFixtureSeverity(t *testing.T) {
	skipWithoutPython3(t)
	for _, tool := range []string{"betterleaks", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	root, _ := betterleaksWorkspace(t, "")
	paths := map[string]string{
		"config/app.env":                   "High",
		"internal/client_test.go":          "Low",
		"vendor/scanner/testdata/keys.env": "Low",
		"examples/app.env":                 "Low",
	}
	secret := "glpat-" + "a8Zk4mQ9pR2xV7nL5sT1"
	for path := range paths {
		file := filepath.Join(root, "src", path)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("TOKEN="+secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q"}, {"add", "."},
		{"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "Add synthetic token fixtures"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = filepath.Join(root, "src"), testutil.GitEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %v: %s", err, out)
		}
	}
	report, raw := runBetterleaksAdapter(t, root, true)
	if report.Error != "" {
		t.Fatal(report.Error)
	}
	got := map[string]string{}
	for _, finding := range report.Findings {
		if finding.Title == "gitlab-pat" {
			got[finding.Location] = finding.Severity
		}
	}
	for path, severity := range paths {
		if got[path+":1"] != severity {
			t.Errorf("%s: severity = %q, want %s", path, got[path+":1"], severity)
		}
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("adapter exposed synthetic token")
	}
}

func TestBetterleaksScriptSanitizesFindings(t *testing.T) {
	skipWithoutPython3(t)
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
	skipWithoutPython3(t)
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
	writeFakeBin(t, bin, "betterleaks", body)
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
