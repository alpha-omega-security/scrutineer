package ingest

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseSARIF(t *testing.T) {
	results, format, err := Parse(read(t, "testdata/codeql.sarif"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if format != FormatSARIF {
		t.Fatalf("format = %q, want sarif", format)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.Tool != "CodeQL" {
		t.Errorf("Tool = %q, want CodeQL", r.Tool)
	}
	if r.RepoURL != "https://github.com/example/widget.git" {
		t.Errorf("RepoURL = %q", r.RepoURL)
	}
	if r.Commit != "abc123" {
		t.Errorf("Commit = %q", r.Commit)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(r.Findings))
	}

	xss := r.Findings[0]
	if xss.Title != "Reflected cross-site scripting" {
		t.Errorf("xss.Title = %q", xss.Title)
	}
	if xss.CWE != "CWE-79" {
		t.Errorf("xss.CWE = %q, want CWE-79", xss.CWE)
	}
	if xss.Severity != "high" {
		t.Errorf("xss.Severity = %q, want high (from security-severity 7.5)", xss.Severity)
	}
	if xss.Confidence != "high" {
		t.Errorf("xss.Confidence = %q, want high", xss.Confidence)
	}
	if xss.Location != "src/handlers/echo.js:42:7" {
		t.Errorf("xss.Location = %q", xss.Location)
	}
	if xss.Description == "" {
		t.Error("xss.Description empty, want result message text")
	}

	sqli := r.Findings[1]
	if sqli.CWE != "CWE-89" {
		t.Errorf("sqli.CWE = %q, want CWE-89", sqli.CWE)
	}
	if sqli.Severity != "medium" {
		t.Errorf("sqli.Severity = %q, want medium (from level=warning, no score)", sqli.Severity)
	}
	if sqli.Location != "src/db/users.js:17" {
		t.Errorf("sqli.Location = %q", sqli.Location)
	}
}

func TestParseMinimal(t *testing.T) {
	results, format, err := Parse(read(t, "testdata/minimal.json"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if format != FormatMinimal {
		t.Fatalf("format = %q, want minimal", format)
	}
	r := results[0]
	if r.Tool != "pentest-2026q2" {
		t.Errorf("Tool = %q", r.Tool)
	}
	if r.RepoURL != "https://github.com/example/widget" {
		t.Errorf("RepoURL = %q", r.RepoURL)
	}
	f := r.Findings[0]
	if f.CWE != "CWE-22" || f.Severity != "critical" || f.Confidence != "high" {
		t.Errorf("fields = %+v", f)
	}
	if f.SuggestedFix == "" {
		t.Error("SuggestedFix empty, want patch")
	}
}

func TestParseMinimalDefaultsTool(t *testing.T) {
	body := []byte(`{"findings":[{"title":"x"}]}`)
	results, _, err := Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if results[0].Tool != "manual" {
		t.Errorf("Tool = %q, want manual", results[0].Tool)
	}
}

func TestParseCSV(t *testing.T) {
	results, format, err := Parse(read(t, "testdata/findings.csv"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if format != FormatCSV {
		t.Fatalf("format = %q, want csv", format)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (grouped by repository)", len(results))
	}

	widget := results[0]
	if widget.RepoURL != "example/widget" {
		t.Errorf("RepoURL = %q, want example/widget", widget.RepoURL)
	}
	if widget.Tool != "scanner.example" {
		t.Errorf("Tool = %q, want scanner.example (from Finding URL host)", widget.Tool)
	}
	if len(widget.Findings) != 2 {
		t.Fatalf("got %d findings, want 2 (dismissed row skipped)", len(widget.Findings))
	}

	pt := widget.Findings[0]
	if pt.Title != "Path traversal in download URL" {
		t.Errorf("Title = %q", pt.Title)
	}
	if pt.Severity != "medium" || pt.Confidence != "medium" {
		t.Errorf("Severity/Confidence = %q/%q, want medium/medium", pt.Severity, pt.Confidence)
	}
	if pt.CWE != "CWE-22" {
		t.Errorf("CWE = %q, want CWE-22", pt.CWE)
	}
	if pt.Location != "download_url.rb:97" {
		t.Errorf("Location = %q", pt.Location)
	}
	if pt.RuleID != "https://scanner.example/finding/abc" {
		t.Errorf("RuleID = %q, want finding URL", pt.RuleID)
	}
	if !strings.Contains(pt.Description, "Multi-line cell with \"embedded\" quotes.") {
		t.Error("Description should preserve multi-line cells and unescape doubled quotes")
	}

	ssrf := widget.Findings[1]
	if ssrf.Severity != "low" || ssrf.CWE != "" {
		t.Errorf("ssrf Severity/CWE = %q/%q, want low/empty", ssrf.Severity, ssrf.CWE)
	}

	other := results[1]
	if other.RepoURL != "example/other" {
		t.Errorf("second RepoURL = %q", other.RepoURL)
	}
	if other.Findings[0].Severity != "critical" || other.Findings[0].CWE != "CWE-89" {
		t.Errorf("other finding = %+v", other.Findings[0])
	}
}

func TestParseMarkdown(t *testing.T) {
	results, format, err := Parse(read(t, "testdata/findings.md"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if format != FormatMarkdown {
		t.Fatalf("format = %q, want markdown", format)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.RepoURL != "https://github.com/example/widget" {
		t.Errorf("RepoURL = %q, want full URL from location link", r.RepoURL)
	}
	if len(r.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(r.Findings))
	}

	pt := r.Findings[0]
	if pt.Title != "Path traversal in download URL" {
		t.Errorf("Title = %q", pt.Title)
	}
	if pt.Severity != "medium" {
		t.Errorf("Severity = %q, want medium", pt.Severity)
	}
	if pt.Location != "download_url.rb:97" {
		t.Errorf("Location = %q", pt.Location)
	}
	if !strings.Contains(pt.SuggestedFix, "re-encoded when interpolated") {
		t.Errorf("SuggestedFix = %q, want recommended-fix section", pt.SuggestedFix)
	}
	if !strings.Contains(pt.Description, "without re-encoding") {
		t.Error("Description should contain Details section")
	}
	if !strings.Contains(pt.Description, "## Impact") || !strings.Contains(pt.Description, "Allowlist check") {
		t.Error("Description should append Impact section")
	}
	if !strings.Contains(pt.Description, "## Reproduction steps") {
		t.Error("Description should append Reproduction steps section")
	}
	if strings.Contains(pt.Description, "Recommended fix") {
		t.Error("Description should not include Recommended fix (goes to SuggestedFix)")
	}

	ssrf := r.Findings[1]
	if ssrf.Severity != "low" || ssrf.Location != "lookup.rb:179" {
		t.Errorf("ssrf = %+v", ssrf)
	}
	if strings.Contains(ssrf.Description, "## Impact") {
		t.Error("ssrf has no Impact section, should not append empty heading")
	}
}

func TestParseUnrecognised(t *testing.T) {
	if _, _, err := Parse([]byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("want error for unrecognised input")
	}
	if _, _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("want error for non-JSON input")
	}
}

func TestCWEFromTags(t *testing.T) {
	cases := map[string]string{
		"external/cwe/cwe-079": "CWE-79",
		"CWE-89":               "CWE-89",
		"cwe 1333":             "CWE-1333",
		"security":             "",
	}
	for in, want := range cases {
		if got := cweFromTags([]string{in}); got != want {
			t.Errorf("cweFromTags(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSarifSeverity(t *testing.T) {
	cases := []struct {
		level, score, want string
	}{
		{"error", "9.1", "critical"},
		{"warning", "7.0", "high"},
		{"", "4.0", "medium"},
		{"", "0.5", "low"},
		{"error", "", "high"},
		{"warning", "", "medium"},
		{"note", "", "low"},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := sarifSeverity(tc.level, tc.score); got != tc.want {
			t.Errorf("sarifSeverity(%q, %q) = %q, want %q", tc.level, tc.score, got, tc.want)
		}
	}
}
