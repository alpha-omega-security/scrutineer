package web

import (
	"strings"
	"testing"
)

func TestRenderMarkdown_codeBlock(t *testing.T) {
	src := "Some text\n\n```go\nfmt.Println(\"hello\")\n```\n"
	got := string(renderMarkdown(src))
	if !strings.Contains(got, "<code class=\"language-go\">") {
		t.Errorf("expected language-go code block, got:\n%s", got)
	}
	if !strings.Contains(got, "fmt.Println") {
		t.Errorf("expected code content preserved, got:\n%s", got)
	}
}

func TestRenderMarkdown_inlineCode(t *testing.T) {
	src := "Use `foo()` here."
	got := string(renderMarkdown(src))
	if !strings.Contains(got, "<code>foo()</code>") {
		t.Errorf("expected inline code, got:\n%s", got)
	}
}

func TestRenderMarkdown_escapsHTML(t *testing.T) {
	src := "Test <script>alert(1)</script> end"
	got := string(renderMarkdown(src))
	if strings.Contains(got, "<script>") {
		t.Errorf("raw HTML should be escaped, got:\n%s", got)
	}
}

func TestRenderMarkdown_dropsUnsafe(t *testing.T) {
	got := string(renderMarkdown("<div onclick=\"x\">hi</div>\n\n[x](javascript:alert(1)) ![y](vbscript:x) <img src=x onerror=alert(1)>"))
	for _, bad := range []string{"onclick", "javascript:", "vbscript:", "onerror", "<img src=x"} {
		if strings.Contains(got, bad) {
			t.Errorf("output keeps %q:\n%s", bad, got)
		}
	}
}

func TestRenderMarkdown_gfm(t *testing.T) {
	got := string(renderMarkdown("| a |\n|---|\n| 1 |\n\n~~gone~~ https://example.com\n\n- [x] done\n"))
	for _, want := range []string{"<table>", "<td>1</td>", "<del>gone</del>", `<a href="https://example.com">`, `<input checked="" disabled="" type="checkbox">`} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
}

func TestRenderMarkdown_empty(t *testing.T) {
	got := string(renderMarkdown(""))
	if got != "" {
		t.Errorf("empty input should produce empty output, got:\n%q", got)
	}
}

// TestUnmark pins code-span delimiters dropped and literal backticks kept.
func TestUnmark(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"`buildQuery` formats the column list.", "buildQuery formats the column list."},
		{"Runs `` `id` `` through the shell.", "Runs `id` through the shell."},
		{"``a`b`` and `c`", "a`b and c"},
		{"`a``b`", "a``b"},
		{"Runs \\`id\\` through the shell.", "Runs \\`id\\` through the shell."},
		{"\\``foo`", "\\`foo"},
		{"\\\\`foo`", "\\\\foo"},
		{"`a\\`b`", "a\\b`"},
		{"a stray ` stays", "a stray ` stays"},
		{"unclosed `` run`", "unclosed `` run`"},
		{"no markdown", "no markdown"},
		{"", ""},
	} {
		if got := unmark(tt.in); got != tt.want {
			t.Errorf("unmark(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
