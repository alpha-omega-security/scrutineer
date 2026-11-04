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
