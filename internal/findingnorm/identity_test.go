package findingnorm

import (
	"regexp"
	"strings"
	"testing"
)

var rulePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

func TestRule(t *testing.T) {
	for in, want := range map[string]string{
		"sql-injection":             "sql-injection",
		"SQL-Injection":             "sql-injection",
		"sql injection":             "sql-injection",
		" SQL Injection! ":          "sql-injection",
		"  Missing \t Authz\nCheck": "missing-authz-check",
		"path -- traversal":         "path-traversal",
		"integer.overflow_alloc":    "integer.overflow_alloc",
		"._-heap overflow":          "heap-overflow",
		"café/redirect":             "caf-redirect",
		"   ":                       "",
		"!!!":                       "",
	} {
		got := Rule(in)
		if got != want {
			t.Errorf("Rule(%q) = %q, want %q", in, got, want)
		}
		if got != "" && !rulePattern.MatchString(got) {
			t.Errorf("Rule(%q) = %q does not match the schema pattern", in, got)
		}
	}
	long := Rule(strings.Repeat("ab ", MaxRuleRunes))
	if len(long) > MaxRuleRunes || !rulePattern.MatchString(long) || strings.HasSuffix(long, "-") {
		t.Fatalf("capped slug = %q", long)
	}
}

func TestAnchorAndInstance(t *testing.T) {
	if got := Anchor("  a \t b\n c "); got != "a b c" {
		t.Fatalf("Anchor collapsed = %q", got)
	}
	if got := Anchor(strings.Repeat("é", MaxAnchorRunes+10)); len([]rune(got)) != MaxAnchorRunes {
		t.Fatalf("Anchor capped length = %d runes", len([]rune(got)))
	}
	if got := Instance(strings.Repeat("x", MaxInstanceRunes+5)); len(got) != MaxInstanceRunes {
		t.Fatalf("Instance capped length = %d", len(got))
	}
	if got := Instance("   "); got != "" {
		t.Fatalf("blank = %q", got)
	}
}
