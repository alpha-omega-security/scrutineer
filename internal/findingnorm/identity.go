package findingnorm

import (
	"strings"
	"unicode/utf8"
)

// The identity fields are short labels compared across findings, not prose.
// The schemas cap them. These caps hold for a report that failed validation
// and for imported findings.
const (
	MaxRuleRunes     = 64
	MaxAnchorRunes   = 200
	MaxInstanceRunes = 120
)

// Rule turns a reported rule into a slug matching the schema pattern
// ^[a-z0-9][a-z0-9._-]*$. It lowercases the value and joins the runs of
// letters, digits, dots and underscores with single hyphens, so
// "SQL Injection!" and "sql-injection" land on the same slug. An already
// valid slug without repeated hyphens comes back unchanged.
func Rule(s string) string {
	var b strings.Builder
	pendingSep := false
	for _, r := range strings.ToLower(s) {
		if !slugRune(r) {
			pendingSep = true
			continue
		}
		if pendingSep && b.Len() > 0 {
			b.WriteByte('-')
		}
		pendingSep = false
		b.WriteRune(r)
	}
	slug := strings.TrimLeft(b.String(), "._-")
	if len(slug) > MaxRuleRunes {
		slug = strings.TrimRight(slug[:MaxRuleRunes], "-")
	}
	return slug
}

func slugRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_'
}

// Anchor collapses whitespace in a reported anchor and caps its length.
func Anchor(s string) string { return identityText(s, MaxAnchorRunes) }

// Instance collapses whitespace in a reported instance and caps its length.
func Instance(s string) string { return identityText(s, MaxInstanceRunes) }

// identityText collapses runs of whitespace (including newlines) to single
// spaces and cuts the result to limit runes.
func identityText(s string, limit int) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:limit]))
}
