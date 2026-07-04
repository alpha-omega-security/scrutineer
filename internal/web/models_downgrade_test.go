package web

import "testing"

func TestIsDowngradableTier(t *testing.T) {
	// The expensive tiers and the empty default (which resolves to high) are
	// rewritten to mid during overage.
	for _, p := range []string{"", ModelTierHigh, ModelTierMax} {
		if !isDowngradableTier(p) {
			t.Errorf("isDowngradableTier(%q) = false, want true", p)
		}
	}
	// A concrete model id or the mid tier is left alone, so an explicit choice
	// (or an already-cheap tier) is never touched.
	for _, p := range []string{ModelTierMid, "claude-opus-4-8", "claude-sonnet-4-6", "garbage"} {
		if isDowngradableTier(p) {
			t.Errorf("isDowngradableTier(%q) = true, want false", p)
		}
	}
}

func TestApplyOverageDowngrade(t *testing.T) {
	cases := []struct {
		pref   string
		active bool
		want   string
	}{
		// active + expensive tier (or empty default) -> mid
		{"", true, ModelTierMid},
		{ModelTierHigh, true, ModelTierMid},
		{ModelTierMax, true, ModelTierMid},
		// active but mid or a concrete id -> left alone (explicit choice honoured)
		{ModelTierMid, true, ModelTierMid},
		{"claude-opus-4-8", true, "claude-opus-4-8"},
		{"claude-sonnet-4-6", true, "claude-sonnet-4-6"},
		// inactive -> everything unchanged
		{"", false, ""},
		{ModelTierMax, false, ModelTierMax},
		{"claude-opus-4-8", false, "claude-opus-4-8"},
	}
	for _, tc := range cases {
		if got := applyOverageDowngrade(tc.pref, tc.active); got != tc.want {
			t.Errorf("applyOverageDowngrade(%q, %v) = %q, want %q", tc.pref, tc.active, got, tc.want)
		}
	}
}
