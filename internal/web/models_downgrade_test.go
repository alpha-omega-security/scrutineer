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
