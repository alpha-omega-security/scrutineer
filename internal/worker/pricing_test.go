package worker

import (
	"math"
	"testing"
)

// TestPricingCoversEveryDefaultModel is the staleness tripwire: every
// model any registered harness offers by default must have a price
// entry, so a new harness (or a new model added to an existing one)
// fails here until pricing.go is updated. That keeps costFromUsage from
// silently returning $0 for a model in the pick list.
func TestPricingCoversEveryDefaultModel(t *testing.T) {
	for name, h := range harnesses {
		if name == "" {
			continue
		}
		for _, m := range h.DefaultModels() {
			if _, ok := modelPricing[normalizeModelID(m.ID)]; !ok {
				t.Errorf("%s: DefaultModels() entry %q has no modelPricing row", name, m.ID)
			}
		}
	}
}

func TestCostFromUsage(t *testing.T) {
	// gpt-5.4: $2.50 in / $15 out / $0.25 cached, per 1M.
	// 1M uncached in + 1M cached in + 1M out = 2.50 + 0.25 + 15.00.
	got := costFromUsage("gpt-5.4", Usage{
		InputTokens:     2_000_000, // total, of which 1M cached
		CacheReadTokens: 1_000_000,
		OutputTokens:    1_000_000,
	})
	if want := 17.75; math.Abs(got-want) > 1e-9 {
		t.Errorf("costFromUsage = %.4f, want %.4f", got, want)
	}
}

func TestCostFromUsage_unknownModelIsZero(t *testing.T) {
	if got := costFromUsage("no-such-model", Usage{InputTokens: 1_000_000, OutputTokens: 1_000_000}); got != 0 {
		t.Errorf("unknown model cost = %.4f, want 0", got)
	}
}

func TestCostFromUsage_zeroUsageIsZero(t *testing.T) {
	// A result event with no token usage (e.g. a claude run where the
	// stream reported CostUSD elsewhere) must not synthesize a nonzero
	// cost.
	if got := costFromUsage("gpt-5.4", Usage{}); got != 0 {
		t.Errorf("zero-usage cost = %.4f, want 0", got)
	}
}

func TestNormalizeModelID_stripsBracketSuffix(t *testing.T) {
	for in, want := range map[string]string{
		"claude-fable-5[1m]": "claude-fable-5",
		"claude-opus-4-8":    "claude-opus-4-8",
		"":                   "",
	} {
		if got := normalizeModelID(in); got != want {
			t.Errorf("normalizeModelID(%q) = %q, want %q", in, got, want)
		}
	}
}
