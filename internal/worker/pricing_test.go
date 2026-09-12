package worker

import (
	"math"
	"testing"

	"github.com/alpha-omega-security/harness"
)

func TestCostFromUsage_gpt6Astra(t *testing.T) {
	usage := Usage{
		InputTokens:      1_000_000,
		OutputTokens:     1_000_000,
		CacheReadTokens:  100_000,
		CacheWriteTokens: 200_000,
	}
	const want = 59.60
	for _, model := range []string{modelGPT6AstraID, "openai/gpt-6-astra[1m]"} {
		if got := CostFromUsage(model, usage); math.Abs(got-want) > 1e-9 {
			t.Errorf("CostFromUsage(%q) = %v, want %v", model, got, want)
		}
	}
}

func TestCostFromUsage_gpt56SolAndDaybreakBasePricing(t *testing.T) {
	tests := []struct {
		name  string
		usage Usage
		want  float64
	}{
		{"uncached input", Usage{InputTokens: 100_000}, 0.40},
		{"output", Usage{OutputTokens: 10_000}, 0.20},
		{"cache reads", Usage{InputTokens: 100_000, CacheReadTokens: 100_000}, 0.04},
		{"cache writes", Usage{InputTokens: 100_000, CacheWriteTokens: 100_000}, 0.50},
		{"standard scan", Usage{InputTokens: 100_000, OutputTokens: 10_000}, 0.60},
		{"mixed", Usage{InputTokens: 100_000, OutputTokens: 10_000, CacheReadTokens: 10_000, CacheWriteTokens: 20_000}, 0.584},
	}
	for _, model := range []struct{ name, id string }{
		{"sol", modelGPT56SolID},
		{"sol_normalized", "openai/gpt-5.6-sol[1m]"},
		{"daybreak", modelDaybreakBlueID},
		{"daybreak_normalized", "openai/gpt-daybreak-blue-latest[1m]"},
	} {
		t.Run(model.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					if got := CostFromUsage(model.id, tt.usage); math.Abs(got-tt.want) > 1e-9 {
						t.Errorf("CostFromUsage(%q, %+v) = %v, want %v", model.id, tt.usage, got, tt.want)
					}
				})
			}
		})
	}
}

func TestCostFromUsage_solOverrideStillNeeded(t *testing.T) {
	for _, usage := range []Usage{
		{InputTokens: 100_000},
		{OutputTokens: 10_000},
		{InputTokens: 100_000, CacheReadTokens: 100_000},
		{InputTokens: 100_000, CacheWriteTokens: 100_000},
	} {
		upstream := harness.CostFromUsage(modelGPT56SolID, usage)
		if math.Abs(upstream-CostFromUsage(modelGPT56SolID, usage)) > 1e-9 {
			return
		}
	}
	t.Fatal("Harness now has the current Sol base rates; remove the local Sol rate override, delegate Daybreak to Harness's Sol pricing, and delete this test")
}

func TestCostFromUsage_delegatesOtherModels(t *testing.T) {
	usage := Usage{InputTokens: 100_000, OutputTokens: 10_000, CacheReadTokens: 10_000, CacheWriteTokens: 20_000}
	if got := CostFromUsage("unknown", usage); got != 0 {
		t.Errorf("unknown model cost = %v, want 0", got)
	}
	const model = "anthropic/claude-sonnet-4-6[1m]"
	if got, want := CostFromUsage(model, usage), harness.CostFromUsage(model, usage); got != want {
		t.Errorf("CostFromUsage(%q) = %v, want Harness cost %v", model, got, want)
	}
}
