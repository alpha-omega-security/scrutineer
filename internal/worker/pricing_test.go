package worker

import (
	"math"
	"testing"
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

func TestCostFromUsage_daybreakBlueUsesGPT56SolPricing(t *testing.T) {
	usage := Usage{
		InputTokens:      1_000_000,
		OutputTokens:     1_000_000,
		CacheReadTokens:  100_000,
		CacheWriteTokens: 200_000,
	}
	want := CostFromUsage(modelGPT56SolID, usage)
	if got := CostFromUsage(modelDaybreakBlueID, usage); math.Abs(got-want) > 1e-9 {
		t.Errorf("CostFromUsage(%q) = %v, want %v", modelDaybreakBlueID, got, want)
	}
}
