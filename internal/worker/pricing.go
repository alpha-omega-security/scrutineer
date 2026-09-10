package worker

import (
	"strings"

	"github.com/alpha-omega-security/harness"
)

const (
	modelDaybreakBlueID = "gpt-daybreak-blue-latest"
	modelGPT56SolID     = "gpt-5.6-sol"
	modelGPT6AstraID    = "gpt-6-astra"
	perMillionTokens    = 1e6

	// GPT-6 Astra base list prices in USD per million tokens. The aggregate
	// Usage event cannot identify requests that crossed the long-context
	// threshold, so this deliberately remains a base-rate estimate.
	gpt6AstraInputPrice       = 10.00
	gpt6AstraOutputPrice      = 50.00
	gpt6AstraCachedInputPrice = 1.00
	gpt6AstraCacheWritePrice  = 12.50
)

// CostFromUsage computes the dollar cost of one result event's token usage
// against the given model's list price. Harness owns the shared pricing table;
// local handling bridges newer Codex models and aliases until the module ships
// matching defaults and pricing.
func CostFromUsage(model string, u Usage) float64 {
	switch normalizePricingModelID(model) {
	case modelDaybreakBlueID:
		// OpenAI documents Daybreak Blue as an approval-gated alias for
		// GPT-5.6 Sol; keep their local rates identical.
		// https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest
		return harness.CostFromUsage(modelGPT56SolID, u)
	case modelGPT6AstraID:
		// Handled by the local Astra row below.
	default:
		return harness.CostFromUsage(model, u)
	}

	uncached := u.InputTokens - u.CacheReadTokens - u.CacheWriteTokens
	if uncached < 0 {
		uncached = 0
	}
	return (float64(uncached)*gpt6AstraInputPrice +
		float64(u.CacheReadTokens)*gpt6AstraCachedInputPrice +
		float64(u.CacheWriteTokens)*gpt6AstraCacheWritePrice +
		float64(u.OutputTokens)*gpt6AstraOutputPrice) / perMillionTokens
}

func normalizePricingModelID(id string) string {
	if slash := strings.LastIndexByte(id, '/'); slash >= 0 {
		id = id[slash+1:]
	}
	if bracket := strings.IndexByte(id, '['); bracket > 0 {
		id = id[:bracket]
	}
	return id
}
