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

	// Standard base list prices in USD per million tokens. The aggregate
	// Usage event cannot identify requests that crossed the long-context
	// threshold, so this deliberately remains a base-rate estimate.
	// https://developers.openai.com/api/docs/pricing
	// Sol's promotional rates apply at least through 2026-11-21; recheck then.
	gpt56SolInputPrice       = 4.00
	gpt56SolOutputPrice      = 20.00
	gpt56SolCachedInputPrice = 0.40
	gpt56SolCacheWritePrice  = 5.00

	gpt6AstraInputPrice       = 10.00
	gpt6AstraOutputPrice      = 50.00
	gpt6AstraCachedInputPrice = 1.00
	gpt6AstraCacheWritePrice  = 12.50
)

// CostFromUsage computes the dollar cost of one result event's token usage
// against the given model's list price. Harness owns the shared pricing table;
// local handling bridges newer Codex models, aliases, and corrected rates until
// the module ships matching defaults and pricing.
func CostFromUsage(model string, u Usage) float64 {
	var inputPrice, outputPrice, cachedInputPrice, cacheWritePrice float64
	switch normalizePricingModelID(model) {
	case modelGPT56SolID, modelDaybreakBlueID:
		// OpenAI documents Daybreak Blue as an approval-gated alias for
		// GPT-5.6 Sol; keep their local rates identical.
		// https://developers.openai.com/api/docs/models/gpt-daybreak-blue-latest
		inputPrice, outputPrice = gpt56SolInputPrice, gpt56SolOutputPrice
		cachedInputPrice, cacheWritePrice = gpt56SolCachedInputPrice, gpt56SolCacheWritePrice
	case modelGPT6AstraID:
		inputPrice, outputPrice = gpt6AstraInputPrice, gpt6AstraOutputPrice
		cachedInputPrice, cacheWritePrice = gpt6AstraCachedInputPrice, gpt6AstraCacheWritePrice
	default:
		return harness.CostFromUsage(model, u)
	}

	uncached := u.InputTokens - u.CacheReadTokens - u.CacheWriteTokens
	if uncached < 0 {
		uncached = 0
	}
	return (float64(uncached)*inputPrice +
		float64(u.CacheReadTokens)*cachedInputPrice +
		float64(u.CacheWriteTokens)*cacheWritePrice +
		float64(u.OutputTokens)*outputPrice) / perMillionTokens
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
