package worker

import "strings"

// modelPrice is the USD list price per 1M tokens for one model. In is
// the uncached-input rate, Out the output rate, CachedIn the discounted
// cache-read rate, and CacheWrite the cache-creation rate.
type modelPrice struct {
	In, Out, CachedIn, CacheWrite float64
}

// modelPricing maps model ids to their per-1M-token USD list prices. It
// backs CostFromUsage, which the event loop consults when a harness's
// stream reports token usage but no dollar figure (codex). Claude
// reports total_cost_usd in-stream so its entries here are not used to
// compute cost; they exist so the coverage tripwire in pricing_test.go
// can assert every DefaultModels() id is priced without special-casing
// which harness reports cost.
//
// Prices are list rates as of 2026-07 (Anthropic: platform.claude.com;
// OpenAI: developers.openai.com/api/docs/pricing). Update alongside
// each harness's DefaultModels().
//
//nolint:mnd // a pricing table is a table of numbers; naming each rate would obscure it
var modelPricing = map[string]modelPrice{
	// Anthropic
	"claude-opus-4-6":   {In: 5.00, Out: 25.00, CachedIn: 0.50, CacheWrite: 6.25},
	"claude-opus-4-7":   {In: 5.00, Out: 25.00, CachedIn: 0.50, CacheWrite: 6.25},
	"claude-opus-4-8":   {In: 5.00, Out: 25.00, CachedIn: 0.50, CacheWrite: 6.25},
	"claude-sonnet-4-6": {In: 3.00, Out: 15.00, CachedIn: 0.30, CacheWrite: 3.75},
	"claude-haiku-4-5":  {In: 1.00, Out: 5.00, CachedIn: 0.10, CacheWrite: 1.25},
	// Sonnet 5 is not on any published price sheet as of 2026-07;
	// priced at Sonnet 4.6's rate. Claude reports cost in-stream so
	// this row is only reached by the coverage tripwire, not billing.
	"claude-sonnet-5": {In: 3.00, Out: 15.00, CachedIn: 0.30, CacheWrite: 3.75},
	"claude-fable-5":  {In: 10.00, Out: 50.00, CachedIn: 1.00, CacheWrite: 12.50},

	// OpenAI (codex catalog at the pinned Dockerfile.runner version)
	"gpt-5.5":       {In: 5.00, Out: 30.00, CachedIn: 0.50},
	"gpt-5.4":       {In: 2.50, Out: 15.00, CachedIn: 0.25},
	"gpt-5.4-mini":  {In: 0.75, Out: 4.50, CachedIn: 0.075},
	"gpt-5.3-codex": {In: 1.75, Out: 14.00, CachedIn: 0.175},
	"gpt-5.2":       {In: 1.75, Out: 14.00, CachedIn: 0.175},
}

const perMillion = 1e6

// CostFromUsage computes the dollar cost of one result event's token usage
// against the given model's list price. Called by the event loop
// only when the harness's stream event reported Usage but no CostUSD
// (codex); claude reports CostUSD directly so this is never reached
// for it. Returns 0 for an unpriced model so an unknown id degrades to
// "cost not shown" rather than a wrong number.
//
// InputTokens is the total prompt token count. CacheReadTokens is a discounted
// subset. CacheWriteTokens is a separate subset only for models with a
// dedicated cache-write rate; on OpenAI rows where CacheWrite is zero, it
// remains ordinary input. The auxiliary Anthropic path normalizes its separate
// input counters into this shared representation.
func CostFromUsage(model string, u Usage) float64 {
	p, ok := modelPricing[normalizeModelID(model)]
	if !ok {
		return 0
	}
	uncached := u.InputTokens - u.CacheReadTokens
	if p.CacheWrite > 0 {
		uncached -= u.CacheWriteTokens
	}
	if uncached < 0 {
		uncached = 0
	}
	return (float64(uncached)*p.In +
		float64(u.CacheReadTokens)*p.CachedIn +
		float64(u.CacheWriteTokens)*p.CacheWrite +
		float64(u.OutputTokens)*p.Out) / perMillion
}

// normalizeModelID strips a leading provider/ prefix (opencode's
// "anthropic/claude-opus-4-8" form) and a trailing [...] variant suffix
// ("claude-fable-5[1m]" -> "claude-fable-5") so pricing keys stay on the
// base model id regardless of harness or context-window variant.
func normalizeModelID(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		id = id[i+1:]
	}
	if i := strings.IndexByte(id, '['); i > 0 {
		return id[:i]
	}
	return id
}
