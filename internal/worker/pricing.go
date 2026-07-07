package worker

import "strings"

// modelPrice is the USD list price per 1M tokens for one model. In is
// the uncached-input rate, Out the output rate, CachedIn the discounted
// cache-read rate.
type modelPrice struct {
	In, Out, CachedIn float64
}

// modelPricing maps model ids to their per-1M-token USD list prices. It
// backs costFromUsage, which the event loop consults when a harness's
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
	"claude-opus-4-6":   {In: 5.00, Out: 25.00, CachedIn: 0.50},
	"claude-opus-4-7":   {In: 5.00, Out: 25.00, CachedIn: 0.50},
	"claude-opus-4-8":   {In: 5.00, Out: 25.00, CachedIn: 0.50},
	"claude-sonnet-4-6": {In: 3.00, Out: 15.00, CachedIn: 0.30},
	// Sonnet 5 is not on any published price sheet as of 2026-07;
	// priced at Sonnet 4.6's rate. Claude reports cost in-stream so
	// this row is only reached by the coverage tripwire, not billing.
	"claude-sonnet-5": {In: 3.00, Out: 15.00, CachedIn: 0.30},
	"claude-fable-5":  {In: 10.00, Out: 50.00, CachedIn: 1.00},

	// OpenAI (codex catalog at the pinned Dockerfile.runner version)
	"gpt-5.5":       {In: 5.00, Out: 30.00, CachedIn: 0.50},
	"gpt-5.4":       {In: 2.50, Out: 15.00, CachedIn: 0.25},
	"gpt-5.4-mini":  {In: 0.75, Out: 4.50, CachedIn: 0.075},
	"gpt-5.3-codex": {In: 1.75, Out: 14.00, CachedIn: 0.175},
	"gpt-5.2":       {In: 1.75, Out: 14.00, CachedIn: 0.175},
}

const perMillion = 1e6

// costFromUsage computes the dollar cost of one result event's token
// usage against the given model's list price. Called by the event loop
// only when the harness's stream event reported Usage but no CostUSD
// (codex); claude reports CostUSD directly so this is never reached
// for it. Returns 0 for an unpriced model so an unknown id degrades to
// "cost not shown" rather than a wrong number.
//
// The arithmetic assumes OpenAI usage semantics: InputTokens is the
// total prompt token count and CacheReadTokens is the cached subset of
// it, so uncached = InputTokens - CacheReadTokens. That is what codex's
// turn.completed usage reports. CacheWriteTokens is not billed
// separately by OpenAI and codex does not report it, so it is ignored.
func costFromUsage(model string, u Usage) float64 {
	p, ok := modelPricing[normalizeModelID(model)]
	if !ok {
		return 0
	}
	uncached := u.InputTokens - u.CacheReadTokens
	if uncached < 0 {
		uncached = 0
	}
	return (float64(uncached)*p.In +
		float64(u.CacheReadTokens)*p.CachedIn +
		float64(u.OutputTokens)*p.Out) / perMillion
}

// normalizeModelID strips a trailing [...] variant suffix (e.g.
// "claude-fable-5[1m]" -> "claude-fable-5") so pricing keys stay on the
// base model id regardless of context-window or routing variants.
func normalizeModelID(id string) string {
	if i := strings.IndexByte(id, '['); i > 0 {
		return id[:i]
	}
	return id
}
