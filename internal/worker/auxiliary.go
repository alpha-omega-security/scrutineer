package worker

import (
	"context"
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/llm"
)

// CallAuxiliary performs a direct structured model call and records its usage
// on scan. It is for small worker-side decisions that do not need an agent
// workspace. Usage is persisted when the provider returns a decodable response,
// even when its structured text is malformed, because the request was still
// billable.
func (w *Worker) CallAuxiliary(ctx context.Context, scan *db.Scan, prompt string, schema json.RawMessage, opts llm.Options) (json.RawMessage, error) {
	if w == nil || w.DB == nil {
		return nil, fmt.Errorf("auxiliary model call requires a worker database")
	}
	if scan == nil || scan.ID == 0 {
		return nil, fmt.Errorf("auxiliary model call requires a persisted scan")
	}
	if opts.Model == "" {
		opts.Model = scan.Model
	}
	if scan.Model != "" && opts.Model != scan.Model {
		return nil, fmt.Errorf("auxiliary model %q does not match scan model %q", opts.Model, scan.Model)
	}
	result, usage, callErr := llm.Call(ctx, prompt, schema, opts)
	if err := recordAuxiliaryUsage(w.DB, scan, opts.Model, usage); err != nil {
		if callErr != nil {
			return nil, fmt.Errorf("%w; record auxiliary usage: %v", callErr, err)
		}
		return nil, fmt.Errorf("record auxiliary usage: %w", err)
	}
	return result, callErr
}

func recordAuxiliaryUsage(gdb *gorm.DB, scan *db.Scan, model string, usage llm.Usage) error {
	if usage == (llm.Usage{}) {
		return nil
	}
	storedUsage := Usage{
		// Anthropic's input_tokens is fresh input. Scan stores that separately
		// from cache categories so TotalInputTokens can add each exactly once.
		InputTokens:      usage.InputTokens,
		OutputTokens:     usage.OutputTokens,
		CacheReadTokens:  usage.CacheReadTokens,
		CacheWriteTokens: usage.CacheWriteTokens,
	}
	pricingUsage := storedUsage
	// CostFromUsage takes the harness representation, where input_tokens is
	// the total prompt size and cache categories are subsets of that total.
	pricingUsage.InputTokens += pricingUsage.CacheReadTokens + pricingUsage.CacheWriteTokens
	cost := CostFromUsage(model, pricingUsage)
	updates := map[string]any{
		"cost_usd":           gorm.Expr("cost_usd + ?", cost),
		"input_tokens":       gorm.Expr("input_tokens + ?", storedUsage.InputTokens),
		"output_tokens":      gorm.Expr("output_tokens + ?", storedUsage.OutputTokens),
		"cache_read_tokens":  gorm.Expr("cache_read_tokens + ?", storedUsage.CacheReadTokens),
		"cache_write_tokens": gorm.Expr("cache_write_tokens + ?", storedUsage.CacheWriteTokens),
	}
	result := gdb.Model(&db.Scan{}).Where("id = ?", scan.ID).Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("scan %d no longer exists", scan.ID)
	}
	scan.CostUSD += cost
	scan.InputTokens += storedUsage.InputTokens
	scan.OutputTokens += storedUsage.OutputTokens
	scan.CacheReadTokens += storedUsage.CacheReadTokens
	scan.CacheWriteTokens += storedUsage.CacheWriteTokens
	return nil
}
