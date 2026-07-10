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
// workspace. Usage is persisted even when the provider returned JSON that
// failed schema validation, because the request was still billable.
func (w *Worker) CallAuxiliary(ctx context.Context, scan *db.Scan, prompt string, schema json.RawMessage, opts llm.Options) (json.RawMessage, error) {
	if w == nil || w.DB == nil {
		return nil, fmt.Errorf("auxiliary model call requires a worker database")
	}
	if scan == nil || scan.ID == 0 {
		return nil, fmt.Errorf("auxiliary model call requires a persisted scan")
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
	workerUsage := Usage{
		InputTokens:      usage.InputTokens,
		OutputTokens:     usage.OutputTokens,
		CacheReadTokens:  usage.CacheReadTokens,
		CacheWriteTokens: usage.CacheWriteTokens,
	}
	cost := CostFromUsage(model, workerUsage)
	updates := map[string]any{
		"cost_usd":           gorm.Expr("cost_usd + ?", cost),
		"input_tokens":       gorm.Expr("input_tokens + ?", workerUsage.InputTokens),
		"output_tokens":      gorm.Expr("output_tokens + ?", workerUsage.OutputTokens),
		"cache_read_tokens":  gorm.Expr("cache_read_tokens + ?", workerUsage.CacheReadTokens),
		"cache_write_tokens": gorm.Expr("cache_write_tokens + ?", workerUsage.CacheWriteTokens),
	}
	result := gdb.Model(&db.Scan{}).Where("id = ?", scan.ID).Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("scan %d no longer exists", scan.ID)
	}
	scan.CostUSD += cost
	scan.InputTokens += workerUsage.InputTokens
	scan.OutputTokens += workerUsage.OutputTokens
	scan.CacheReadTokens += workerUsage.CacheReadTokens
	scan.CacheWriteTokens += workerUsage.CacheWriteTokens
	return nil
}
