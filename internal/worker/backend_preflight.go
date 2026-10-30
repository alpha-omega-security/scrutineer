package worker

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

const backendProbeTimeout = 2 * time.Minute
const backendPreflightCacheLimit = 256

// BackendPreflightCache is process-local. A restart intentionally re-probes;
// persisted receipts are provenance, not authority to trust an old credential.
type BackendPreflightCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	salt    [32]byte
	entries map[string]*backendProbeEntry
	now     func() time.Time
}

type backendProbeEntry struct {
	done   chan struct{}
	result coverage.BackendProbe
	err    error
}

func (e *backendProbeEntry) readyAt(now time.Time) bool {
	return e.err == nil && e.result.Status == coverage.PreflightReady && now.Before(e.result.ExpiresAt)
}

func NewBackendPreflightCache(ttl time.Duration) (*BackendPreflightCache, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("backend preflight TTL must be positive")
	}
	c := &BackendPreflightCache{ttl: ttl, entries: make(map[string]*backendProbeEntry), now: time.Now}
	if _, err := rand.Read(c.salt[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// Inputs can contain credentials. Only a process-keyed digest is retained.
func (c *BackendPreflightCache) key(config []byte) string {
	h := hmac.New(sha256.New, c.salt[:])
	_, _ = h.Write(config)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *BackendPreflightCache) check(ctx context.Context, config []byte, run func(context.Context) coverage.BackendProbe) (coverage.BackendProbe, error) {
	key := c.key(config)
	for {
		if err := ctx.Err(); err != nil {
			return coverage.BackendProbe{}, err
		}
		c.mu.Lock()
		entry, ok := c.entries[key]
		if ok {
			select {
			case <-entry.done:
				if entry.readyAt(c.now()) {
					result := entry.result
					result.Reused = true
					c.mu.Unlock()
					return result, nil
				}
				delete(c.entries, key)
			default:
				c.mu.Unlock()
				select {
				case <-ctx.Done():
					return coverage.BackendProbe{}, ctx.Err()
				case <-entry.done:
					if entry.err != nil || (entry.result.Status == coverage.PreflightReady && !c.now().Before(entry.result.ExpiresAt)) {
						continue
					}
					// Existing waiters share even a failed probe, but later scans
					// must not inherit a transient failure from the cache.
					result := entry.result
					result.Reused = true
					return result, nil
				}
			}
		}
		c.prune()
		entry = &backendProbeEntry{done: make(chan struct{})}
		c.entries[key] = entry
		c.mu.Unlock()
		probeCtx, cancel := context.WithTimeout(ctx, backendProbeTimeout)
		result := run(probeCtx)
		if probeCtx.Err() != nil {
			result.Status, result.Error = coverage.PreflightBlocked, "backend probe canceled or timed out"
		}
		cancel()
		result.ProbeID = randomProbeID()
		result.ConfigHash = key
		result.CheckedAt = c.now().UTC()
		result.ExpiresAt = result.CheckedAt
		if result.Status == coverage.PreflightReady {
			result.ExpiresAt = result.CheckedAt.Add(c.ttl)
		}
		c.mu.Lock()
		entry.result = result
		entry.err = ctx.Err()
		if entry.err != nil || result.Status != coverage.PreflightReady {
			delete(c.entries, key)
		}
		close(entry.done)
		c.mu.Unlock()
		return result, entry.err
	}
}

// Called under mu. Never evict in-flight probes: that would defeat deduplication.
func (c *BackendPreflightCache) prune() {
	var oldest string
	var expiry time.Time
	for key, entry := range c.entries {
		select {
		case <-entry.done:
			if !c.now().Before(entry.result.ExpiresAt) {
				delete(c.entries, key)
				continue
			}
			if oldest == "" || entry.result.ExpiresAt.Before(expiry) {
				oldest, expiry = key, entry.result.ExpiresAt
			}
		default:
		}
	}
	if len(c.entries) >= backendPreflightCacheLimit && oldest != "" {
		delete(c.entries, oldest)
	}
}

func randomProbeID() string {
	var id [16]byte
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

func (w *Worker) configureBackendPreflight(ctx context.Context, scan *db.Scan, sj *SkillJob, document skillContext) {
	if w.BackendPreflight == nil {
		return
	}
	sj.checkBackend = func(runCtx context.Context, config []byte, run func(context.Context) coverage.BackendProbe) error {
		result, err := w.BackendPreflight.check(runCtx, config, run)
		if err != nil {
			return err
		}
		preflight, err := w.recordBackendPreflight(ctx, scan, result)
		if err != nil {
			return err
		}
		document.Scrutineer.Preflight = preflight
		if err := writeSkillContext(sj.WorkRoot, sj.SkillDir, document); err != nil {
			return err
		}
		if result.Status != coverage.PreflightReady {
			if result.RateLimited {
				return &AccountError{Detail: "backend preflight rate limit rejected the request", ResetAt: result.RateLimitResetAt}
			}
			return fmt.Errorf("backend preflight blocked: %s", result.Error)
		}
		return nil
	}
}

func (w *Worker) recordBackendPreflight(ctx context.Context, scan *db.Scan, result coverage.BackendProbe) (*coverage.Preflight, error) {
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok && scan.Coverage != "" {
		return nil, fmt.Errorf("stored coverage did not decode")
	}
	if result.CostUSD == 0 {
		result.CostUSD = CostFromUsage(scan.Model, Usage{InputTokens: result.InputTokens, OutputTokens: result.OutputTokens, CacheReadTokens: result.CacheReadTokens, CacheWriteTokens: result.CacheWriteTokens})
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	receipt := db.ScanPreflightReceipt{ScanID: scan.ID, ProbeID: result.ProbeID, RecipeSHA256: textDigest(scan.Recipe), Report: string(raw)}
	updated := *scan
	if err := db.TimedTransaction(w.DB.WithContext(ctx), w.scanTransactionLog(scan, "record_backend_preflight"), func(tx *gorm.DB) error {
		insert := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "scan_id"}, {Name: "probe_id"}}, DoNothing: true}).Create(&receipt)
		if insert.Error != nil {
			return insert.Error
		}
		if err := tx.Where("scan_id = ? AND probe_id = ?", scan.ID, result.ProbeID).First(&receipt).Error; err != nil {
			return err
		}
		result.ReceiptID = receipt.ID
		if rec.Preflight == nil {
			rec.Preflight = &coverage.Preflight{Status: coverage.PreflightReady, Missing: []string{}}
		}
		rec.Preflight.Backend = &result
		if rec.Completeness == "" {
			rec.Completeness = coverage.CompletenessUnknown
		}
		setCoverage(&updated, rec)
		updates := map[string]any{"coverage": updated.Coverage, "completeness": updated.Completeness}
		if !result.Reused && insert.RowsAffected == 1 {
			addBackendProbeUsage(&updated, result, updates)
		}
		update := tx.Model(&db.Scan{}).Where("id = ?", scan.ID).Updates(updates)
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return fmt.Errorf("scan no longer exists")
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("record backend preflight: %w", err)
	}
	scan.Coverage, scan.Completeness = updated.Coverage, updated.Completeness
	scan.CostUSD, scan.InputTokens, scan.OutputTokens = updated.CostUSD, updated.InputTokens, updated.OutputTokens
	scan.CacheReadTokens, scan.CacheWriteTokens = updated.CacheReadTokens, updated.CacheWriteTokens
	return rec.Preflight, nil
}

// Usage is charged once, in the same transaction that inserts the receipt.
func addBackendProbeUsage(scan *db.Scan, result coverage.BackendProbe, updates map[string]any) {
	updates["cost_usd"] = gorm.Expr("cost_usd + ?", result.CostUSD)
	updates["input_tokens"] = gorm.Expr("input_tokens + ?", result.InputTokens)
	updates["output_tokens"] = gorm.Expr("output_tokens + ?", result.OutputTokens)
	updates["cache_read_tokens"] = gorm.Expr("cache_read_tokens + ?", result.CacheReadTokens)
	updates["cache_write_tokens"] = gorm.Expr("cache_write_tokens + ?", result.CacheWriteTokens)
	scan.CostUSD += result.CostUSD
	scan.InputTokens += result.InputTokens
	scan.OutputTokens += result.OutputTokens
	scan.CacheReadTokens += result.CacheReadTokens
	scan.CacheWriteTokens += result.CacheWriteTokens
}
