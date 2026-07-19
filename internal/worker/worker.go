// Package worker holds the queue handler that runs skill scans. Jobs are
// dispatched by name through goqite; every scan is a skill-driven scan.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

const (
	JobSkill    = "skill"
	JobExposure = "exposure"

	PrioScan     = 0
	PrioFinding  = 2
	PrioTool     = 5
	PrioFastTool = 8
	PrioMetadata = 10
)

// DefaultScanTimeout is the wall-clock limit applied to each scan when no
// override is configured. Model-backed audits on large repos rarely need
// more than this; a scan that does is almost always wedged.
const DefaultScanTimeout = time.Hour

// Prereq gate defaults. A skill declaring scrutineer.requires has its
// dispatch deferred when any listed upstream scan is enqueued but not
// yet done; the queue message is re-published with the delay doubling
// from DefaultPrereqRetryDelay up to MaxPrereqRetryDelay, for up to
// DefaultMaxPrereqAttempts attempts. With the defaults that spans
// roughly 90 minutes of wall clock — enough for an hour-scale prereq
// scan to finish under runner contention — before the scan fails with
// a "prereqs not satisfied" error.
const (
	DefaultPrereqRetryDelay  = 30 * time.Second
	MaxPrereqRetryDelay      = 5 * time.Minute
	DefaultMaxPrereqAttempts = 20
)

// defaultLogFlushInterval bounds how long a scan's log can lag behind the
// in-memory accumulator. Each emitted event used to UPDATE the whole
// scans.log TEXT column, so a token-heavy scan fired thousands of full
// rewrites; batching to once every couple of seconds collapses that to a
// trickle. Real-time UI updates flow through publish() on every event and
// are independent of this cadence; wrap()'s closing Save flushes the
// final buffered tail regardless of how long ago the last write was.
const defaultLogFlushInterval = 2 * time.Second

type Worker struct {
	DB      *gorm.DB
	Log     *slog.Logger
	DataDir string // workspace root for clones
	APIBase string // base URL for the scrutineer skill API (http://host:port/api)
	ForkOrg string // github org the fork skill targets; empty disables it
	// MetadataDir is the directory in a staging repo where scrutineer
	// keeps per-project metadata. Empty means the worker substitutes
	// the default, `.scrutineer/`, when staging the skill context.
	MetadataDir string
	Runner      SkillRunner
	OnEvent     func(scanID, repoID uint, name, data string) // optional SSE bridge
	// OnFindingCreated, when non-nil, is called after a findings-emitting
	// scan persists a fresh Finding row. The web layer wires it up to
	// auto-enqueue a revalidate scan over High/Critical findings from
	// security-deep-dive. The worker has no queue access of its own;
	// this callback is the seam.
	OnFindingCreated func(scan *db.Scan, finding *db.Finding)
	// OnRevalidateVerdict, when non-nil, is called after parseRevalidateOutput
	// applies a verdict to a finding. The web layer wires it up to
	// auto-enqueue a verify scan when revalidate confirms a High/Critical
	// finding as a true positive, completing the triage pipeline for
	// imports and high-severity scan output. severity is the
	// post-adjustment severity: revalidate may have rated the finding
	// lower than the original claim, and the chain to verify uses the
	// revised value.
	OnRevalidateVerdict func(scan *db.Scan, finding *db.Finding, verdict, severity string)
	// OnScanFinalized, when non-nil, is called once after a scan finishes its
	// analysis with findings committed and the worker has no further writes
	// to make for the scan — that is, ScanDone or a fail_on-threshold
	// failure (which still persists findings). Named "finalized" rather than
	// "done" precisely because it also fires on that failure path. The web
	// layer wires it up to auto-enqueue a repository-scoped finding-dedup
	// pass after a security-deep-dive run adds new findings to a repo that
	// already holds other non-scanner findings. Firing post-commit means the
	// dedup run sees the full finding set, and the worker has no queue access
	// of its own so this callback is the seam.
	OnScanFinalized func(scan *db.Scan)
	ScanTimeout     time.Duration
	// AutoRejectMissedCount is the threshold of consecutive missed rescans at
	// which an open finding is automatically transitioned to 'rejected'.
	// 0 means disabled.
	AutoRejectMissedCount int

	// Queue is the queue this worker is registered on. Required for the
	// prereq gate to re-enqueue a scan whose upstream skills have not yet
	// completed. Register() sets it from its argument so callers do not
	// need to wire it twice.
	Queue *queue.Queue

	// PrereqRetryDelay and MaxPrereqAttempts override the prereq-gate
	// defaults. Tests set these to keep gate behaviour deterministic
	// without the production backoff. Zero falls through to the consts.
	PrereqRetryDelay  time.Duration
	MaxPrereqAttempts int
	// SchemaStrict makes a report.json that fails validation against the
	// skill's schema.json fail the scan. When false the validator output
	// is emitted to the log and the kind-specific parser still runs.
	SchemaStrict bool

	mu      sync.Mutex
	running map[uint]context.CancelFunc

	// cacheMu serialises clone/fetch on the per-URL repo and dependent
	// caches. One Mutex per URL keeps two scans from racing inside the
	// same physical dir while leaving scans of different URLs free to
	// run in parallel.
	cacheMu sync.Map

	// PrepareRepoSrc overrides the default per-URL repo-cache populate
	// step in doSkill. Tests set it to skip the network; production
	// leaves it nil and falls through to prepareRepoSrc.
	PrepareRepoSrc func(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error)

	// RefreshEcosystemsCache, when non-nil, runs the stale-only ecosyste.ms
	// cache refresh at scan start so rescans see fresh-enough data.
	// main wires it to RefreshEcosystems; tests leave it nil so scans stay
	// hermetic. Best-effort: errors are logged, never fail the scan.
	RefreshEcosystemsCache func(ctx context.Context, repoID uint) error

	// VIDCommand overrides the vid binary name for computeVID. Tests
	// point it at a stub; empty falls through to "vid" on PATH.
	VIDCommand string

	// vidMissingOnce gates the missing-binary warning so a deployment
	// without vid on PATH logs it once, not once per finding.
	vidMissingOnce sync.Once

	// LogFlushInterval overrides defaultLogFlushInterval. Tests set it to
	// a tiny or huge value to assert flush behaviour without sleeping.
	// Zero falls through to the const default.
	LogFlushInterval time.Duration

	// AutoResumeBuffer is added to the reset timestamp before the worker
	// resumes paused scans. Zero falls through to the default buffer.
	AutoResumeBuffer time.Duration
	// AutoResumeRetryDelay backs off retry attempts when a due auto-resume
	// cannot re-enqueue one or more scans. Zero falls through to the default.
	AutoResumeRetryDelay time.Duration
	// MaxRateLimitAutoResumeDelay bounds provider reset times accepted for
	// automatic resume. A reset farther out is treated as unreliable and leaves
	// the batch paused for manual operator action.
	MaxRateLimitAutoResumeDelay time.Duration
	// DowngradeOnOverage falls the model tier back from max/high to the mid tier
	// for newly enqueued scans while the subscription is past its included quota
	// (on overage), restoring it when the window resets. Off by default; only a
	// subscription token reports overage, so it is inert on an API key.
	DowngradeOnOverage bool
	// Now overrides time.Now in tests.
	Now func() time.Time

	autoResumeMu    sync.Mutex
	autoResumeTimer *time.Timer
	autoResumeAt    time.Time

	// rlStatus holds the latest in-memory rate_limit_event per window type.
	rlStatusMu sync.Mutex
	rlStatus   map[string]RateLimitInfo
}

// recordRateLimit stores the latest rate-limit status for its window type and,
// when the overage fallback is enabled, logs the transition into or out of
// overage so the switch to/from the mid tier is visible in the log.
func (w *Worker) recordRateLimit(info RateLimitInfo) {
	if info.Type == "" {
		return
	}
	w.rlStatusMu.Lock()
	if w.rlStatus == nil {
		w.rlStatus = map[string]RateLimitInfo{}
	}
	before := w.onOverageLocked()
	w.rlStatus[info.Type] = info
	after := w.onOverageLocked()
	w.rlStatusMu.Unlock()
	if w.DowngradeOnOverage && before != after && w.Log != nil {
		if after {
			w.Log.Info("model overage fallback engaged: account on overage, new scans use the mid tier")
		} else {
			w.Log.Info("model overage fallback lifted: overage cleared, new scans use the max/high tier again")
		}
	}
}

// RateLimitStatus returns a snapshot of the latest rate-limit status per window,
// for the usage page. Empty when no subscription rate_limit_event has been seen
// (fresh process, or an API-key account that does not report them).
func (w *Worker) RateLimitStatus() []RateLimitInfo {
	if w == nil {
		return nil
	}
	w.rlStatusMu.Lock()
	defer w.rlStatusMu.Unlock()
	out := make([]RateLimitInfo, 0, len(w.rlStatus))
	for _, v := range w.rlStatus {
		out = append(out, v)
	}
	return out
}

// onOverageLocked reports whether any tracked window is currently on overage
// (past the included quota) with an unexpired reset, or with no reset timestamp
// (unknown reset). Caller holds rlStatusMu.
func (w *Worker) onOverageLocked() bool {
	now := w.now().UTC()
	for _, info := range w.rlStatus {
		if info.IsUsingOverage {
			if t := info.ResetTime(); t == nil || t.After(now) {
				return true
			}
		}
	}
	return false
}

// OnOverage reports whether the Claude account is currently past its included
// subscription quota (any tracked window isUsingOverage with an unexpired reset
// or no reset timestamp). An API-key account never reports overage, so this stays false there.
func (w *Worker) OnOverage() bool {
	if w == nil {
		return false
	}
	w.rlStatusMu.Lock()
	defer w.rlStatusMu.Unlock()
	return w.onOverageLocked()
}

// ShouldDowngradeModel reports whether the max/high-to-mid overage fallback is
// both enabled and currently active. The web layer calls it at enqueue to rewrite
// max/high tier preferences to mid, and to surface the fallback banner.
func (w *Worker) ShouldDowngradeModel() bool {
	return w != nil && w.DowngradeOnOverage && w.OnOverage()
}

func (w *Worker) logFlushInterval() time.Duration {
	if w.LogFlushInterval > 0 {
		return w.LogFlushInterval
	}
	return defaultLogFlushInterval
}

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

const (
	defaultAutoResumeBuffer     = 5 * time.Second
	defaultAutoResumeRetryDelay = 30 * time.Second
	// defaultMaxRateLimitAutoResumeAge bounds how far out a reported reset can
	// be before it is treated as unreliable. Anthropic subscription windows are
	// five-hour and seven-day, so allow a little over a week.
	defaultMaxRateLimitAutoResumeAge = 8 * 24 * time.Hour
)

func (w *Worker) autoResumeBuffer() time.Duration {
	if w.AutoResumeBuffer > 0 {
		return w.AutoResumeBuffer
	}
	return defaultAutoResumeBuffer
}

func (w *Worker) autoResumeRetryDelay() time.Duration {
	if w.AutoResumeRetryDelay > 0 {
		return w.AutoResumeRetryDelay
	}
	return defaultAutoResumeRetryDelay
}

func (w *Worker) maxRateLimitAutoResumeDelay() time.Duration {
	if w.MaxRateLimitAutoResumeDelay > 0 {
		return w.MaxRateLimitAutoResumeDelay
	}
	return defaultMaxRateLimitAutoResumeAge
}

// Cancel aborts an in-flight scan. Returns true if a running job was found and
// signalled; false means the scan is queued (or already finished) and the
// caller should flip the DB row itself so the queue handler drops it.
func (w *Worker) Cancel(scanID uint) bool {
	w.mu.Lock()
	cancel, ok := w.running[scanID]
	w.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

func (w *Worker) publish(scanID, repoID uint, name, data string) {
	if w.OnEvent != nil {
		w.OnEvent(scanID, repoID, name, data)
	}
}

// workRoot returns the per-scan workspace directory under DataDir.
func (w *Worker) workRoot(scanID uint) string {
	return filepath.Join(w.DataDir, fmt.Sprintf("scan-%d", scanID))
}

// resolveMaxTurns picks a scan's turn cap: the skill's own cap when it sets
// one, else the operator-configured default read live from settings so a
// change on the Settings page applies to the next scan without a restart. A
// 0 result leaves the runner's startup default (the --max-turns flag) as the
// downstream fallback.
func (w *Worker) resolveMaxTurns(skillMaxTurns int) int {
	if skillMaxTurns > 0 {
		return skillMaxTurns
	}
	return db.SettingInt(w.DB, db.SettingDefaultMaxTurns)
}

// workspaceScanID returns the scan id whose workspace path a run should
// use. A fresh scan uses its own id; a retry that resumes a session reuses
// the lineage-root id so claude executes in the same working directory the
// original run did — claude keys its resumable session store by cwd, so a
// different path means --resume can't find the conversation.
func workspaceScanID(scan *db.Scan) uint {
	if scan.ResumedFromScanID != nil && *scan.ResumedFromScanID != 0 {
		return *scan.ResumedFromScanID
	}
	return scan.ID
}

// scanWorkRoot is workRoot resolved through the resume lineage.
func (w *Worker) scanWorkRoot(scan *db.Scan) string {
	return w.workRoot(workspaceScanID(scan))
}

// harnessStateDir is the host directory holding the active harness's
// session store for this scan's lineage. The container runner mounts it
// at /harness-state and points the harness at it via StateEnv, so the
// conversation survives a container exit; it lives outside the per-scan
// workspace (which is deleted when the scan finishes) and is keyed by
// the lineage root so a retry finds the original run's session. The
// local runner ignores it and uses the host's own ~/.claude.
func (w *Worker) harnessStateDir(scan *db.Scan) string {
	return w.harnessStateDirID(workspaceScanID(scan))
}

const (
	harnessStateDirName = "harness-state"
	// legacyHarnessStateDirName is the pre-rename directory name.
	// migrateLegacyState renames it in place at startup so existing
	// resume stores survive the rename. Remove once no deployment can
	// have the old directory (one release after this change ships).
	legacyHarnessStateDirName = "claude-config"
)

func (w *Worker) harnessStateDirID(scanID uint) string {
	return filepath.Join(w.DataDir, harnessStateDirName, fmt.Sprintf("scan-%d", scanID))
}

// RemoveScanArtifacts deletes the on-disk per-scan workspace and harness
// state directory for scanID. Normal terminal cleanup removes workspaces,
// while resumable scans (failed or max-turns-hit) keep their state dir so a
// retry can resume the session; this explicit removal path reclaims both. It
// is a no-op when the
// directories are already gone. Passing every scan id of a repository covers
// resume lineages too: a retry reuses its root's workspace id, and the root
// scan is itself in the repo, while the retry's own id maps to a directory
// that was never created.
func (w *Worker) RemoveScanArtifacts(scanID uint) error {
	return errors.Join(
		os.RemoveAll(w.workRoot(scanID)),
		os.RemoveAll(w.harnessStateDirID(scanID)),
	)
}

// applyResume fills a SkillJob's session-resume inputs from the scan: the
// harness session id to continue (set on a retry that carries one forward
// from a failed or max-turns-hit run) and the persistent state dir the
// container runner mounts so the session store survives a container exit.
// A fresh scan has an empty SessionID, so the harness starts a new
// conversation. What the id names depends on the harness (a claude session,
// a codex thread, an opencode session); the runner never interprets it.
func (w *Worker) applyResume(scan *db.Scan, sj *SkillJob, emit func(Event)) {
	sj.StateDir = w.harnessStateDir(scan)
	if scan.SessionID != "" {
		sj.ResumeSessionID = scan.SessionID
		emit(Event{Kind: KindText, Text: "resuming session " + scan.SessionID})
	}
}

// scanEmitter returns the emit callback handed to a job handler and a snapshot
// callback that materializes its buffered log into scan.Log. Event accumulation
// stays linear, live publication remains immediate, and DB persistence is
// batched to logFlushInterval. wrap snapshots before final persistence so a
// scan that finishes between flushes still lands its full log. Session
// events bypass batching: a session id is small, terminal-only changes,
// and must hit the DB the moment it appears so a crash mid-run leaves the
// scan resumable.
func (w *Worker) scanEmitter(scan *db.Scan) (func(Event), func()) {
	interval := w.logFlushInterval()
	lastFlush := time.Now()
	var logBuilder strings.Builder
	logBuilder.Grow(len(scan.Log))
	logBuilder.WriteString(scan.Log)
	snapshot := func() {
		scan.Log = logBuilder.String()
	}
	return func(e Event) {
		if e.Kind == KindSession {
			if e.SessionID != "" && e.SessionID != scan.SessionID {
				scan.SessionID = e.SessionID
				w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("session_id", e.SessionID)
			}
			return
		}
		if e.Kind == KindRateLimit && e.RateLimit != nil {
			w.recordRateLimit(*e.RateLimit)
		}
		line := FormatEvent(e)
		logBuilder.WriteString(line)
		logBuilder.WriteByte('\n')
		if time.Since(lastFlush) >= interval {
			snapshot()
			w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("log", scan.Log)
			lastFlush = time.Now()
		}
		if e.Kind == KindResult {
			// Claude reports total_cost_usd in its result event; harnesses
			// that only report token counts (codex) get the cost computed
			// from list prices so /usage and the scan row show a real
			// figure instead of $0.
			if e.CostUSD == 0 {
				e.CostUSD = CostFromUsage(scan.Model, e.Usage)
			}
			scan.CostUSD += e.CostUSD
			scan.Turns += e.Turns
			scan.InputTokens += e.Usage.InputTokens
			scan.OutputTokens += e.Usage.OutputTokens
			scan.CacheReadTokens += e.Usage.CacheReadTokens
			scan.CacheWriteTokens += e.Usage.CacheWriteTokens
		}
		w.publish(scan.ID, scan.RepositoryID, "scan-log", line+"\n")
	}, snapshot
}

// clearSessionStore wipes a finished scan's resume state so its next
// deliberate re-run starts fresh: it drops the session id and tears down the
// persisted claude session store. Only called on ordinary "done" — failed and
// max-turns-hit scans keep both so a UI retry can --resume instead of
// restarting from turn 0.
func (w *Worker) clearSessionStore(scan *db.Scan) {
	scan.SessionID = ""
	if rmErr := os.RemoveAll(w.harnessStateDir(scan)); rmErr != nil {
		w.Log.Warn("session store cleanup failed", "scan", scan.ID, "err", rmErr)
	}
}

func (w *Worker) Register(q *queue.Queue) {
	w.Queue = q
	w.migrateLegacyState()
	q.Register(JobSkill, w.wrap(w.doSkill))
	q.Register(JobExposure, w.wrap(w.doExposure))
	w.scheduleNextAccountResume()
}

// migrateLegacyState brings pre-rename on-disk and in-row state forward
// so a deployment upgraded across the harness-naming rename keeps its
// resume stores and its account-paused scans keep auto-resuming without
// every LIKE query having to match two prefixes. Both steps are no-ops
// on a fresh install.
func (w *Worker) migrateLegacyState() {
	// {data}/claude-config -> {data}/harness-state, so existing session
	// stores survive the harnessStateDir rename. Only when the old
	// directory exists and the new one does not; anything else is left
	// alone so a partially-migrated tree is never clobbered.
	if w.DataDir != "" {
		oldDir := filepath.Join(w.DataDir, legacyHarnessStateDirName)
		newDir := filepath.Join(w.DataDir, harnessStateDirName)
		if _, err := os.Stat(oldDir); err == nil {
			if _, err := os.Stat(newDir); errors.Is(err, os.ErrNotExist) {
				if err := os.Rename(oldDir, newDir); err != nil {
					w.Log.Warn("migrate harness state dir", "from", oldDir, "to", newDir, "err", err)
				}
			}
		}
	}
	// Rewrite the pre-rename AccountPausePrefix in scans.error so the
	// single-pattern LIKE queries (worker.go, web/scans.go) still find
	// scans that were account-paused before the upgrade. Scoped to
	// paused rows only, which is a small transient set.
	if w.DB != nil {
		res := w.DB.Exec(
			"UPDATE scans SET error = REPLACE(error, ?, ?) WHERE status = ? AND error LIKE ?",
			legacyAccountPausePrefix, AccountPausePrefix, db.ScanPaused, legacyAccountPausePrefix+"%",
		)
		if res.Error != nil {
			w.Log.Warn("migrate account-pause prefix", "err", res.Error)
		} else if res.RowsAffected > 0 {
			w.Log.Info("migrated account-pause prefix on paused scans", "rows", res.RowsAffected)
		}
	}
}

// handler does the actual work for one job kind. It receives the loaded scan
// (with Repository preloaded) and an emit callback that appends to Scan.Log.
// The returned report string lands in Scan.Report.
type handler func(ctx context.Context, scan *db.Scan, emit func(Event)) (report string, err error)

// wrap turns a handler into a goqite jobs.Func: decode payload, load the
// scan row, run the handler, persist status/log/report. Errors from the
// handler mark the scan failed but return nil to goqite so it does not
// auto-retry expensive work; the user re-queues from the UI.
func (w *Worker) wrap(h handler) func(context.Context, []byte) error {
	return func(ctx context.Context, body []byte) error {
		var p queue.Payload
		if err := json.Unmarshal(body, &p); err != nil {
			return fmt.Errorf("decode payload: %w", err)
		}
		var scan db.Scan
		if err := w.DB.Preload("Repository").First(&scan, p.ScanID).Error; err != nil {
			return fmt.Errorf("load scan %d: %w", p.ScanID, err)
		}
		if scan.Status != db.ScanQueued {
			w.Log.Info("dropping stale job", "scan", scan.ID, "status", scan.Status)
			return nil
		}

		if scan.Kind == JobSkill {
			deferred, err := w.preflightSkill(ctx, &scan, p.Attempt)
			if err != nil {
				return err
			}
			if deferred {
				return nil
			}
		}

		timeout := w.ScanTimeout
		if timeout <= 0 {
			timeout = DefaultScanTimeout
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		w.mu.Lock()
		if w.running == nil {
			w.running = make(map[uint]context.CancelFunc)
		}
		w.running[scan.ID] = cancel
		w.mu.Unlock()
		defer func() {
			w.mu.Lock()
			delete(w.running, scan.ID)
			w.mu.Unlock()
		}()

		if err := w.startScan(&scan); err != nil {
			return err
		}

		if w.RefreshEcosystemsCache != nil && !scan.Repository.IsLocal() {
			if err := w.RefreshEcosystemsCache(ctx, scan.RepositoryID); err != nil {
				w.Log.Warn("ecosystems refresh failed", "scan", scan.ID, "repo", scan.RepositoryID, "err", err)
			}
		}

		emit, snapshotLog := w.scanEmitter(&scan)

		report, err := h(ctx, &scan, emit)
		return w.finalizeScan(ctx, &scan, report, err, timeout, emit, snapshotLog)
	}
}

// startScan records the running state and its audit event in one transaction
// so a scan never appears to have started without a corresponding timeline
// entry.
func (w *Worker) startScan(scan *db.Scan) error {
	now := time.Now()
	scan.Status = db.ScanRunning
	scan.StatusPriority = db.StatusPriorityFor(db.ScanRunning)
	scan.StartedAt = &now
	scan.Log = ""
	scan.Error = ""
	if br, ok := w.Runner.(BackendReporter); ok {
		scan.Backend = br.Backend()
	}
	return w.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(scan).Error; err != nil {
			return err
		}
		return db.LogScanEvent(tx, db.AuditEventScanStarted, scan)
	})
}

// finalizeScan persists the terminal/paused scan state, fires
// post-completion hooks, bulk-pauses the rest of the queue when this scan
// hit an account-level Claude problem, cleans up the workspace, and publishes
// the status. It returns an error only when the terminal save fails, which
// wrap propagates to goqite.
func (w *Worker) finalizeScan(ctx context.Context, scan *db.Scan, report string, err error, timeout time.Duration, emit func(Event), snapshotLog func()) error {
	finishScan(ctx, scan, report, err, timeout, emit)
	snapshotLog()
	if scan.Status == db.ScanDone && !scan.MaxTurnsHit {
		w.clearSessionStore(scan)
	}
	scan.StatusPriority = db.StatusPriorityFor(scan.Status)
	if eventKind, ok := db.ScanLifecycleEventKind(scan.Status); ok {
		if saveErr := w.DB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Save(scan).Error; err != nil {
				return err
			}
			return db.LogScanEvent(tx, eventKind, scan)
		}); saveErr != nil {
			return saveErr
		}
	} else if saveErr := w.DB.Save(scan).Error; saveErr != nil {
		return saveErr
	}
	w.maybeFireScanFinalized(scan, err)
	if accErr, isAccountErr := errors.AsType[*AccountError](err); isAccountErr && scan.Status == db.ScanPaused {
		w.pauseQueuedOnAccountError(scan.ID)
		if rawReset := w.resolveAccountReset(accErr, emit); rawReset != nil {
			effective, applyErr := w.applyAccountPauseReset(scan.ID, scan.Error, rawReset)
			if applyErr != nil {
				w.Log.Warn("account-pause reset update failed", "scan", scan.ID, "err", applyErr)
			} else if effective != nil {
				scan.PausedUntil = effective
				scan.Error = appendAutoResume(scan.Error, effective)
				w.scheduleAccountResumeAt(*effective)
			}
		}
		// resolveAccountReset emitted after the Save above; persist that log tail.
		snapshotLog()
		if logErr := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("log", scan.Log).Error; logErr != nil {
			w.Log.Warn("account-pause log update failed", "scan", scan.ID, "err", logErr)
		}
	}
	// The clone cache may have grown (clone/fetch/unshallow); refresh the
	// cached size so the repo list reads it from the row instead of walking
	// the filesystem per render (#126).
	if !scan.Repository.IsLocal() {
		w.refreshRepoDiskUsage(scan.RepositoryID)
	}
	if scan.Status.Terminal() {
		if rmErr := os.RemoveAll(w.scanWorkRoot(scan)); rmErr != nil {
			w.Log.Warn("workspace cleanup failed", "scan", scan.ID, "err", rmErr)
		}
	}
	w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
	w.Log.Info("job finished", "scan", scan.ID, "kind", scan.Kind, "status", scan.Status)
	return nil
}

// resolveAccountReset accepts only fresh, plausible reset times; nil leaves the
// batch paused for manual resume.
func (w *Worker) resolveAccountReset(accErr *AccountError, emit func(Event)) *time.Time {
	if accErr == nil || accErr.ResetAt == nil {
		emit(Event{Kind: KindText, Text: "no rate-limit reset reported; leaving paused for manual resume"})
		return nil
	}
	now := w.now().UTC()
	resetAt := accErr.ResetAt.UTC()
	if !resetAt.After(now) {
		emit(Event{Kind: KindText, Text: "rate-limit reset time is already in the past"})
		return nil
	}
	if wait := resetAt.Sub(now); wait > w.maxRateLimitAutoResumeDelay() {
		emit(Event{Kind: KindText, Text: fmt.Sprintf("rate-limit reset time %s is beyond auto-resume limit %s", resetAt.UTC().Format(time.RFC3339), w.maxRateLimitAutoResumeDelay())})
		return nil
	}
	emit(Event{Kind: KindText, Text: "rate limit reset detected; auto-resume after " + resetAt.UTC().Format(time.RFC3339)})
	return &resetAt
}

// maybeFireScanFinalized invokes the OnScanFinalized hook once a scan has
// finished its analysis with findings committed. A fail_on threshold leaves
// Status=ScanFailed but the findings are already persisted (see
// finishErroredScan), so a deep-dive that trips fail_on must still trigger
// downstream dedup — exactly the high-severity case we most want deduped.
func (w *Worker) maybeFireScanFinalized(scan *db.Scan, runErr error) {
	if w.OnScanFinalized == nil {
		return
	}
	_, failOnThreshold := errors.AsType[*FailOnThresholdError](runErr)
	if scan.Status == db.ScanDone || failOnThreshold {
		w.OnScanFinalized(scan)
	}
}

func finishScan(ctx context.Context, scan *db.Scan, report string, err error, timeout time.Duration, emit func(Event)) {
	scan.FinishedAt = new(time.Now())
	scan.MaxTurnsHit = false
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		scan.Status = db.ScanFailed
		scan.Error = fmt.Sprintf("scan timed out after %s", timeout)
		emit(Event{Kind: KindError, Text: scan.Error})
	case errors.Is(ctx.Err(), context.Canceled):
		scan.Status = db.ScanCancelled
		scan.Error = "cancelled by user"
		emit(Event{Kind: KindError, Text: scan.Error})
	case err != nil:
		finishErroredScan(scan, report, err, emit)
	default:
		scan.Status = db.ScanDone
		scan.Report = report
	}
}

func finishErroredScan(scan *db.Scan, report string, err error, emit func(Event)) {
	scan.Status = db.ScanFailed
	scan.Error = err.Error()
	_, maxTurns := errors.AsType[*MaxTurnsReachedError](err)
	_, failOnThreshold := errors.AsType[*FailOnThresholdError](err)
	_, schemaValidation := errors.AsType[*SchemaValidationError](err)
	_, accountErr := errors.AsType[*AccountError](err)
	switch {
	case maxTurns:
		scan.Status = db.ScanDone
		scan.Report = report
		scan.Error = ""
		scan.MaxTurnsHit = true
		emit(Event{Kind: KindText, Text: "scan completed (hit max turns cap)"})
	case failOnThreshold:
		scan.Report = report
		emit(Event{Kind: KindError, Text: scan.Error})
	case schemaValidation:
		scan.Report = report
	case accountErr:
		// Account-level Claude failures pause the batch instead of failing scans
		// one by one.
		scan.Status = db.ScanPaused
		emit(Event{Kind: KindError, Text: scan.Error})
	default:
		emit(Event{Kind: KindError, Text: scan.Error})
	}
}

// accountPauseReasonBase shares AccountPausePrefix with trigger rows so
// the scans page can group the batch together.
const accountPauseReasonBase = AccountPausePrefix + " Queued scan paused automatically"

func accountPauseReason(resetAt *time.Time) string {
	if resetAt == nil || resetAt.IsZero() {
		return accountPauseReasonBase + "; resume once the account recovers."
	}
	return appendAutoResume(accountPauseReasonBase+" until the provider rate limit resets.", resetAt)
}

func appendAutoResume(msg string, resetAt *time.Time) string {
	if resetAt == nil || resetAt.IsZero() {
		return msg
	}
	return msg + autoResumeAfterPrefix + resetAt.UTC().Format(time.RFC3339) + "."
}

// replaceAutoResume swaps the reset suffix without clobbering the row's detail.
func replaceAutoResume(msg string, resetAt *time.Time) string {
	return appendAutoResume(stripAutoResume(msg), resetAt)
}

// stripAutoResume removes existing auto-resume metadata before rewriting it.
func stripAutoResume(msg string) string {
	if i := strings.Index(msg, autoResumeAfterPrefix); i >= 0 {
		return strings.TrimRight(msg[:i], " ")
	}
	if i := strings.Index(msg, autoResumeFailurePrefix); i >= 0 {
		return strings.TrimRight(msg[:i], " ")
	}
	return msg
}

const (
	autoResumeAfterPrefix   = " Auto-resume after "
	autoResumeFailurePrefix = " Auto-resume failed: "
	maxAutoResumeErrorBytes = 600
)

func appendAutoResumeFailure(msg string, err error) string {
	if msg == "" {
		msg = accountPauseReason(nil)
	}
	msg = stripAutoResume(msg)
	detail := err.Error()
	if len(detail) > maxAutoResumeErrorBytes {
		detail = detail[:maxAutoResumeErrorBytes] + "..."
	}
	return msg + autoResumeFailurePrefix + detail
}

// pauseQueuedOnAccountError pauses every queued scan behind an account-level
// Claude failure; queued jobs later drop themselves when wrap sees the DB state.
func (w *Worker) pauseQueuedOnAccountError(triggerID uint) {
	now := w.now().UTC()
	reason := accountPauseReason(nil)
	res := w.DB.Model(&db.Scan{}).
		Where("status = ?", db.ScanQueued).
		Updates(map[string]any{
			"status":          db.ScanPaused,
			"status_priority": db.StatusPriorityFor(db.ScanPaused),
			"error":           reason,
			"finished_at":     &now,
		})
	if res.Error != nil {
		w.Log.Warn("pause-on-account-error failed", "trigger", triggerID, "err", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		w.Log.Info("paused queued scans after Claude account error", "count", res.RowsAffected, "trigger", triggerID)
	}
}

// applyAccountPauseReset moves the trigger and batch to the furthest known
// reset, returning that effective reset for scheduling.
func (w *Worker) applyAccountPauseReset(triggerID uint, baseError string, resetAt *time.Time) (*time.Time, error) {
	if resetAt == nil {
		return nil, nil
	}
	resetAtUTC := resetAt.UTC()
	resetAt = &resetAtUTC
	// A concurrent scan may already have found a later binding reset. Ignore any
	// row already beyond the auto-resume window, so a stale or manually-set
	// far-future pause cannot drag every subsequent batch out to it.
	maxAcceptable := w.now().UTC().Add(w.maxRateLimitAutoResumeDelay())
	var latest db.Scan
	if err := w.DB.Select("paused_until").
		Where("id != ? AND status = ? AND error LIKE ? AND paused_until IS NOT NULL AND paused_until <= ?",
			triggerID, db.ScanPaused, AccountPausePrefix+"%", maxAcceptable).
		Order("paused_until DESC").Limit(1).Find(&latest).Error; err != nil {
		return nil, err
	}
	effective := resetAt
	if latest.PausedUntil != nil && latest.PausedUntil.After(*resetAt) {
		effective = latest.PausedUntil
	}

	// Update the triggering scan's reset, keeping its Claude detail. Forward-only
	// so a concurrent finalizer that already pushed this row to a later reset is
	// not pulled back; if the guard skips it, re-read so the returned effective
	// reset reflects the row's actual (possibly later) value.
	trigRes := w.DB.Model(&db.Scan{}).
		Where("id = ? AND status = ? AND (paused_until IS NULL OR paused_until < ?)", triggerID, db.ScanPaused, effective).
		Updates(map[string]any{
			"error":        appendAutoResume(baseError, effective),
			"paused_until": effective,
		})
	if trigRes.Error != nil {
		return nil, trigRes.Error
	}
	if trigRes.RowsAffected == 0 {
		// The guard skipped the row: it was either extended to a later reset by a
		// concurrent finalizer, or is no longer account-paused (manually resumed).
		// Only adopt a later reset while the row is still account-paused; a
		// resumed/absent row matches nothing here, so we never revive a stale one.
		var cur db.Scan
		if err := w.DB.Select("paused_until").
			Where("id = ? AND status = ? AND error LIKE ? AND paused_until IS NOT NULL",
				triggerID, db.ScanPaused, AccountPausePrefix+"%").
			Find(&cur).Error; err != nil {
			return nil, err
		}
		if cur.PausedUntil != nil && cur.PausedUntil.After(*effective) {
			effective = cur.PausedUntil
		}
	}
	// Shared queued rows carry the same message, so extend them in bulk.
	if err := w.DB.Model(&db.Scan{}).
		Where("id != ? AND status = ? AND error LIKE ? AND (paused_until IS NULL OR paused_until < ?)",
			triggerID, db.ScanPaused, accountPauseReasonBase+"%", effective).
		Updates(map[string]any{
			"error":        accountPauseReason(effective),
			"paused_until": effective,
		}).Error; err != nil {
		return nil, err
	}
	// Trigger rows carry Claude detail, so rewrite them individually. The
	// update re-checks the guard to avoid clobbering concurrent changes.
	var triggers []db.Scan
	if err := w.DB.Select("id", "error").
		Where("id != ? AND status = ? AND error LIKE ? AND error NOT LIKE ? AND (paused_until IS NULL OR paused_until < ?)",
			triggerID, db.ScanPaused, AccountPausePrefix+"%", accountPauseReasonBase+"%", effective).
		Find(&triggers).Error; err != nil {
		return nil, err
	}
	for _, tr := range triggers {
		res := w.DB.Model(&db.Scan{}).
			Where("id = ? AND status = ? AND error LIKE ? AND error NOT LIKE ? AND (paused_until IS NULL OR paused_until < ?)",
				tr.ID, db.ScanPaused, AccountPausePrefix+"%", accountPauseReasonBase+"%", effective).
			Updates(map[string]any{
				"error":        replaceAutoResume(tr.Error, effective),
				"paused_until": effective,
			})
		if res.Error != nil {
			return nil, res.Error
		}
	}
	return effective, nil
}

func (w *Worker) scheduleAccountResumeAt(resetAt time.Time) {
	if resetAt.IsZero() || w.DB == nil || w.Queue == nil {
		return
	}
	when := resetAt.Add(w.autoResumeBuffer())
	w.scheduleAutoResumeAt(when)
}

func (w *Worker) scheduleAccountResumeAfter(delay time.Duration) {
	if w.DB == nil || w.Queue == nil {
		return
	}
	if delay < w.autoResumeRetryDelay() {
		delay = w.autoResumeRetryDelay()
	}
	w.scheduleAutoResumeAt(w.now().UTC().Add(delay))
}

func (w *Worker) scheduleAutoResumeAt(when time.Time) {
	delay := when.Sub(w.now().UTC())
	if delay < 0 {
		delay = 0
	}

	w.autoResumeMu.Lock()
	defer w.autoResumeMu.Unlock()
	if w.autoResumeTimer != nil && !when.Before(w.autoResumeAt) {
		return
	}
	if w.autoResumeTimer != nil {
		w.autoResumeTimer.Stop()
	}
	w.autoResumeAt = when
	w.autoResumeTimer = time.AfterFunc(delay, func() {
		resumed, err := w.resumeAccountPaused(context.Background())
		w.autoResumeMu.Lock()
		w.autoResumeTimer = nil
		w.autoResumeAt = time.Time{}
		w.autoResumeMu.Unlock()
		if err != nil {
			w.Log.Warn("auto-resume account-paused scans failed", "err", err)
			w.scheduleAccountResumeAfter(w.autoResumeRetryDelay())
			return
		} else if resumed > 0 {
			w.Log.Info("auto-resumed account-paused scans", "count", resumed)
		}
		w.scheduleNextAccountResume()
	})
}

func (w *Worker) scheduleNextAccountResume() {
	if w.DB == nil || w.Queue == nil {
		return
	}
	var scan db.Scan
	err := w.DB.Select("id", "paused_until").
		Where("status = ? AND error LIKE ? AND paused_until IS NOT NULL", db.ScanPaused, AccountPausePrefix+"%").
		Order("paused_until ASC").
		Limit(1).
		Find(&scan).Error
	if err != nil || scan.ID == 0 || scan.PausedUntil == nil {
		return
	}
	w.scheduleAccountResumeAt(*scan.PausedUntil)
}

func (w *Worker) resumeAccountPaused(ctx context.Context) (int, error) {
	if w.Queue == nil {
		return 0, errors.New("queue not configured")
	}
	var scans []db.Scan
	if err := w.DB.Select("id", "kind", "finding_id", "error", "paused_until").
		Where("status = ? AND error LIKE ? AND paused_until IS NOT NULL AND paused_until <= ?",
			db.ScanPaused, AccountPausePrefix+"%", w.now().UTC()).
		Order("id").
		Find(&scans).Error; err != nil {
		return 0, err
	}
	var resumed int
	for _, sc := range scans {
		updates := map[string]any{
			"status":          db.ScanQueued,
			"status_priority": db.StatusPriorityFor(db.ScanQueued),
			"error":           "",
			"finished_at":     nil,
			"paused_until":    nil,
		}
		res := w.DB.Model(&db.Scan{}).Where("id = ? AND status = ?", sc.ID, db.ScanPaused).Updates(updates)
		if res.Error != nil {
			return resumed, res.Error
		}
		if res.RowsAffected == 0 {
			continue
		}
		priority := PrioScan
		if sc.FindingID != nil {
			priority = PrioFinding
		}
		if err := w.Queue.Enqueue(ctx, sc.Kind, sc.ID, priority); err != nil {
			now := w.now().UTC()
			restoreErr := w.DB.Model(&db.Scan{}).Where("id = ?", sc.ID).Updates(map[string]any{
				"status":          db.ScanPaused,
				"status_priority": db.StatusPriorityFor(db.ScanPaused),
				"error":           appendAutoResumeFailure(sc.Error, err),
				"finished_at":     &now,
				"paused_until":    sc.PausedUntil,
			}).Error
			return resumed, errors.Join(err, restoreErr)
		}
		resumed++
	}
	return resumed, nil
}
