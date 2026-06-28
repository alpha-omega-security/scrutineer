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
}

func (w *Worker) logFlushInterval() time.Duration {
	if w.LogFlushInterval > 0 {
		return w.LogFlushInterval
	}
	return defaultLogFlushInterval
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

// claudeConfigDir is the host directory holding the claude session store
// for this scan's lineage. The container runner mounts it as CLAUDE_CONFIG_DIR
// so the conversation survives a container exit; it lives outside the
// per-scan workspace (which is deleted when the scan finishes) and is keyed
// by the lineage root so a retry finds the original run's session. The
// local runner ignores it and uses the host's own ~/.claude.
func (w *Worker) claudeConfigDir(scan *db.Scan) string {
	return w.claudeConfigDirID(workspaceScanID(scan))
}

func (w *Worker) claudeConfigDirID(scanID uint) string {
	return filepath.Join(w.DataDir, "claude-config", fmt.Sprintf("scan-%d", scanID))
}

// RemoveScanArtifacts deletes the on-disk per-scan workspace and claude
// session store for scanID. Normal terminal cleanup removes workspaces, while
// resumable scans (failed or max-turns-hit) keep their session store for
// --resume; this explicit removal path reclaims both. It is a no-op when the
// directories are already gone. Passing every scan id of a repository covers
// resume lineages too: a retry reuses its root's workspace id, and the root
// scan is itself in the repo, while the retry's own id maps to a directory
// that was never created.
func (w *Worker) RemoveScanArtifacts(scanID uint) error {
	return errors.Join(
		os.RemoveAll(w.workRoot(scanID)),
		os.RemoveAll(w.claudeConfigDirID(scanID)),
	)
}

// applyResume fills a SkillJob's session-resume inputs from the scan: the
// claude session id to --resume (set on a retry that carries one forward
// from a failed or max-turns-hit run) and the persistent config dir the container
// runner mounts so the session store survives a container exit. A fresh scan
// has an empty SessionID, so the runner just starts a new conversation.
func (w *Worker) applyResume(scan *db.Scan, sj *SkillJob, emit func(Event)) {
	sj.ClaudeConfigDir = w.claudeConfigDir(scan)
	if scan.SessionID != "" {
		sj.ResumeSessionID = scan.SessionID
		emit(Event{Kind: KindText, Text: "resuming claude session " + scan.SessionID})
	}
}

// scanEmitter returns the emit callback handed to a job handler. It appends
// each event to scan.Log in memory and streams it live to subscribers via
// publish(); DB persistence is batched to logFlushInterval so a token-heavy
// scan does not rewrite the whole log TEXT column on every event. wrap's
// final Save(&scan) flushes the tail along with every other column, so a
// scan that finishes between flushes still lands its full log. Session
// events bypass batching: a session id is small, terminal-only changes,
// and must hit the DB the moment it appears so a crash mid-run leaves the
// scan resumable.
func (w *Worker) scanEmitter(scan *db.Scan) func(Event) {
	interval := w.logFlushInterval()
	lastFlush := time.Now()
	return func(e Event) {
		if e.Kind == KindSession {
			if e.SessionID != "" && e.SessionID != scan.SessionID {
				scan.SessionID = e.SessionID
				w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("session_id", e.SessionID)
			}
			return
		}
		line := FormatEvent(e)
		scan.Log += line + "\n"
		if time.Since(lastFlush) >= interval {
			w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("log", scan.Log)
			lastFlush = time.Now()
		}
		if e.Kind == KindResult {
			scan.CostUSD += e.CostUSD
			scan.Turns += e.Turns
			scan.InputTokens += e.Usage.InputTokens
			scan.OutputTokens += e.Usage.OutputTokens
			scan.CacheReadTokens += e.Usage.CacheReadTokens
			scan.CacheWriteTokens += e.Usage.CacheWriteTokens
		}
		w.publish(scan.ID, scan.RepositoryID, "scan-log", line+"\n")
	}
}

// clearSessionStore wipes a finished scan's resume state so its next
// deliberate re-run starts fresh: it drops the session id and tears down the
// persisted claude session store. Only called on ordinary "done" — failed and
// max-turns-hit scans keep both so a UI retry can --resume instead of
// restarting from turn 0.
func (w *Worker) clearSessionStore(scan *db.Scan) {
	scan.SessionID = ""
	if rmErr := os.RemoveAll(w.claudeConfigDir(scan)); rmErr != nil {
		w.Log.Warn("session store cleanup failed", "scan", scan.ID, "err", rmErr)
	}
}

func (w *Worker) Register(q *queue.Queue) {
	w.Queue = q
	q.Register(JobSkill, w.wrap(w.doSkill))
	q.Register(JobExposure, w.wrap(w.doExposure))
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

		scan.Status = db.ScanRunning
		scan.StatusPriority = db.StatusPriorityFor(db.ScanRunning)
		scan.StartedAt = new(time.Now())
		scan.Log = ""
		scan.Error = ""
		if err := w.DB.Save(&scan).Error; err != nil {
			return err
		}

		if w.RefreshEcosystemsCache != nil && !scan.Repository.IsLocal() {
			if err := w.RefreshEcosystemsCache(ctx, scan.RepositoryID); err != nil {
				w.Log.Warn("ecosystems refresh failed", "scan", scan.ID, "repo", scan.RepositoryID, "err", err)
			}
		}

		emit := w.scanEmitter(&scan)

		report, err := h(ctx, &scan, emit)
		return w.finalizeScan(ctx, &scan, report, err, timeout, emit)
	}
}

// finalizeScan persists the terminal/paused scan state, fires
// post-completion hooks, bulk-pauses the rest of the queue when this scan
// hit an account-level Claude problem, cleans up the workspace, and publishes
// the status. It returns an error only when the terminal save fails, which
// wrap propagates to goqite.
func (w *Worker) finalizeScan(ctx context.Context, scan *db.Scan, report string, err error, timeout time.Duration, emit func(Event)) error {
	finishScan(ctx, scan, report, err, timeout, emit)
	if scan.Status == db.ScanDone && !scan.MaxTurnsHit {
		w.clearSessionStore(scan)
	}
	scan.StatusPriority = db.StatusPriorityFor(scan.Status)
	if saveErr := w.DB.Save(scan).Error; saveErr != nil {
		return saveErr
	}
	w.maybeFireScanFinalized(scan, err)
	if _, isAccountErr := errors.AsType[*ClaudeAccountError](err); isAccountErr && scan.Status == db.ScanPaused {
		w.pauseQueuedOnAccountError(scan.ID)
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
	_, accountErr := errors.AsType[*ClaudeAccountError](err)
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
		// An account-level problem (usage/credit limit, or access disabled or
		// revoked) is not this scan's fault and retrying cannot succeed until the
		// account recovers, so pause rather than fail: the operator resumes the
		// batch once it does instead of burning a retry per scan. The remaining
		// queued scans are paused by the worker loop (pauseQueuedOnAccountError).
		scan.Status = db.ScanPaused
		emit(Event{Kind: KindError, Text: scan.Error})
	default:
		emit(Event{Kind: KindError, Text: scan.Error})
	}
}

// accountPauseReason is recorded on scans auto-paused because another scan hit
// an account-level Claude problem (a usage/credit limit, or access being
// disabled or revoked). It shares ClaudeAccountPausePrefix with the triggering
// scan's error so the scans page matches both and surfaces them together in the
// account banner.
const accountPauseReason = ClaudeAccountPausePrefix + " Queued scan held automatically; resume once the account recovers."

// pauseQueuedOnAccountError pauses every still-queued scan after one scan hit an
// account-level Claude problem (limit, or access disabled/revoked). It is
// account-wide, so the rest of the queue would only run into the same wall;
// pausing keeps the batch intact for a later resume instead of failing it scan
// by scan. The worker loop drops the now-stale queue jobs when they fire (see
// wrap), exactly as a manual "pause queued" does, so updating the rows here is
// enough.
func (w *Worker) pauseQueuedOnAccountError(triggerID uint) {
	now := time.Now()
	res := w.DB.Model(&db.Scan{}).
		Where("status = ?", db.ScanQueued).
		Updates(map[string]any{
			"status":          db.ScanPaused,
			"status_priority": db.StatusPriorityFor(db.ScanPaused),
			"error":           accountPauseReason,
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
