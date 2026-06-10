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

// defaultLogFlushInterval bounds how long a scan's log can lag behind the
// in-memory accumulator. Each emitted event used to UPDATE the whole
// scans.log TEXT column, so a token-heavy scan fired thousands of full
// rewrites; batching to once every couple of seconds collapses that to a
// trickle. Real-time UI updates flow through publish() on every event and
// are independent of this cadence; wrap()'s closing Save flushes the
// final buffered tail regardless of how long ago the last write was.
const defaultLogFlushInterval = 2 * time.Second

type Worker struct {
	DB          *gorm.DB
	Log         *slog.Logger
	DataDir     string // workspace root for clones
	APIBase     string // base URL for the scrutineer skill API (http://host:port/api)
	ForkOrg     string // github org the fork skill targets; empty disables it
	Runner      SkillRunner
	OnEvent     func(scanID, repoID uint, name, data string) // optional SSE bridge
	ScanTimeout time.Duration
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
// for this scan's lineage. The docker runner mounts it as CLAUDE_CONFIG_DIR
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
// session store for scanID. A terminal scan removes its own workspace and a
// done scan its session store, so this reclaims space left by scans still
// holding a workspace (queued/running, or crashed before cleanup) and by
// failed scans whose session store is kept for --resume. It is a no-op when
// the directories are already gone. Passing every scan id of a repository
// covers resume lineages too: a retry reuses its root's workspace id, and the
// root scan is itself in the repo, while the retry's own id maps to a
// directory that was never created.
func (w *Worker) RemoveScanArtifacts(scanID uint) error {
	return errors.Join(
		os.RemoveAll(w.workRoot(scanID)),
		os.RemoveAll(w.claudeConfigDirID(scanID)),
	)
}

// applyResume fills a SkillJob's session-resume inputs from the scan: the
// claude session id to --resume (set on a retry that carries one forward
// from a failed run) and the persistent config dir the docker runner mounts
// so the session store survives a container exit. A fresh scan has an empty
// SessionID, so the runner just starts a new conversation.
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
			scan.CostUSD = e.CostUSD
			scan.Turns = e.Turns
			scan.InputTokens = e.Usage.InputTokens
			scan.OutputTokens = e.Usage.OutputTokens
			scan.CacheReadTokens = e.Usage.CacheReadTokens
			scan.CacheWriteTokens = e.Usage.CacheWriteTokens
		}
		w.publish(scan.ID, scan.RepositoryID, "scan-log", line+"\n")
	}
}

// clearSessionStore wipes a finished scan's resume state so its next
// deliberate re-run starts fresh: it drops the session id and tears down the
// persisted claude session store. Only called on "done" — a failed scan
// keeps both so a UI retry can --resume instead of restarting from turn 0.
func (w *Worker) clearSessionStore(scan *db.Scan) {
	scan.SessionID = ""
	if rmErr := os.RemoveAll(w.claudeConfigDir(scan)); rmErr != nil {
		w.Log.Warn("session store cleanup failed", "scan", scan.ID, "err", rmErr)
	}
}

func (w *Worker) Register(q *queue.Queue) {
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

		emit := w.scanEmitter(&scan)

		report, err := h(ctx, &scan, emit)

		finishScan(ctx, &scan, report, err, timeout, emit)
		if scan.Status == db.ScanDone {
			w.clearSessionStore(&scan)
		}
		scan.StatusPriority = db.StatusPriorityFor(scan.Status)
		if saveErr := w.DB.Save(&scan).Error; saveErr != nil {
			return saveErr
		}
		if scan.Status.Terminal() {
			if rmErr := os.RemoveAll(w.scanWorkRoot(&scan)); rmErr != nil {
				w.Log.Warn("workspace cleanup failed", "scan", scan.ID, "err", rmErr)
			}
		}
		w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
		w.Log.Info("job finished", "scan", scan.ID, "kind", scan.Kind, "status", scan.Status)
		return nil
	}
}

func finishScan(ctx context.Context, scan *db.Scan, report string, err error, timeout time.Duration, emit func(Event)) {
	scan.FinishedAt = new(time.Now())
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
	_, planLimit := errors.AsType[*ClaudePlanLimitError](err)
	switch {
	case maxTurns:
		scan.Status = db.ScanDone
		scan.Report = report
		scan.Error = ""
		emit(Event{Kind: KindText, Text: "scan completed (hit max turns cap)"})
	case failOnThreshold:
		scan.Report = report
		emit(Event{Kind: KindError, Text: scan.Error})
	case schemaValidation:
		scan.Report = report
	case planLimit:
		emit(Event{Kind: KindError, Text: scan.Error})
	default:
		emit(Event{Kind: KindError, Text: scan.Error})
	}
}
