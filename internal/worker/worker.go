// Package worker holds the queue handler that runs skill scans. Jobs are
// dispatched by name through goqite; every scan is a skill-driven scan.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

const (
	JobSkill = "skill"

	PrioScan     = 0
	PrioTool     = 5
	PrioFastTool = 8
	PrioMetadata = 10
)

type Worker struct {
	DB      *gorm.DB
	Log     *slog.Logger
	DataDir string // workspace root for clones
	APIBase string // base URL for the scrutineer skill API (http://host:port/api)
	Runner  SkillRunner
	OnEvent func(scanID, repoID uint, name, data string) // optional SSE bridge

	mu      sync.Mutex
	running map[uint]context.CancelFunc
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

func (w *Worker) Register(q *queue.Queue) {
	q.Register(JobSkill, w.wrap(w.doSkill))
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
		if scan.Status.Terminal() {
			w.Log.Info("dropping stale job", "scan", scan.ID, "status", scan.Status)
			return nil
		}

		ctx, cancel := context.WithCancel(ctx)
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

		now := time.Now()
		scan.Status = db.ScanRunning
		scan.StartedAt = &now
		scan.Log = ""
		scan.Error = ""
		if err := w.DB.Save(&scan).Error; err != nil {
			return err
		}

		emit := func(e Event) {
			line := FormatEvent(e)
			scan.Log += line + "\n"
			w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("log", scan.Log)
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

		report, err := h(ctx, &scan, emit)

		fin := time.Now()
		scan.FinishedAt = &fin
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			scan.Status = db.ScanCancelled
			scan.Error = "cancelled by user"
			emit(Event{Kind: KindError, Text: "cancelled by user"})
		case err != nil:
			scan.Status = db.ScanFailed
			scan.Error = err.Error()
			emit(Event{Kind: KindError, Text: err.Error()})
		default:
			scan.Status = db.ScanDone
			scan.Report = report
		}
		if saveErr := w.DB.Save(&scan).Error; saveErr != nil {
			return saveErr
		}
		w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
		w.Log.Info("job finished", "scan", scan.ID, "kind", scan.Kind, "status", scan.Status)
		return nil
	}
}
