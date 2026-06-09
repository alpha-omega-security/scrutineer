// Package queue wraps goqite so the rest of the app deals in Scan IDs
// rather than message bodies, and so the schema lives in one place.
package queue

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"maragu.dev/goqite"
	"maragu.dev/goqite/jobs"
)

//go:embed schema_sqlite.sql
var schema string

// Payload is what travels on the queue. The job handler looks up the Scan
// row by ID; everything else (repo URL, kind) hangs off that record so the
// queue message stays small and the DB is the source of truth.
//
// Attempt counts re-enqueues from the prereq gate (worker.preflightSkill).
// It is zero on first dispatch and increments each time a skill's required
// upstream scans were not yet done. The worker caps the count so a missing
// prereq fails the scan instead of looping forever.
type Payload struct {
	ScanID  uint `json:"scan_id"`
	Attempt int  `json:"attempt,omitempty"`
}

type Queue struct {
	q   *goqite.Queue
	log *slog.Logger

	// concurrency is atomic so Concurrency() (read by the settings page) never
	// blocks on mu while Reconfigure holds it for the duration of a runner
	// swap (which includes the cancelled scan's teardown).
	concurrency atomic.Int64

	mu        sync.Mutex
	runner    *jobs.Runner
	handlers  map[string]jobs.Func
	parentCtx context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

const (
	visibilityTimeout        = 30 * time.Second
	DefaultWorkerConcurrency = 4
)

// New builds a queue wired to goqite. concurrency controls how many jobs
// the runner processes in parallel; pass 0 to use DefaultWorkerConcurrency.
// The runner itself is built lazily in Start (and rebuilt by Reconfigure).
func New(sqldb *sql.DB, log *slog.Logger, concurrency int) (*Queue, error) {
	if concurrency <= 0 {
		concurrency = DefaultWorkerConcurrency
	}
	if _, err := sqldb.Exec(schema); err != nil {
		return nil, fmt.Errorf("goqite schema: %w", err)
	}
	q := goqite.New(goqite.NewOpts{
		DB:      sqldb,
		Name:    "scans",
		Timeout: visibilityTimeout,
	})
	queue := &Queue{q: q, log: log, handlers: map[string]jobs.Func{}}
	queue.concurrency.Store(int64(concurrency))
	return queue, nil
}

// Concurrency reports the parallelism limit the runner is currently using.
func (q *Queue) Concurrency() int {
	return int(q.concurrency.Load())
}

func (q *Queue) Register(name string, fn jobs.Func) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.handlers[name] = fn
}

// Start runs the job runner until ctx is cancelled, then waits for in-flight
// jobs to drain. ctx is retained as the parent for every runner instance, so
// a runner spawned by Reconfigure also dies with the process.
func (q *Queue) Start(ctx context.Context) {
	q.mu.Lock()
	q.parentCtx = ctx
	q.startRunnerLocked()
	q.mu.Unlock()

	<-ctx.Done()
	q.wg.Wait()
}

// startRunnerLocked builds a fresh goqite runner at the current concurrency,
// registers the known handlers, and starts it on a child of parentCtx. The
// caller must hold q.mu.
func (q *Queue) startRunnerLocked() {
	r := jobs.NewRunner(jobs.NewRunnerOpts{
		Queue:        q.q,
		Log:          slogAdapter{q.log},
		Limit:        int(q.concurrency.Load()),
		PollInterval: time.Second,
		Extend:       visibilityTimeout,
	})
	for name, fn := range q.handlers {
		r.Register(name, fn)
	}
	ctx, cancel := context.WithCancel(q.parentCtx)
	q.runner = r
	q.cancel = cancel
	q.wg.Go(func() { r.Start(ctx) })
}

// Reconfigure swaps the runner for one with a new parallelism limit without
// restarting the process. goqite fixes the limit at construction, so the only
// way to change it live is to stand up a new runner: the current one is
// cancelled first, which aborts in-flight jobs (their context derives from the
// runner's). Queued jobs are untouched and the fresh runner picks them up.
// Calling before Start just records the value, applied when Start builds the
// first runner.
func (q *Queue) Reconfigure(concurrency int) {
	if concurrency <= 0 {
		concurrency = DefaultWorkerConcurrency
	}
	q.concurrency.Store(int64(concurrency))
	q.mu.Lock()
	defer q.mu.Unlock()
	// Not started yet (value is recorded, applied when Start builds the first
	// runner), or shutting down: bail before touching the runner. During
	// shutdown Start is running its own q.wg.Wait(); spawning a runner here
	// would Add to the WaitGroup mid-Wait and panic, and a new runner would be
	// pointless anyway. The post-drain re-check catches a shutdown that begins
	// while we drain.
	if q.parentCtx == nil || q.parentCtx.Err() != nil {
		return
	}
	q.cancel()
	q.wg.Wait()
	if q.parentCtx.Err() != nil {
		return
	}
	q.startRunnerLocked()
}

// Enqueue puts a job on the queue. Higher priority is received first; use 0
// for long-running scans and >0 for quick housekeeping that should jump them.
func (q *Queue) Enqueue(ctx context.Context, jobName string, scanID uint, priority int) error {
	body, err := json.Marshal(Payload{ScanID: scanID})
	if err != nil {
		return err
	}
	_, err = jobs.Create(ctx, q.q, jobName, goqite.Message{Body: body, Priority: priority})
	return err
}

// EnqueueRetry re-puts a job on the queue with an attempt count and a delay
// before it becomes visible. Used by the prereq gate to back off a scan
// whose upstream skills have not yet completed.
func (q *Queue) EnqueueRetry(ctx context.Context, jobName string, scanID uint, priority, attempt int, delay time.Duration) error {
	body, err := json.Marshal(Payload{ScanID: scanID, Attempt: attempt})
	if err != nil {
		return err
	}
	_, err = jobs.Create(ctx, q.q, jobName, goqite.Message{Body: body, Priority: priority, Delay: delay})
	return err
}

// slogAdapter satisfies goqite's logger interface using slog.
type slogAdapter struct{ l *slog.Logger }

func (s slogAdapter) Info(msg string, args ...any) { s.l.Info(msg, args...) }
