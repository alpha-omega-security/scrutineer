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
	"time"

	"maragu.dev/goqite"
	"maragu.dev/goqite/jobs"
)

//go:embed schema_sqlite.sql
var schema string

// Payload is what travels on the queue. The job handler looks up the Scan
// row by ID; everything else (repo URL, kind) hangs off that record so the
// queue message stays small and the DB is the source of truth.
type Payload struct {
	ScanID uint `json:"scan_id"`
}

type Queue struct {
	q      *goqite.Queue
	runner *jobs.Runner
}

const (
	visibilityTimeout        = 30 * time.Second
	DefaultWorkerConcurrency = 4
)

// New builds a queue wired to goqite. concurrency controls how many jobs
// the runner processes in parallel; pass 0 to use DefaultWorkerConcurrency.
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
	r := jobs.NewRunner(jobs.NewRunnerOpts{
		Queue:        q,
		Log:          slogAdapter{log},
		Limit:        concurrency,
		PollInterval: time.Second,
		Extend:       visibilityTimeout,
	})
	return &Queue{q: q, runner: r}, nil
}

func (q *Queue) Register(name string, fn jobs.Func) {
	q.runner.Register(name, fn)
}

func (q *Queue) Start(ctx context.Context) {
	q.runner.Start(ctx)
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

// slogAdapter satisfies goqite's logger interface using slog.
type slogAdapter struct{ l *slog.Logger }

func (s slogAdapter) Info(msg string, args ...any) { s.l.Info(msg, args...) }
