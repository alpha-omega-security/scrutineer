package queue

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func newTestQueue(t *testing.T, concurrency int) *Queue {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	q, err := New(sqldb, slog.New(slog.NewTextHandler(io.Discard, nil)), concurrency)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestQueue_ReconfigureBeforeStart(t *testing.T) {
	q := newTestQueue(t, 4)
	if q.Concurrency() != 4 {
		t.Fatalf("initial concurrency = %d, want 4", q.Concurrency())
	}
	q.Reconfigure(8)
	if q.Concurrency() != 8 {
		t.Errorf("after Reconfigure(8) = %d, want 8", q.Concurrency())
	}
	q.Reconfigure(0) // non-positive clamps to the built-in default
	if q.Concurrency() != DefaultWorkerConcurrency {
		t.Errorf("after Reconfigure(0) = %d, want %d", q.Concurrency(), DefaultWorkerConcurrency)
	}
}

// TestQueue_ReconfigureDuringShutdown covers the guard that keeps Reconfigure
// from spawning a runner (and Add-ing to the WaitGroup) once the parent ctx is
// cancelled, which would panic against Start's shutdown Wait. After shutdown it
// must be a safe no-op that still records the requested value.
func TestQueue_ReconfigureDuringShutdown(t *testing.T) {
	q := newTestQueue(t, 2)
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{}, 1)
	q.Register("job", func(c context.Context, _ []byte) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-c.Done()
		return nil
	})

	startReturned := make(chan struct{})
	go func() { q.Start(ctx); close(startReturned) }()
	if err := q.Enqueue(ctx, "job", 1, 0); err != nil {
		t.Fatal(err)
	}
	waitChan(t, started, "runner never started")

	cancel() // simulate process shutdown: Start drains then returns
	select {
	case <-startReturned:
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after shutdown")
	}

	q.Reconfigure(7) // must not panic, and records the value without a new runner
	if q.Concurrency() != 7 {
		t.Errorf("Concurrency = %d, want 7", q.Concurrency())
	}
}

// TestQueue_ReconfigureLive proves the headline behaviour: changing the limit
// while running cancels the in-flight job, applies the new limit, and the
// fresh runner keeps processing newly enqueued jobs.
func TestQueue_ReconfigureLive(t *testing.T) {
	q := newTestQueue(t, 1)

	started := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	processed := make(chan uint, 4)
	q.Register("job", func(ctx context.Context, body []byte) error {
		var p Payload
		_ = json.Unmarshal(body, &p)
		if p.ScanID == 1 {
			started <- struct{}{}
			<-ctx.Done() // block until the runner is torn down
			cancelled <- struct{}{}
			return nil // return nil so goqite drops the message (no retry loop)
		}
		processed <- p.ScanID
		return nil
	})

	ctx := t.Context()
	go q.Start(ctx)

	if err := q.Enqueue(ctx, "job", 1, 0); err != nil {
		t.Fatal(err)
	}
	waitChan(t, started, "in-flight job never started")

	q.Reconfigure(3)
	waitChan(t, cancelled, "in-flight job was not cancelled by Reconfigure")
	if q.Concurrency() != 3 {
		t.Errorf("concurrency after Reconfigure = %d, want 3", q.Concurrency())
	}

	if err := q.Enqueue(ctx, "job", 2, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-processed:
		if got != 2 {
			t.Errorf("processed scan %d, want 2", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fresh runner did not process the job enqueued after Reconfigure")
	}
}

func waitChan(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal(msg)
	}
}
