package worker

import (
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

// TestQueueDepthAcrossWorkerPauses pins that the account-error and overage
// pauses read as not queued until the auto-resume, and that the auto-resume
// leaves the hours before the pause unchanged.
func TestQueueDepthAcrossWorkerPauses(t *testing.T) {
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	resumeAt := t0.Add(4 * time.Hour)
	for name, pause := range map[string]func(*testing.T, *Worker){
		"account error": func(t *testing.T, w *Worker) {
			w.pauseQueuedOnAccountError(0)
			if err := w.DB.Model(&db.Scan{}).Where("status = ?", db.ScanPaused).Update("paused_until", resumeAt).Error; err != nil {
				t.Fatal(err)
			}
		},
		"overage": func(t *testing.T, w *Worker) {
			if err := w.pauseOverageRows(&resumeAt); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			gdb := dbtest.Open(t)
			clock := t0
			gdb.NowFunc = func() time.Time { return clock }
			sqldb, err := gdb.DB()
			if err != nil {
				t.Fatal(err)
			}
			q, err := queue.New(sqldb, slog.New(slog.NewTextHandler(io.Discard, nil)), 1, queue.SQLite)
			if err != nil {
				t.Fatal(err)
			}
			w := &Worker{DB: gdb, Queue: q, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return clock }}
			repo := db.Repository{URL: "https://example.com/queue-depth", Name: "queue-depth"}
			gdb.Create(&repo)
			gdb.Create(&db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued})

			clock = t0.Add(2 * time.Hour)
			pause(t, w)
			before := queuedPerHour(t, w, t0)
			clock = resumeAt
			if n, err := w.resumeAccountPaused(t.Context()); err != nil || n != 1 {
				t.Fatalf("resumed %d, err %v", n, err)
			}
			after := queuedPerHour(t, w, t0)

			if want := []int{1, 1, 0, 0, 0, 0}; !slices.Equal(before, want) {
				t.Errorf("while paused = %v, want %v", before, want)
			}
			if want := []int{1, 1, 0, 0, 1, 1}; !slices.Equal(after, want) {
				t.Errorf("after resume = %v, want %v", after, want)
			}
		})
	}
}

func queuedPerHour(t *testing.T, w *Worker, from time.Time) []int {
	t.Helper()
	points, err := db.QueueDepth(w.DB, from, from.Add(5*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var queued []int
	for _, p := range points {
		queued = append(queued, p.Queued)
	}
	return queued
}
