package worker

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/reflection"
	"scrutineer/internal/testutil"
)

func TestPostgresReflection(t *testing.T) {
	gdb, err := db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: testutil.PostgresDSN(t)})
	if err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q, err := queue.New(sqldb, log, 1, queue.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	testReflectionWindows(t, &Worker{DB: gdb, Log: log, Queue: q})
}

func TestSQLiteReflectionWindows(t *testing.T) {
	testReflectionWindows(t, newPreflightWorker(t))
}

func testReflectionWindows(t *testing.T, w *Worker) {
	t.Helper()
	w, scan, child := reflectionFixtureFor(t, w)
	log := "error: HEAD\n" + strings.Repeat("x", 2*reflection.Window) + "\nTAIL"
	if err := w.DB.Model(child).Updates(map[string]any{"log": log, "commit": "abc123"}).Error; err != nil {
		t.Fatal(err)
	}
	if pending, err := w.prepareReflection(scan); err != nil || pending {
		t.Fatalf("prepareReflection: pending=%v err=%v", pending, err)
	}
	var input reflection.Input
	if err := json.Unmarshal(scan.ImportPayload, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Sources) != 1 {
		t.Fatalf("sources = %+v", input.Sources)
	}
	source := input.Sources[0]
	if source.Commit != "abc123" || !source.Truncated || !strings.Contains(source.Excerpt, "HEAD") || !strings.Contains(source.Excerpt, "TAIL") {
		t.Fatalf("source = commit %q truncated %v excerpt %d bytes", source.Commit, source.Truncated, len(source.Excerpt))
	}
}
