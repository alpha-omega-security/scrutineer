package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"scrutineer/internal/testutil"
)

// TestPostgresQueue exercises the queue against a real PostgreSQL server when
// SCRUTINEER_TEST_PG_DSN is set (skipped otherwise). It proves the embedded
// idempotent schema_postgres.sql runs — twice — and that goqite operates in
// its PostgreSQL flavour through an enqueue/receive round trip.
func TestPostgresQueue(t *testing.T) {
	dsn := testutil.PostgresDSN(t)
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open pgx: %v", err)
	}
	defer func() { _ = sqldb.Close() }()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Build twice: the second New re-runs the schema, asserting idempotency.
	if _, err := New(sqldb, log, 1, Postgres); err != nil {
		t.Fatalf("first New: %v", err)
	}
	q, err := New(sqldb, log, 1, Postgres)
	if err != nil {
		t.Fatalf("second New (idempotency): %v", err)
	}

	if err := q.Enqueue(context.Background(), "test-job", 42, 0); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	received := make(chan Payload, 1)
	q.Register("test-job", func(_ context.Context, body []byte) error {
		var payload Payload
		if err := json.Unmarshal(body, &payload); err != nil {
			return err
		}
		received <- payload
		return nil
	})
	done := make(chan struct{})
	go func() { q.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case payload := <-received:
		if payload.ScanID != 42 {
			t.Fatalf("scan id = %d", payload.ScanID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("queued job was not dispatched")
	}
}
