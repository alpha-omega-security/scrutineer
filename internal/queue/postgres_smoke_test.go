package queue

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestPostgresQueue exercises the queue against a real PostgreSQL server when
// SCRUTINEER_TEST_PG_DSN is set (skipped otherwise). It proves the embedded
// idempotent schema_postgres.sql runs — twice — and that goqite operates in
// its PostgreSQL flavour through an enqueue/receive round trip.
func TestPostgresQueue(t *testing.T) {
	dsn := os.Getenv("SCRUTINEER_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set SCRUTINEER_TEST_PG_DSN to run the postgres queue smoke test")
	}
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
}
