package queue

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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

// A DBA-provisioned role often has CREATE on the schema but not on the
// database, so the schema must not need CREATE EXTENSION.
func TestPostgresQueueSchemaOnlyRole(t *testing.T) {
	dsn := testutil.PostgresDSN(t)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	role := "scrutineer_schema_only_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, stmt := range []string{
		fmt.Sprintf("CREATE ROLE %q LOGIN PASSWORD 'schema-only'", role),
		fmt.Sprintf("GRANT USAGE, CREATE ON SCHEMA public TO %q", role),
	} {
		if _, err := admin.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(fmt.Sprintf("DROP OWNED BY %q", role))
		_, _ = admin.Exec(fmt.Sprintf("DROP ROLE %q", role))
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "schema-only")
	restricted, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restricted.Close() }()
	if _, err := New(restricted, slog.New(slog.NewTextHandler(io.Discard, nil)), 1, Postgres); err != nil {
		t.Fatalf("New as schema-only role: %v", err)
	}
}
