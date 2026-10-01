package testutil

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresDSN creates an isolated database and drops it when the test ends.
func PostgresDSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv("SCRUTINEER_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set SCRUTINEER_TEST_PG_DSN to run PostgreSQL integration tests")
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := "scrutineer_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(fmt.Sprintf("CREATE DATABASE %q", name)); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(fmt.Sprintf("DROP DATABASE %q WITH (FORCE)", name)); err != nil {
			t.Errorf("drop test database: %v", err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		u.Path = "/" + name
		query := u.Query()
		query.Del("dbname")
		u.RawQuery = query.Encode()
		return u.String()
	}
	return dsn + " dbname=" + name
}
