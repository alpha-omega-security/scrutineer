// Package dbtest opens per-test in-memory SQLite databases with the schema
// pre-applied from a cached DDL snapshot, avoiding a full GORM AutoMigrate
// on every test. AutoMigrate for the ~30 scrutineer models costs ~265ms
// under -race (checkptr + TSAN over modernc.org/sqlite's transpiled unsafe
// pointer arithmetic); at ~700 test servers in internal/web that dominates
// the package's runtime. Replaying the captured DDL as one batch skips the
// GORM reflection pass.
//
// SQLite-only by design: unit tests run on in-memory SQLite regardless of
// the production dialect. Postgres coverage lives in the separate opt-in
// smoke tests.
package dbtest

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

var schema = sync.OnceValue(func() string {
	gdb, err := db.Open("file::memory:")
	if err != nil {
		panic("dbtest: capture schema: " + err.Error())
	}
	defer func() {
		if sqldb, _ := gdb.DB(); sqldb != nil {
			_ = sqldb.Close()
		}
	}()
	var stmts []string
	if err := gdb.Raw(
		"SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'",
	).Scan(&stmts).Error; err != nil {
		panic("dbtest: read schema: " + err.Error())
	}
	return strings.Join(stmts, ";\n") + ";"
})

var seq atomic.Uint64

// Open returns a fresh in-memory *gorm.DB with the full scrutineer schema
// already applied, and registers a cleanup to close it. Each call gets its
// own named in-memory database so repeated calls within one test, and
// t.Parallel tests, do not share state.
func Open(tb testing.TB) *gorm.DB {
	tb.Helper()
	dsn := fmt.Sprintf("file:dbtest%d?mode=memory&cache=shared", seq.Add(1))
	gdb, err := db.Connect(dsn)
	if err != nil {
		tb.Fatalf("dbtest: connect: %v", err)
	}
	if err := gdb.Exec(schema()).Error; err != nil {
		tb.Fatalf("dbtest: apply schema: %v", err)
	}
	tb.Cleanup(func() {
		if sqldb, _ := gdb.DB(); sqldb != nil {
			_ = sqldb.Close()
		}
	})
	return gdb
}
