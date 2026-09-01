// Package dbtest opens per-test SQLite databases from a cached template
// image, avoiding a full GORM AutoMigrate on every test. AutoMigrate for
// the ~30 scrutineer models costs ~265ms under -race (checkptr + TSAN over
// modernc.org/sqlite's transpiled unsafe pointer arithmetic); at ~700 test
// servers in internal/web that dominates the package's runtime. Writing a
// pre-migrated database file and opening it per test skips both GORM's
// reflection and the DDL execution, at ~20ms/call.
//
// SQLite-only by design: unit tests run on SQLite regardless of the
// production dialect. Postgres coverage lives in the separate opt-in
// smoke tests.
package dbtest

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const dbFilePerm = 0o600

var template = sync.OnceValue(func() []byte {
	gdb, err := db.Open("file::memory:")
	if err != nil {
		panic("dbtest: capture schema: " + err.Error())
	}
	defer func() {
		if sqldb, _ := gdb.DB(); sqldb != nil {
			_ = sqldb.Close()
		}
	}()
	path := filepath.Join(os.TempDir(), fmt.Sprintf("dbtest-template-%d.db", os.Getpid()))
	_ = os.Remove(path)
	if err := gdb.Exec("VACUUM INTO ?", path).Error; err != nil {
		panic("dbtest: vacuum template: " + err.Error())
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		panic("dbtest: read template: " + err.Error())
	}
	_ = os.Remove(path)
	return buf
})

// Open returns a fresh file-backed *gorm.DB with the full scrutineer schema
// already applied, and registers a cleanup to close it. Each call writes
// its own copy of the template into tb.TempDir, so repeated calls in one
// test and t.Parallel tests do not share state.
func Open(tb testing.TB) *gorm.DB {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "dbtest.db")
	if err := os.WriteFile(path, template(), dbFilePerm); err != nil {
		tb.Fatalf("dbtest: write template: %v", err)
	}
	gdb, err := db.Connect(path)
	if err != nil {
		tb.Fatalf("dbtest: connect: %v", err)
	}
	tb.Cleanup(func() {
		if sqldb, _ := gdb.DB(); sqldb != nil {
			_ = sqldb.Close()
		}
	})
	return gdb
}
