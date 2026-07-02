package db

import (
	"os"
	"testing"
)

// TestPostgresBackend is a live integration check against a real PostgreSQL
// server. It is skipped unless SCRUTINEER_TEST_PG_DSN points at one, so the
// normal `go test ./...` run (SQLite only) is unaffected. It proves the
// dialect-portable path: OpenBackend runs AutoMigrate on Postgres and the
// shared models round-trip.
func TestPostgresBackend(t *testing.T) {
	dsn := os.Getenv("SCRUTINEER_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set SCRUTINEER_TEST_PG_DSN to run the postgres backend smoke test")
	}

	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: dsn})
	if err != nil {
		t.Fatalf("OpenBackend postgres: %v", err)
	}
	if name := gdb.Dialector.Name(); name != "postgres" {
		t.Fatalf("dialector name = %q, want postgres", name)
	}

	// Start clean so the test is rerunnable: the URL has a unique index, and
	// the delete cascades to scans/findings via the FK constraints the
	// postgres two-pass migration added.
	const repoURL = "https://example.com/pg/repo"
	if err := gdb.Where("url = ?", repoURL).Delete(&Repository{}).Error; err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// Write and read back through a shared model, including the reserved-word
	// "commit" column, to confirm AutoMigrate produced a usable schema.
	repo := Repository{URL: repoURL, Name: "pg-repo"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatalf("create repository: %v", err)
	}
	scan := Scan{RepositoryID: repo.ID, Commit: "deadbeef", Status: ScanDone}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatalf("create scan: %v", err)
	}

	var got Scan
	if err := gdb.First(&got, scan.ID).Error; err != nil {
		t.Fatalf("read scan: %v", err)
	}
	if got.Commit != "deadbeef" {
		t.Fatalf("commit round-trip = %q, want deadbeef", got.Commit)
	}
}
