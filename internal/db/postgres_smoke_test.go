package db

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/testutil"
)

// TestPostgresBackend is a live integration check against a real PostgreSQL
// server. It is skipped unless SCRUTINEER_TEST_PG_DSN points at one, so the
// normal `go test ./...` run (SQLite only) is unaffected. It proves the
// dialect-portable path: OpenBackend runs AutoMigrate on Postgres and the
// shared models round-trip.
func TestPostgresBackend(t *testing.T) {
	dsn := testutil.PostgresDSN(t)

	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: dsn})
	if err != nil {
		t.Fatalf("OpenBackend postgres: %v", err)
	}
	if name := gdb.Name(); name != "postgres" {
		t.Fatalf("dialector name = %q, want postgres", name)
	}
	closePostgres(t, gdb)

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
	if err := gdb.Model(&scan).Update("log", "before\x00after\xff").Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Log != "beforeafter�" {
		t.Fatalf("scan log = %q", got.Log)
	}
	reopened, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: dsn})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	closePostgres(t, reopened)
}

func closePostgres(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
}

func TestPostgresConcurrentStartup(t *testing.T) {
	dsn := testutil.PostgresDSN(t)
	const count = 4
	results := make(chan error, count)
	var ready sync.WaitGroup
	start := make(chan struct{})
	for range count {
		ready.Add(1)
		go func() {
			ready.Done()
			<-start
			gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: dsn})
			if err == nil {
				sqldb, dbErr := gdb.DB()
				err = dbErr
				if dbErr == nil {
					err = sqldb.Close()
				}
			}
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	for range count {
		if err := <-results; err != nil {
			t.Errorf("concurrent startup: %v", err)
		}
	}
}

func TestPostgresRejectsNewerSchema(t *testing.T) {
	dsn := testutil.PostgresDSN(t)
	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	closePostgres(t, gdb)
	if err := SetSetting(gdb, postgresSchemaVersionKey, fmt.Sprint(databaseSchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	if err := gdb.Migrator().DropColumn(&Repository{}, "description"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: dsn}); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("expected newer schema rejection, got %v", err)
	}
	if gdb.Migrator().HasColumn(&Repository{}, "description") {
		t.Fatal("schema changed before rejecting its version")
	}
}

func TestPostgresFindingTransactionRetry(t *testing.T) {
	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: testutil.PostgresDSN(t)})
	if err != nil {
		t.Fatal(err)
	}
	closePostgres(t, gdb)
	for _, code := range []string{"40001", "40P01"} {
		t.Run(code, func(t *testing.T) {
			attempts := 0
			err := FindingWriteTransaction(gdb, 1, func(tx *gorm.DB) error {
				attempts++
				if err := tx.Create(&Setting{Key: code, Value: fmt.Sprint(attempts)}).Error; err != nil {
					return err
				}
				if attempts == 1 {
					return tx.Exec("DO $$ BEGIN RAISE EXCEPTION 'retry' USING ERRCODE = '" + code + "'; END $$").Error
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if value, ok := GetSetting(gdb, code); !ok || value != "2" || attempts != 2 {
				t.Fatalf("value=%q, attempts=%d", value, attempts)
			}
		})
	}
}
