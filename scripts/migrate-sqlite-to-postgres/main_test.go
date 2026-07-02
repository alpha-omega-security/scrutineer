package main

import (
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

// TestMigrate is a live end-to-end check: it seeds a temp SQLite database
// (including the scans<->findings foreign-key cycle and both many-to-many
// join tables), migrates it into a real PostgreSQL server, and verifies the
// row counts and key relationships survive. It is skipped unless
// SCRUTINEER_TEST_PG_DSN points at an empty-or-forceable Postgres.
func TestMigrate(t *testing.T) {
	dsn := os.Getenv("SCRUTINEER_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("set SCRUTINEER_TEST_PG_DSN to run the migrator integration test")
	}

	// Seed a SQLite source.
	srcPath := filepath.Join(t.TempDir(), "scrutineer.db")
	src, err := db.Open(srcPath)
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	repo := db.Repository{
		URL:  "https://example.com/repo",
		Name: "repo",
		Maintainers: []db.Maintainer{ // many2many -> repository_maintainers
			{Login: "alice"}, {Login: "bob"},
		},
	}
	must(t, src.Create(&repo).Error)
	scan := db.Scan{RepositoryID: repo.ID, Commit: "abc123", Status: db.ScanDone}
	must(t, src.Create(&scan).Error)
	finding := db.Finding{
		ScanID: scan.ID,
		Title:  "example",
		Labels: []db.FindingLabel{{Name: "triage"}}, // many2many -> finding_labels_join
	}
	must(t, src.Create(&finding).Error)
	// Close the scans<->findings cycle: a finding-scoped scan pointing back.
	fScan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, FindingID: &finding.ID}
	must(t, src.Create(&fScan).Error)
	must(t, src.Create(&db.Setting{Key: "concurrency", Value: "4"}).Error)

	// Migrate into the empty Postgres.
	if err := run(srcPath, dsn, false); err != nil {
		t.Fatalf("run migrate: %v", err)
	}

	dst, err := db.OpenBackend(db.Options{Dialect: db.DialectPostgres, DSN: dsn})
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}

	// Row counts survived.
	for _, tc := range []struct {
		model any
		want  int64
	}{
		{&db.Repository{}, 1}, {&db.Scan{}, 2}, {&db.Finding{}, 1},
		{&db.Maintainer{}, 2}, {&db.FindingLabel{}, 1}, {&db.Setting{}, 1},
	} {
		var n int64
		must(t, dst.Model(tc.model).Count(&n).Error)
		if n != tc.want {
			t.Errorf("%T count = %d, want %d", tc.model, n, tc.want)
		}
	}

	// Join tables survived.
	for _, jt := range []struct {
		table string
		want  int64
	}{{"repository_maintainers", 2}, {"finding_labels_join", 1}} {
		var n int64
		must(t, dst.Table(jt.table).Count(&n).Error)
		if n != jt.want {
			t.Errorf("%s count = %d, want %d", jt.table, n, jt.want)
		}
	}

	// The FK-cycle edge survived: the finding-scoped scan still points at the
	// finding, and the reserved-word commit column round-tripped.
	var gotScan db.Scan
	must(t, dst.First(&gotScan, fScan.ID).Error)
	if gotScan.FindingID == nil || *gotScan.FindingID != finding.ID {
		t.Errorf("finding-scoped scan lost its FindingID: got %v, want %d", gotScan.FindingID, finding.ID)
	}
	var origScan db.Scan
	must(t, dst.First(&origScan, scan.ID).Error)
	if origScan.Commit != "abc123" {
		t.Errorf("commit round-trip = %q, want abc123", origScan.Commit)
	}

	// Sequence was reset: a fresh insert must not collide with imported ids.
	newRepo := db.Repository{URL: "https://example.com/after", Name: "after"}
	must(t, dst.Create(&newRepo).Error)
	if newRepo.ID <= repo.ID {
		t.Errorf("new repo id %d did not advance past imported max %d (sequence not reset)", newRepo.ID, repo.ID)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
