package db

import (
	"context"
	"database/sql"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLStringLiteral(t *testing.T) {
	cases := []struct{ in, want string }{
		{"security-deep-dive", "'security-deep-dive'"},
		{"", "''"},
		{"o'brien", "'o''brien'"},
		{"a'b'c", "'a''b''c'"},
		{"'; DROP TABLE findings;--", "'''; DROP TABLE findings;--'"},
	}
	for _, c := range cases {
		if got := SQLStringLiteral(c.in); got != c.want {
			t.Errorf("SQLStringLiteral(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSnapshot(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	gdb, err := Open(src)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the source open across Snapshot to mirror a live server holding
	// the DB: Snapshot must still produce a usable copy via a second conn.
	defer func() {
		if sqldb, err := gdb.DB(); err == nil {
			_ = sqldb.Close()
		}
	}()
	if err := gdb.Exec("CREATE TABLE probe(v INTEGER)").Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Exec("INSERT INTO probe(v) VALUES (4242)").Error; err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "snap.db")
	if err := Snapshot(src, dest); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	snap, err := Open(dest)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	var v int
	if err := snap.Raw("SELECT v FROM probe").Scan(&v).Error; err != nil {
		t.Fatalf("read probe from snapshot: %v", err)
	}
	if v != 4242 {
		t.Errorf("probe = %d, want 4242", v)
	}
}

func TestSnapshot_destExists(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	if _, err := Open(src); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "snap.db")
	if err := os.WriteFile(dest, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Snapshot(src, dest); err == nil {
		t.Error("Snapshot to an existing dest should fail")
	}
}

func TestRepositoryIsLocal(t *testing.T) {
	cases := []struct {
		url      string
		local    bool
		wantPath string
	}{
		{"https://github.com/foo/bar", false, ""},
		{"file:///srv/projects/x", true, "/srv/projects/x"},
		{"", false, ""},
	}
	for _, tc := range cases {
		r := Repository{URL: tc.url}
		if got := r.IsLocal(); got != tc.local {
			t.Errorf("IsLocal(%q) = %v, want %v", tc.url, got, tc.local)
		}
		if got := r.LocalPath(); got != tc.wantPath {
			t.Errorf("LocalPath(%q) = %q, want %q", tc.url, got, tc.wantPath)
		}
	}
}

func TestFindingLocationList(t *testing.T) {
	var empty Finding
	if empty.LocationList() != nil || empty.ExtraLocationCount() != 0 {
		t.Errorf("empty Locations: list=%v extra=%d", empty.LocationList(), empty.ExtraLocationCount())
	}

	one := Finding{Locations: "a.go:1"}
	if got := one.LocationList(); len(got) != 1 || got[0] != "a.go:1" {
		t.Errorf("single: %v", got)
	}
	if one.ExtraLocationCount() != 0 {
		t.Errorf("single ExtraLocationCount = %d, want 0", one.ExtraLocationCount())
	}

	many := Finding{Locations: "a.go:1\n b.go:2 \nc.go:3"}
	got := many.LocationList()
	if len(got) != 3 || got[1] != "b.go:2" {
		t.Errorf("many: %v (whitespace should be trimmed)", got)
	}
	if many.ExtraLocationCount() != 2 {
		t.Errorf("many ExtraLocationCount = %d, want 2", many.ExtraLocationCount())
	}
}

func TestScanTokenHelpers(t *testing.T) {
	s := Scan{InputTokens: 100, CacheReadTokens: 800, CacheWriteTokens: 100, OutputTokens: 50}
	if s.TotalInputTokens() != 1000 {
		t.Errorf("TotalInputTokens = %d", s.TotalInputTokens())
	}
	if math.Abs(s.CacheHitRatio()-0.8) > 1e-9 {
		t.Errorf("CacheHitRatio = %v", s.CacheHitRatio())
	}
	var z Scan
	if z.CacheHitRatio() != 0 {
		t.Errorf("zero scan CacheHitRatio = %v", z.CacheHitRatio())
	}
}

func TestScanHasExportableReport(t *testing.T) {
	cases := []struct {
		name string
		s    Scan
		want bool
	}{
		{"empty scan", Scan{}, false},
		{"no findings, empty subprojects-style report", Scan{Report: `{"subprojects": []}`}, false},
		{"no findings, two empty arrays", Scan{Report: `{"packages": [], "advisories": []}`}, false},
		{"no findings, whitespace-padded empty report", Scan{Report: "  \n  {\"x\": []}  \n  "}, false},
		{"no findings, empty string and null values", Scan{Report: `{"x": "", "y": null, "z": {}}`}, false},
		{"findings present overrides shape check", Scan{FindingsCount: 1, Report: "{}"}, true},
		{"single small entry counts as content", Scan{Report: `{"components":[{"name":"foo","version":"1.0"}]}`}, true},
		{"top-level scalars count as content", Scan{Report: `{"version":1,"bomFormat":"CycloneDX"}`}, true},
		{"non-trivial freeform report", Scan{Report: `{"components":[{"name":"foo","version":"1.0","license":"MIT","purl":"pkg:npm/foo"}]}`}, true},
		{"non-object top level falls back to length", Scan{Report: `["a","b","c","d","e","f","g","h"]`}, true},
		{"non-object short report stays hidden", Scan{Report: `[]`}, false},
	}
	for _, tc := range cases {
		if got := tc.s.HasExportableReport(); got != tc.want {
			t.Errorf("%s: HasExportableReport() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestBackfillFindingRepositoryFillsCommit(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	r := Repository{URL: "https://example.com/x", Name: "x"}
	if err := gdb.Create(&r).Error; err != nil {
		t.Fatal(err)
	}
	s := Scan{RepositoryID: r.ID, Kind: "claude", Status: ScanDone, Commit: "deadbeef"}
	if err := gdb.Create(&s).Error; err != nil {
		t.Fatal(err)
	}
	f := Finding{ScanID: s.ID, RepositoryID: r.ID, Title: "t", Severity: "Low"}
	if err := gdb.Create(&f).Error; err != nil {
		t.Fatal(err)
	}

	BackfillFindingRepository(gdb)

	var got Finding
	if err := gdb.First(&got, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Commit != "deadbeef" {
		t.Errorf("Finding.Commit = %q, want %q", got.Commit, "deadbeef")
	}
}

func TestOpenAndMigrate(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	r := Repository{URL: "https://example.com/x", Name: "x"}
	if err := gdb.Create(&r).Error; err != nil {
		t.Fatal(err)
	}
	s := Scan{RepositoryID: r.ID, Kind: "claude", Status: ScanQueued}
	if err := gdb.Create(&s).Error; err != nil {
		t.Fatal(err)
	}
	var got Scan
	if err := gdb.Preload("Repository").First(&got, s.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Repository.URL != r.URL {
		t.Errorf("preload failed: %+v", got.Repository)
	}

	cna := CNA{ShortName: "apache", CNAID: "CNA-2016-0004", Organization: "Apache Software Foundation",
		Scope: "All Apache Software Foundation projects", Email: "security@apache.org"}
	if err := gdb.Create(&cna).Error; err != nil {
		t.Fatalf("create CNA: %v", err)
	}
	if err := gdb.Create(&CNA{ShortName: "apache"}).Error; err == nil {
		t.Errorf("expected unique-index violation on duplicate ShortName")
	}
}

func TestWithPragmas_joinsOnExistingQuery(t *testing.T) {
	cases := map[string]string{
		"data/scrutineer.db":         "data/scrutineer.db?" + connectionPragmas,
		":memory:":                   ":memory:?" + connectionPragmas,
		"file::memory:?cache=shared": "file::memory:?cache=shared&" + connectionPragmas,
	}
	for in, want := range cases {
		if got := withPragmas(in); got != want {
			t.Errorf("withPragmas(%q) = %q, want %q", in, got, want)
		}
	}
}

// foreign_keys and busy_timeout are per-connection in SQLite. Setting them
// via a single gdb.Exec only configures whichever pooled connection that
// Exec lands on, leaving the rest at the defaults (#457). Open now folds
// the pragmas into the DSN so the driver applies them on every connection
// it opens; this test pulls several distinct connections off the pool and
// checks each one.
func TestOpen_pragmasApplyToEveryConnection(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqldb.Close() }()

	const n = 8
	sqldb.SetMaxOpenConns(n)
	ctx := context.Background()
	conns := make([]*sql.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := sqldb.Conn(ctx)
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	// Holding all n at once forces n distinct connections out of the pool;
	// release them after the loop so each iteration sees a fresh one.
	for i, c := range conns {
		var fk, bt int
		if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatalf("conn %d foreign_keys: %v", i, err)
		}
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&bt); err != nil {
			t.Fatalf("conn %d busy_timeout: %v", i, err)
		}
		if fk != 1 {
			t.Errorf("conn %d: foreign_keys = %d, want 1", i, fk)
		}
		if bt != 5000 {
			t.Errorf("conn %d: busy_timeout = %d, want 5000", i, bt)
		}
		_ = c.Close()
	}
}

func TestStatusPriority_sortOrder(t *testing.T) {
	gdb, err := Open("file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	defer func() { _ = sqldb.Close() }()

	repo := Repository{URL: "https://example.com/sort-test", Name: "sort-test"}
	gdb.Create(&repo)

	for _, st := range []ScanStatus{ScanDone, ScanPaused, ScanRunning, ScanQueued} {
		sc := Scan{RepositoryID: repo.ID, Kind: "skill", Status: st, StatusPriority: StatusPriorityFor(st)}
		gdb.Create(&sc)
	}

	var scans []Scan
	gdb.Order("status_priority, id desc").Find(&scans)
	if len(scans) != 4 {
		t.Fatalf("got %d scans", len(scans))
	}
	if scans[0].Status != ScanRunning {
		t.Errorf("first scan status = %s, want running", scans[0].Status)
	}
	if scans[1].Status != ScanQueued {
		t.Errorf("second scan status = %s, want queued", scans[1].Status)
	}
	if scans[2].Status != ScanPaused {
		t.Errorf("third scan status = %s, want paused", scans[2].Status)
	}
	if scans[3].Status != ScanDone {
		t.Errorf("fourth scan status = %s, want done", scans[3].Status)
	}
	for _, sc := range scans {
		t.Logf("id=%d status=%s priority=%d", sc.ID, sc.Status, sc.StatusPriority)
	}
}
