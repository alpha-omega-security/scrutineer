package db

import (
	"math"
	"testing"
)

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

func TestStatusPriority_sortOrder(t *testing.T) {
	gdb, err := Open("file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	defer func() { _ = sqldb.Close() }()

	repo := Repository{URL: "https://example.com/sort-test", Name: "sort-test"}
	gdb.Create(&repo)

	for _, st := range []ScanStatus{ScanDone, ScanRunning, ScanQueued} {
		sc := Scan{RepositoryID: repo.ID, Kind: "skill", Status: st, StatusPriority: StatusPriorityFor(st)}
		gdb.Create(&sc)
	}

	var scans []Scan
	gdb.Order("status_priority, id desc").Find(&scans)
	if len(scans) != 3 {
		t.Fatalf("got %d scans", len(scans))
	}
	if scans[0].Status != ScanRunning {
		t.Errorf("first scan status = %s, want running", scans[0].Status)
	}
	if scans[1].Status != ScanQueued {
		t.Errorf("second scan status = %s, want queued", scans[1].Status)
	}
	if scans[2].Status != ScanDone {
		t.Errorf("third scan status = %s, want done", scans[2].Status)
	}
	for _, sc := range scans {
		t.Logf("id=%d status=%s priority=%d", sc.ID, sc.Status, sc.StatusPriority)
	}
}
