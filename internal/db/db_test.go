package db

import (
	"math"
	"testing"
)

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

func TestNameFromURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/foo/bar":     "bar",
		"https://github.com/foo/bar.git": "bar",
		"https://github.com/foo/bar/":    "bar",
		"git@github.com:foo/bar.git":     "bar",
		"ssh://git@host.xz/path/to/repo": "repo",
		"https://gitlab.com/g/sub/proj":  "proj",
		"":                               "repo",
	}
	for in, want := range cases {
		if got := NameFromURL(in); got != want {
			t.Errorf("NameFromURL(%q) = %q, want %q", in, got, want)
		}
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
}
