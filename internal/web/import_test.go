package web

import (
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/ingest"
)

func TestKnownPURLsMatchWithAndWithoutQualifiers(t *testing.T) {
	gdb, err := db.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	defer func() { _ = sqldb.Close() }()
	repo1 := db.Repository{URL: "https://github.com/splitrb/split", Name: "split"}
	repo2 := db.Repository{URL: "https://github.com/ruby/bigdecimal", Name: "bigdecimal"}
	gdb.Create(&repo1)
	gdb.Create(&repo2)

	// Package with qualifier (from gem.coop registry)
	gdb.Create(&db.Package{
		RepositoryID: repo2.ID,
		Name:         "bigdecimal",
		Ecosystem:    "gem",
		PURL:         "pkg:gem/bigdecimal?repository_url=https://gem.coop",
	})
	// Package without qualifier (from rubygems.org)
	gdb.Create(&db.Package{
		RepositoryID: repo2.ID,
		Name:         "bigdecimal",
		Ecosystem:    "gem",
		PURL:         "pkg:gem/bigdecimal",
	})

	// Dependency row from git-pkgs (always bare PURL)
	gdb.Create(&db.Dependency{
		RepositoryID: repo1.ID,
		Name:         "bigdecimal",
		Ecosystem:    "gem",
		PURL:         "pkg:gem/bigdecimal",
	})

	srv := &Server{DB: gdb}
	deps := []DepGroup{
		{Dependency: db.Dependency{PURL: "pkg:gem/bigdecimal"}},
		{Dependency: db.Dependency{PURL: "pkg:gem/bigdecimal?repository_url=https://gem.coop"}},
	}
	knownPURLs := srv.lookupKnownPURLs(deps)

	// bare PURL should resolve to repo2
	if rid := knownPURLs["pkg:gem/bigdecimal"]; rid != repo2.ID {
		t.Errorf("bare PURL: got repo %d, want %d", rid, repo2.ID)
	}
	// qualified PURL should also resolve
	if rid := knownPURLs["pkg:gem/bigdecimal?repository_url=https://gem.coop"]; rid != repo2.ID {
		t.Errorf("qualified PURL: got repo %d, want %d", rid, repo2.ID)
	}
	// unknown PURL should be 0
	if rid := knownPURLs["pkg:gem/nonexistent"]; rid != 0 {
		t.Errorf("unknown PURL: got repo %d, want 0", rid)
	}
}

func TestKnownURLsMatchDependents(t *testing.T) {
	gdb, err := db.Open("file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	defer func() { _ = sqldb.Close() }()

	repo := db.Repository{URL: "https://github.com/ruby/bigdecimal", Name: "bigdecimal"}
	gdb.Create(&repo)

	srv := &Server{DB: gdb}
	dependents := []db.Dependent{
		{RepositoryURL: "https://github.com/ruby/bigdecimal"},
		{RepositoryURL: "https://github.com/foo/bar"},
	}
	knownURLs := srv.lookupKnownURLs(dependents)

	if rid := knownURLs["https://github.com/ruby/bigdecimal"]; rid != repo.ID {
		t.Errorf("got repo %d, want %d", rid, repo.ID)
	}
	if rid := knownURLs["https://github.com/foo/bar"]; rid != 0 {
		t.Errorf("unknown URL: got repo %d, want 0", rid)
	}
}

func TestAppendFixDescription(t *testing.T) {
	if got := appendFixDescription("desc", ""); got != "desc" {
		t.Errorf("empty fix: got %q", got)
	}
	if got := appendFixDescription("", "do x"); got != "## Suggested fix\n\ndo x" {
		t.Errorf("empty desc: got %q", got)
	}
	if got := appendFixDescription("desc", "  do x  "); got != "desc\n\n## Suggested fix\n\ndo x" {
		t.Errorf("both: got %q", got)
	}
}

func TestImportFindings_keepsSuggestedFixGated(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, Commit: "abc"}
	s.DB.Create(&scan)

	res := ingest.Result{
		Tool: "sarif-tool",
		Findings: []ingest.Finding{{
			Title:        "thing",
			Severity:     "High",
			Location:     "a.go:1",
			Description:  "explanation",
			SuggestedFix: "validate input before use",
		}},
	}
	created, _ := s.importFindings(&scan, res)
	if len(created) != 1 {
		t.Fatalf("created %d findings, want 1", len(created))
	}
	var f db.Finding
	s.DB.First(&f, created[0])
	if f.SuggestedFix != "" {
		t.Errorf("SuggestedFix = %q, want empty (gated column)", f.SuggestedFix)
	}
	if f.SuggestedFixCommit != "" {
		t.Errorf("SuggestedFixCommit = %q, want empty", f.SuggestedFixCommit)
	}
	if !strings.Contains(f.Trace, "validate input before use") {
		t.Errorf("Trace = %q, want fix text folded in", f.Trace)
	}
	if !strings.Contains(f.Trace, "explanation") {
		t.Errorf("Trace = %q, want original description retained", f.Trace)
	}
}
