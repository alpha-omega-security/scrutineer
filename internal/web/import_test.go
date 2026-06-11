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

func TestImportFindings_enqueuesRevalidate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, Commit: "abc"}
	s.DB.Create(&scan)
	revalidate := db.Skill{Name: "revalidate", OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
	s.DB.Create(&revalidate)

	res := ingest.Result{
		Tool: "external-scanner",
		Findings: []ingest.Finding{
			{Title: "high", Severity: "High", Location: "a.go:1"},
			{Title: "low", Severity: "Low", Location: "b.go:1"},
		},
	}
	if created, _ := s.importFindings(&scan, res); len(created) != 2 {
		t.Fatalf("created %d findings, want 2", len(created))
	}

	// Every imported finding gets a revalidate run regardless of severity:
	// import severity is an unvalidated external claim, so even Low is
	// worth revalidating.
	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("skill_id = ? AND status = ?", revalidate.ID, db.ScanQueued).
		Count(&queued)
	if queued != 2 {
		t.Errorf("queued revalidate scans = %d, want 2 (one per imported finding)", queued)
	}
}

func TestImportFindings_skipsRevalidateWhenSkillAbsent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, Commit: "abc"}
	s.DB.Create(&scan)
	// No revalidate skill registered. Import must still succeed.
	res := ingest.Result{Tool: "x", Findings: []ingest.Finding{{Title: "t", Severity: "High", Location: "a.go:1"}}}
	if created, _ := s.importFindings(&scan, res); len(created) != 1 {
		t.Fatalf("created = %d, want 1", len(created))
	}
}

func TestAutoEnqueueRevalidate_onlyHighAndCriticalFromDeepDive(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	revalidate := db.Skill{Name: "revalidate", OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
	s.DB.Create(&revalidate)

	cases := []struct {
		name       string
		skill      string
		severity   string
		wantQueued bool
	}{
		{"deep-dive Critical", "security-deep-dive", "Critical", true},
		{"deep-dive High", "security-deep-dive", "High", true},
		{"deep-dive Medium", "security-deep-dive", "Medium", false},
		{"deep-dive Low", "security-deep-dive", "Low", false},
		{"semgrep High", "semgrep", "High", false},
		{"zizmor Critical", "zizmor", "Critical", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: c.skill}
			s.DB.Create(&scan)
			f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: c.severity}
			s.DB.Create(&f)
			s.autoEnqueueRevalidate(&scan, &f)
			var queued int64
			s.DB.Model(&db.Scan{}).
				Where("finding_id = ? AND skill_id = ? AND status = ?", f.ID, revalidate.ID, db.ScanQueued).
				Count(&queued)
			gotQueued := queued > 0
			if gotQueued != c.wantQueued {
				t.Errorf("queued=%v, want %v", gotQueued, c.wantQueued)
			}
		})
	}
}

func TestAutoEnqueueRevalidate_doesNotDoubleQueue(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	revalidate := db.Skill{Name: "revalidate", OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
	s.DB.Create(&revalidate)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: "High"}
	s.DB.Create(&f)

	s.autoEnqueueRevalidate(&scan, &f)
	s.autoEnqueueRevalidate(&scan, &f)

	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_id = ?", f.ID, revalidate.ID).
		Count(&queued)
	if queued != 1 {
		t.Errorf("queued = %d, want 1 (re-queue guard)", queued)
	}
}
