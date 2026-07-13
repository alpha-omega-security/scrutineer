package web

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm"

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
	if got := appendFixDescription("desc", "", ""); got != "desc" {
		t.Errorf("empty fix: got %q", got)
	}
	if got := appendFixDescription("", "do x", ""); got != "## Suggested fix\n\ndo x" {
		t.Errorf("empty desc: got %q", got)
	}
	if got := appendFixDescription("desc", "  do x  ", ""); got != "desc\n\n## Suggested fix\n\ndo x" {
		t.Errorf("both: got %q", got)
	}
	// A fix commit is noted inside the suggested-fix section so the operator
	// can rebase before promoting the diff; an empty fix drops it entirely.
	if got := appendFixDescription("", "do x", "abc123"); got != "## Suggested fix\n\nApplies to commit `abc123`.\n\ndo x" {
		t.Errorf("with fix commit: got %q", got)
	}
	if got := appendFixDescription("desc", "", "abc123"); got != "desc" {
		t.Errorf("fix commit but no fix: got %q", got)
	}
}

func TestImportFindings_reimportBumpsSeenCount(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	res := ingest.Result{
		RepoURL: "https://example.com/r",
		Tool:    "external-scanner",
		Commit:  "abc",
		Findings: []ingest.Finding{
			{Title: "one", Severity: "High", Location: "a.go:1", CWE: "CWE-79"},
			{Title: "two", Severity: "Low", Location: "b.go:1", CWE: "CWE-89"},
		},
	}
	first, err := s.importResult(res, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if first["created"] != 2 || first["observed"] != 0 {
		t.Fatalf("first import created=%v observed=%v, want 2/0", first["created"], first["observed"])
	}

	// Second import: one finding matches, one is new.
	res.Commit = "def"
	res.Findings = []ingest.Finding{
		{Title: "one", Severity: "High", Location: "a.go:1", CWE: "CWE-79"},
		{Title: "three", Severity: "Medium", Location: "c.go:1", CWE: "CWE-22"},
	}
	second, err := s.importResult(res, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if second["created"] != 1 || second["observed"] != 1 {
		t.Fatalf("second import created=%v observed=%v, want 1/1", second["created"], second["observed"])
	}

	var total int64
	s.DB.Model(&db.Finding{}).Count(&total)
	if total != 3 {
		t.Fatalf("total findings = %d, want 3 (no duplicate for re-observed)", total)
	}

	var reobserved db.Finding
	s.DB.Where("title = ?", "one").First(&reobserved)
	if reobserved.SeenCount != 2 {
		t.Errorf("SeenCount = %d, want 2", reobserved.SeenCount)
	}
	if reobserved.LastSeenCommit != "def" {
		t.Errorf("LastSeenCommit = %q, want def", reobserved.LastSeenCommit)
	}
	if reobserved.LastSeenScanID != uint(second["scan_id"].(uint)) {
		t.Errorf("LastSeenScanID = %d, want %d", reobserved.LastSeenScanID, second["scan_id"])
	}
	if reobserved.MissedCount != 0 {
		t.Errorf("MissedCount = %d, want 0 (reset on re-observation)", reobserved.MissedCount)
	}
	var hist int64
	s.DB.Model(&db.FindingHistory{}).
		Where("finding_id = ? AND field = ?", reobserved.ID, "observed").Count(&hist)
	if hist != 1 {
		t.Errorf("history rows = %d, want 1", hist)
	}
}

func TestImportFindings_rollbackLeavesNoScanOrFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, Commit: "abc"}

	// Run the same tx shape as importResult but force an error after the
	// scan and findings have been written, so we can assert both roll back.
	res := ingest.Result{
		Tool: "external-scanner",
		Findings: []ingest.Finding{
			{Title: "ok", Severity: "High", Location: "a.go:1"},
		},
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&scan).Error; err != nil {
			return err
		}
		if _, _, err := s.importFindings(tx, &scan, res); err != nil {
			return err
		}
		return errors.New("simulated post-write failure")
	})
	if err == nil {
		t.Fatal("expected transaction to roll back")
	}

	var scans, findings int64
	s.DB.Model(&db.Scan{}).Count(&scans)
	s.DB.Model(&db.Finding{}).Count(&findings)
	if scans != 0 || findings != 0 {
		t.Fatalf("after rollback: scans=%d findings=%d, want 0/0", scans, findings)
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
	created, _, err := s.importFindings(s.DB, &scan, res)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("created %d findings, want 1", len(created))
	}
	var f db.Finding
	s.DB.First(&f, created[0].ID)
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

func TestImportFindings_revalidateToggle(t *testing.T) {
	cases := []struct {
		name       string
		revalidate bool
		// Every imported finding gets a revalidate run regardless of severity
		// when enabled (import severity is an unvalidated external claim, so
		// even Low is worth revalidating); revalidate=false primes nothing.
		wantQueued int64
	}{
		{"enabled enqueues one per finding", true, 2},
		{"disabled enqueues nothing", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			revalidate := db.Skill{Name: "revalidate", OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
			s.DB.Create(&revalidate)

			res := ingest.Result{
				RepoURL: "https://example.com/r",
				Tool:    "external-scanner",
				Findings: []ingest.Finding{
					{Title: "high", Severity: "High", Location: "a.go:1"},
					{Title: "low", Severity: "Low", Location: "b.go:1"},
				},
			}
			out, err := s.importResult(res, "", tc.revalidate)
			if err != nil {
				t.Fatal(err)
			}
			if out["created"] != 2 {
				t.Fatalf("created %v findings, want 2", out["created"])
			}
			var queued int64
			s.DB.Model(&db.Scan{}).
				Where("skill_id = ? AND status = ?", revalidate.ID, db.ScanQueued).
				Count(&queued)
			if queued != tc.wantQueued {
				t.Errorf("queued revalidate scans = %d, want %d", queued, tc.wantQueued)
			}
		})
	}
}

func TestImportFindings_skipsRevalidateWhenSkillAbsent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	// No revalidate skill registered. Import must still succeed.
	res := ingest.Result{RepoURL: "https://example.com/r", Tool: "x", Findings: []ingest.Finding{{Title: "t", Severity: "High", Location: "a.go:1"}}}
	out, err := s.importResult(res, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if out["created"] != 1 {
		t.Fatalf("created = %v, want 1", out["created"])
	}
}

func TestImportFindings_enqueuesOneMetadataOnboardingRunForExistingHollowRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	metadata := db.Skill{Name: metadataSkillName, OutputFile: "report.json",
		OutputKind: "repo_metadata", Version: 1, Active: true}
	s.DB.Create(&metadata)
	repo := db.Repository{URL: "https://github.com/ruby/rdoc", Name: "rdoc"}
	s.DB.Create(&repo) // imported before onboarding existed: URL + findings only

	res := ingest.Result{RepoURL: repo.URL, Tool: "scrutineer",
		Findings: []ingest.Finding{{Title: "imported", Severity: "High", Location: "lib/rdoc.rb:1"}}}
	if _, err := s.importResult(res, "", false); err != nil {
		t.Fatal(err)
	}
	// Reimport while metadata is queued must not pile up another run.
	if _, err := s.importResult(res, "", false); err != nil {
		t.Fatal(err)
	}

	var scans []db.Scan
	s.DB.Where("skill_name = ?", metadataSkillName).Find(&scans)
	if len(scans) != 1 {
		t.Fatalf("metadata scans = %d, want 1", len(scans))
	}
	if scans[0].RepositoryID == 0 || scans[0].FindingID != nil || scans[0].Status != db.ScanQueued {
		t.Errorf("metadata scan = %+v, want queued repository-scoped onboarding", scans[0])
	}
}

func TestImportFindings_existingDoneMetadataIsNotDuplicated(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	metadata := db.Skill{Name: metadataSkillName, OutputFile: "report.json",
		OutputKind: "repo_metadata", Version: 1, Active: true}
	s.DB.Create(&metadata)
	repo := db.Repository{URL: "https://github.com/ruby/uri", Name: "uri"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillID: &metadata.ID,
		SkillName: metadataSkillName, Status: db.ScanDone})

	res := ingest.Result{RepoURL: repo.URL, Tool: "scrutineer",
		Findings: []ingest.Finding{{Title: "imported", Severity: "Medium"}}}
	if _, err := s.importResult(res, "", false); err != nil {
		t.Fatal(err)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ? AND skill_name = ?", repo.ID, metadataSkillName).Count(&count)
	if count != 1 {
		t.Errorf("metadata scans = %d, want existing completed scan only", count)
	}
}

func TestImportFindings_localRepoWithValidPathGetsNoMetadataScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	metadata := db.Skill{Name: metadataSkillName, OutputFile: "report.json",
		OutputKind: "repo_metadata", Version: 1, Active: true}
	s.DB.Create(&metadata)

	// A local checkout that genuinely exists on this host must import
	// findings without the remote-only clone/metadata onboarding run.
	dir := t.TempDir()
	res := ingest.Result{RepoURL: LocalScheme + dir, Tool: "scrutineer",
		Findings: []ingest.Finding{{Title: "local", Severity: "High", Location: "main.go:1"}}}
	if _, err := s.importResult(res, "", false); err != nil {
		t.Fatal(err)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_name = ?", metadataSkillName).Count(&count)
	if count != 0 {
		t.Errorf("metadata scans = %d, want 0 for a local repository", count)
	}
}

func TestAutoEnqueueRevalidate_onlyHighAndCriticalFromLLMAudits(t *testing.T) {
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
		{"vuln-scan Critical", "vuln-scan", "Critical", true},
		{"vuln-scan High", "vuln-scan", "High", true},
		{"vuln-scan Medium", "vuln-scan", "Medium", false},
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

// chainTestSetup creates a repo, a parent scan, a verify skill, and a
// finding the callback tests can act on. Returns the server, the verify
// skill, and a fresh-finding factory.
func chainTestSetup(t *testing.T) (*Server, func(), db.Skill, func(string) *db.Finding) {
	t.Helper()
	s, done := newTestServer(t)
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: "revalidate"}
	s.DB.Create(&scan)
	verify := db.Skill{Name: "verify", OutputFile: "report.json", OutputKind: "verify", Version: 1, Active: true}
	s.DB.Create(&verify)
	newFinding := func(severity string) *db.Finding {
		f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: severity}
		s.DB.Create(&f)
		return &f
	}
	return s, done, verify, newFinding
}

func TestAutoChainVerify_truePositiveHighEnqueuesVerify(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	f := newFinding("High")
	s.autoChainVerifyAfterRevalidate(nil, f, "true_positive", "High")

	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_id = ? AND status = ?", f.ID, verify.ID, db.ScanQueued).
		Count(&queued)
	if queued != 1 {
		t.Errorf("queued verify scans = %d, want 1", queued)
	}
}

func TestAutoChainVerify_respectsAdjustedSeverity(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	// Finding's stored severity is High but the callback gets the
	// post-adjustment Medium value, which must stop the chain.
	f := newFinding("High")
	s.autoChainVerifyAfterRevalidate(nil, f, "true_positive", "Medium")

	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_id = ?", f.ID, verify.ID).
		Count(&queued)
	if queued != 0 {
		t.Errorf("queued = %d, want 0 (revalidate downgraded the severity)", queued)
	}
}

func TestAutoChainVerify_skipsNonTruePositive(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	for _, verdict := range []string{"false_positive", "already_fixed", "uncertain"} {
		t.Run(verdict, func(t *testing.T) {
			f := newFinding("Critical")
			s.autoChainVerifyAfterRevalidate(nil, f, verdict, "Critical")
			var queued int64
			s.DB.Model(&db.Scan{}).
				Where("finding_id = ? AND skill_id = ?", f.ID, verify.ID).
				Count(&queued)
			if queued != 0 {
				t.Errorf("queued = %d, want 0 for verdict %q", queued, verdict)
			}
		})
	}
}

func TestAutoChainVerify_doesNotDoubleQueue(t *testing.T) {
	s, done, verify, newFinding := chainTestSetup(t)
	defer done()
	f := newFinding("High")
	s.autoChainVerifyAfterRevalidate(nil, f, "true_positive", "High")
	s.autoChainVerifyAfterRevalidate(nil, f, "true_positive", "High")

	var queued int64
	s.DB.Model(&db.Scan{}).Where("finding_id = ? AND skill_id = ?", f.ID, verify.ID).Count(&queued)
	if queued != 1 {
		t.Errorf("queued = %d, want 1 (re-chain guard)", queued)
	}
}

func TestAutoChainVerify_gracefulWhenVerifySkillAbsent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: "revalidate"}
	s.DB.Create(&scan)
	// No verify skill registered: must not panic, no scan to assert.
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: "High"}
	s.DB.Create(&f)
	s.autoChainVerifyAfterRevalidate(nil, &f, "true_positive", "High")
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
