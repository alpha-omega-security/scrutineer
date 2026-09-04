package db

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestRetireDependentsSkill(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	rows := []Skill{
		{Name: "dependents", Source: "local", Active: true},
		{Name: "dependents-remote", Source: "local", Active: true},
	}
	for i := range rows {
		if err := gdb.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}

	if err := RetireDependentsSkill(gdb); err != nil {
		t.Fatalf("retire dependents skill: %v", err)
	}

	got := map[string]bool{}
	var skills []Skill
	gdb.Order("name, source").Find(&skills)
	for _, sk := range skills {
		got[sk.Name+"/"+sk.Source] = sk.Active
	}
	if got["dependents/local"] {
		t.Error("local dependents skill should be inactive")
	}
	if !got["dependents-remote/local"] {
		t.Error("unrelated local skill should stay active")
	}

	remoteDB, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	remote := Skill{Name: "dependents", Source: "remote", Active: true}
	if err := remoteDB.Create(&remote).Error; err != nil {
		t.Fatal(err)
	}
	if err := RetireDependentsSkill(remoteDB); err != nil {
		t.Fatalf("retire remote fixture: %v", err)
	}
	var loaded Skill
	if err := remoteDB.First(&loaded, remote.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !loaded.Active {
		t.Error("remote dependents skill should stay active")
	}
}

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

func TestFindingSeverityCapList(t *testing.T) {
	finding := Finding{SeverityCaps: " authz held \n\nsandbox held\n"}
	want := []string{"authz held", "sandbox held"}
	if got := finding.SeverityCapList(); !slices.Equal(got, want) {
		t.Fatalf("SeverityCapList() = %v, want %v", got, want)
	}
	if got := (Finding{}).SeverityCapList(); got == nil || len(got) != 0 {
		t.Fatalf("empty SeverityCapList() = %#v, want non-nil empty list", got)
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

	snap := mustOpen(t, dest)
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
	mustOpen(t, src)
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

func TestPreMigrate_renamesSBOMPackageRepositoryID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// Simulate a database written before the rename: sbom_packages has a
	// repository_id column with data in it. Open must rename the column
	// before AutoMigrate would otherwise add source_repository_id alongside
	// it and strand the old values.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{
		`CREATE TABLE repositories (id INTEGER PRIMARY KEY, url TEXT, name TEXT)`,
		`INSERT INTO repositories (id, url, name) VALUES (42, 'https://example.com/r', 'r')`,
		`CREATE TABLE sbom_uploads (id INTEGER PRIMARY KEY, name TEXT)`,
		`INSERT INTO sbom_uploads (id, name) VALUES (1, 'old')`,
		`CREATE TABLE sbom_packages (id INTEGER PRIMARY KEY, sbom_upload_id INTEGER, repository_id INTEGER)`,
		`INSERT INTO sbom_packages (id, sbom_upload_id, repository_id) VALUES (1, 1, 42)`,
	}
	for _, s := range stmts {
		if _, err := raw.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	_ = raw.Close()

	gdb := mustOpen(t, path)
	if gdb.Migrator().HasColumn(&SBOMPackage{}, "repository_id") {
		t.Error("repository_id column should have been renamed, still present")
	}
	var pkg SBOMPackage
	if err := gdb.First(&pkg, 1).Error; err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if pkg.SourceRepositoryID == nil || *pkg.SourceRepositoryID != 42 {
		t.Errorf("SourceRepositoryID = %v, want 42", pkg.SourceRepositoryID)
	}

	// Idempotent: a second Open on the already-migrated file must not fail.
	mustOpen(t, path)
}

// newFindingReferenceDB opens a database at path, seeds a repository, a scan
// and n findings, then drops the unique index so the caller can write the
// duplicate rows a pre-#868 install could hold. The returned handle stays open.
func newFindingReferenceDB(t *testing.T, path string, n int) (*gorm.DB, []uint) {
	t.Helper()
	gdb := mustOpen(t, path)
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := Scan{RepositoryID: repo.ID, Kind: "skill", Status: ScanDone}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	findings := make([]Finding, 0, n)
	for i := range n {
		findings = append(findings, Finding{
			ScanID: scan.ID, RepositoryID: repo.ID,
			FindingID: fmt.Sprintf("F%d", i+1), Title: fmt.Sprintf("f%d", i+1),
			Severity: "High", Status: FindingNew,
		})
	}
	if err := gdb.Create(&findings).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Migrator().DropIndex(&FindingReference{}, findingRefURLIndex); err != nil {
		t.Fatalf("drop %s: %v", findingRefURLIndex, err)
	}
	ids := make([]uint, 0, n)
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	return gdb, ids
}

// legacyFindingReferenceDB writes a database file in the pre-index shape and
// returns its path. newFindingReferenceDB gives it the current schema without
// idx_finding_ref_url, matching what an install written before #868 holds, then
// seed fills finding_references with the duplicates such an install could
// accumulate. Reopening the file is what puts preMigrate to work.
func legacyFindingReferenceDB(t *testing.T, seed func(gdb *gorm.DB, findingA, findingB uint)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "old.db")
	gdb, ids := newFindingReferenceDB(t, path, 2)
	seed(gdb, ids[0], ids[1])
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// seedFindingReferences inserts reference rows verbatim, ids included, into a
// database whose unique index has been dropped.
func seedFindingReferences(t *testing.T, gdb *gorm.DB, rows []FindingReference) {
	t.Helper()
	for i := range rows {
		rows[i].CreatedAt = time.Now().UTC()
		if err := gdb.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed reference %d: %v", rows[i].ID, err)
		}
	}
}

func findingReferencesFor(t *testing.T, gdb *gorm.DB, findingID uint) []FindingReference {
	t.Helper()
	var refs []FindingReference
	if err := gdb.Where("finding_id = ?", findingID).Order("id").Find(&refs).Error; err != nil {
		t.Fatalf("load references: %v", err)
	}
	return refs
}

// The merge pages by finding id, so a database holding more findings than one
// batch must still collapse every group. No other fixture here comes close to
// the production batch of 500, which would leave the `finding_id > ?` advance
// and the claim that paging never splits a group untested: a regression in
// either loops forever or leaves a duplicate for the index creation to trip on.
func TestMergeAndIndexFindingReferences_pagesAcrossBatches(t *testing.T) {
	const (
		findings = 5
		batch    = 2
	)
	gdb, ids := newFindingReferenceDB(t, filepath.Join(t.TempDir(), "old.db"), findings)
	rows := make([]FindingReference, 0, 2*findings)
	for i, id := range ids {
		url := fmt.Sprintf("https://example.com/advisory/%d", i)
		// Two rows per finding for one URL, each carrying half the metadata,
		// so a page that merged the wrong group is visible in the result.
		rows = append(rows,
			FindingReference{ID: uint(2*i + 1), FindingID: id, URL: url, Tags: "cve"},
			FindingReference{ID: uint(2*i + 2), FindingID: id, URL: url, Summary: fmt.Sprintf("summary %d", i)},
		)
	}
	seedFindingReferences(t, gdb, rows)

	if err := mergeAndIndexFindingReferences(gdb, batch); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if !gdb.Migrator().HasIndex(&FindingReference{}, findingRefURLIndex) {
		t.Fatalf("%s missing after the merge", findingRefURLIndex)
	}

	for i, id := range ids {
		got := findingReferencesFor(t, gdb, id)
		if len(got) != 1 {
			t.Fatalf("finding %d kept %d references, want 1", id, len(got))
		}
		wantURL := fmt.Sprintf("https://example.com/advisory/%d", i)
		wantSummary := fmt.Sprintf("summary %d", i)
		if got[0].ID != uint(2*i+1) || got[0].URL != wantURL {
			t.Errorf("finding %d survivor = %+v, want the lowest id holding %s", id, got[0], wantURL)
		}
		if got[0].Tags != "cve" || got[0].Summary != wantSummary {
			t.Errorf("finding %d metadata = tags %q summary %q, want cve / %q", id, got[0].Tags, got[0].Summary, wantSummary)
		}
	}
}

// Collapsing duplicates is only safe because the index creation that justifies
// it is in the same transaction. If the two were separate statements, a schema
// step failing after the cleanup committed would leave Open returning an error
// over a table that had already lost rows. Claiming the index name on another
// table is the cheapest way to make CREATE INDEX fail the way a broken schema
// step would.
func TestMergeAndIndexFindingReferences_rollsBackWhenIndexCreationFails(t *testing.T) {
	gdb, ids := newFindingReferenceDB(t, filepath.Join(t.TempDir(), "old.db"), 1)
	const url = "https://example.com/advisory/1"
	seedFindingReferences(t, gdb, []FindingReference{
		{ID: 1, FindingID: ids[0], URL: url, Tags: "cve"},
		{ID: 2, FindingID: ids[0], URL: url, Summary: "duplicate"},
	})
	if err := gdb.Exec("CREATE INDEX " + findingRefURLIndex + " ON findings(id)").Error; err != nil {
		t.Fatalf("claim index name: %v", err)
	}

	if err := mergeAndIndexFindingReferences(gdb, findingRefMergeBatch); err == nil {
		t.Fatal("mergeAndIndexFindingReferences() = nil, want the index creation to fail")
	}

	got := findingReferencesFor(t, gdb, ids[0])
	if len(got) != 2 {
		t.Fatalf("references after the failure = %d, want both duplicates still there", len(got))
	}
	if got[0].Summary != "" || got[1].Tags != "" {
		t.Errorf("rows were merged before the rollback: %+v", got)
	}
}

func TestPreMigrate_mergesDuplicateFindingReferences(t *testing.T) {
	var findingA uint
	// One finding carries the same advisory URL three times. The first row has
	// no metadata, the second a summary, the third tags: the merge has to end
	// with one row holding all of it. The fourth row is a different URL on the
	// same finding and must survive untouched.
	path := legacyFindingReferenceDB(t, func(gdb *gorm.DB, a, _ uint) {
		findingA = a
		seedFindingReferences(t, gdb, []FindingReference{
			{ID: 1, FindingID: a, URL: "https://example.com/advisory"},
			{ID: 2, FindingID: a, URL: "https://example.com/advisory", Summary: "Upstream advisory"},
			{ID: 3, FindingID: a, URL: "https://example.com/advisory", Tags: "advisory,upstream", Summary: "Later summary"},
			{ID: 4, FindingID: a, URL: "https://example.com/pull/42", Tags: "pr", Summary: "The fix"},
		})
	})

	gdb := mustOpen(t, path)
	if !gdb.Migrator().HasIndex(&FindingReference{}, findingRefURLIndex) {
		t.Fatalf("%s was not created", findingRefURLIndex)
	}

	refs := findingReferencesFor(t, gdb, findingA)
	if len(refs) != 2 {
		t.Fatalf("kept %d references, want 2: %+v", len(refs), refs)
	}
	// The lowest id survives, so a link somebody already followed keeps working.
	if refs[0].ID != 1 {
		t.Errorf("surviving id = %d, want 1", refs[0].ID)
	}
	// Metadata is absorbed oldest first, so the summary comes from id 2 rather
	// than the later one on id 3, while the tags can only come from id 3.
	if refs[0].Summary != "Upstream advisory" {
		t.Errorf("Summary = %q, want %q", refs[0].Summary, "Upstream advisory")
	}
	if refs[0].Tags != "advisory,upstream" {
		t.Errorf("Tags = %q, want %q", refs[0].Tags, "advisory,upstream")
	}
	if refs[1].ID != 4 || refs[1].URL != "https://example.com/pull/42" || refs[1].Tags != "pr" {
		t.Errorf("distinct URL was disturbed: %+v", refs[1])
	}

	// Idempotent: a second Open on the already-migrated file must not fail.
	mustOpen(t, path)
}

func TestPreMigrate_findingReferenceMergeIsPerFinding(t *testing.T) {
	var findingA, findingB uint
	// The same URL on two findings is two references, not a duplicate.
	path := legacyFindingReferenceDB(t, func(gdb *gorm.DB, a, b uint) {
		findingA, findingB = a, b
		seedFindingReferences(t, gdb, []FindingReference{
			{ID: 1, FindingID: a, URL: "https://example.com/cve", Tags: "cve"},
			{ID: 2, FindingID: b, URL: "https://example.com/cve", Summary: "NVD"},
			{ID: 3, FindingID: b, URL: "https://example.com/cve", Tags: "cve"},
		})
	})

	gdb := mustOpen(t, path)
	first, second := findingReferencesFor(t, gdb, findingA), findingReferencesFor(t, gdb, findingB)
	if len(first) != 1 || first[0].ID != 1 || first[0].Tags != "cve" {
		t.Errorf("first finding's references = %+v, want the untouched id 1", first)
	}
	if len(second) != 1 || second[0].ID != 2 {
		t.Fatalf("second finding's references = %+v, want one row at id 2", second)
	}
	if second[0].Summary != "NVD" || second[0].Tags != "cve" {
		t.Errorf("merged row = %+v, want summary NVD and tags cve", second[0])
	}
}

func TestPreMigrate_findingReferenceMergeNormalisesWhitespace(t *testing.T) {
	var findingA, findingB uint
	// AddFindingReference trims before it looks a row up, so a stored URL with
	// stray whitespace can never be matched again and the index would keep both
	// spellings. The merge trims, which also collapses these two into one.
	path := legacyFindingReferenceDB(t, func(gdb *gorm.DB, a, b uint) {
		findingA, findingB = a, b
		seedFindingReferences(t, gdb, []FindingReference{
			{ID: 1, FindingID: a, URL: "  https://example.com/advisory\n", Tags: " advisory ", Summary: "  "},
			{ID: 2, FindingID: a, URL: "https://example.com/advisory", Summary: " Upstream advisory "},
			{ID: 3, FindingID: b, URL: "\thttps://example.com/only "},
		})
	})

	gdb := mustOpen(t, path)
	refs := findingReferencesFor(t, gdb, findingA)
	if len(refs) != 1 {
		t.Fatalf("kept %d references, want 1: %+v", len(refs), refs)
	}
	want := FindingReference{ID: 1, URL: "https://example.com/advisory", Tags: "advisory", Summary: "Upstream advisory"}
	if refs[0].ID != want.ID || refs[0].URL != want.URL || refs[0].Tags != want.Tags || refs[0].Summary != want.Summary {
		t.Errorf("merged row = %+v, want %+v", refs[0], want)
	}
	// A lone reference has no duplicate to merge with but is still normalised,
	// so the next write of the same URL finds it instead of inserting again.
	lone := findingReferencesFor(t, gdb, findingB)
	if len(lone) != 1 || lone[0].URL != "https://example.com/only" {
		t.Errorf("lone reference = %+v, want a trimmed URL", lone)
	}
}

func TestFindingReference_uniqueIndexRejectsDuplicateURL(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	f := seedFinding(t, gdb)
	if err := gdb.Create(&FindingReference{FindingID: f.ID, URL: "https://example.com/a"}).Error; err != nil {
		t.Fatalf("first reference: %v", err)
	}
	// The backstop AddFindingReference cannot provide on its own: two writers
	// that both miss the lookup cannot both insert.
	err = gdb.Create(&FindingReference{FindingID: f.ID, URL: "https://example.com/a", Tags: "cve"}).Error
	if err == nil {
		t.Fatal("second reference with the same URL was accepted, want a unique-index violation")
	}
	// The same URL on another finding, and another URL on this one, are fine.
	other := Finding{ScanID: f.ScanID, RepositoryID: f.RepositoryID, FindingID: "F2", Title: "t2", Severity: "Low", Status: FindingNew}
	if err := gdb.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&FindingReference{FindingID: other.ID, URL: "https://example.com/a"}).Error; err != nil {
		t.Errorf("same URL on a different finding: %v", err)
	}
	if err := gdb.Create(&FindingReference{FindingID: f.ID, URL: "https://example.com/b"}).Error; err != nil {
		t.Errorf("different URL on the same finding: %v", err)
	}
}

func TestPreMigrate_findingReferenceMergeDropsBlankURLs(t *testing.T) {
	var findingA, findingB uint
	// A reference with no URL points nowhere. Rewriting it as an empty string
	// would leave a blank link on the finding page and in every export, so the
	// merge removes it, the same way every writer already refuses to make one.
	path := legacyFindingReferenceDB(t, func(gdb *gorm.DB, a, b uint) {
		findingA, findingB = a, b
		seedFindingReferences(t, gdb, []FindingReference{
			{ID: 1, FindingID: a, URL: "   ", Tags: "junk"},
			{ID: 2, FindingID: a, URL: "", Summary: "also junk"},
			{ID: 3, FindingID: a, URL: "https://example.com/real", Tags: "advisory"},
			{ID: 4, FindingID: b, URL: "\t\n"},
		})
	})

	gdb := mustOpen(t, path)
	refs := findingReferencesFor(t, gdb, findingA)
	if len(refs) != 1 {
		t.Fatalf("kept %d references, want only the real one: %+v", len(refs), refs)
	}
	if refs[0].ID != 3 || refs[0].URL != "https://example.com/real" || refs[0].Tags != "advisory" {
		t.Errorf("surviving reference = %+v, want id 3 untouched", refs[0])
	}
	// A finding whose only reference was blank is left with none, not with an
	// empty-URL row that the index would then treat as a real reference.
	if left := findingReferencesFor(t, gdb, findingB); len(left) != 0 {
		t.Errorf("blank-only finding kept %+v, want no references", left)
	}
}

func TestPlanFindingReferenceMerge_dropsBlankURLsWithoutGroupingThem(t *testing.T) {
	// Two blank rows on one finding are two pieces of junk, not a URL group:
	// each is dropped on its own rather than one surviving as the other's
	// canonical row.
	rows := []FindingReference{
		{ID: 1, FindingID: 7, URL: " ", Tags: "a"},
		{ID: 2, FindingID: 7, URL: "", Tags: "b"},
		{ID: 3, FindingID: 7, URL: "https://example.com/a"},
	}
	survivors, drop := planFindingReferenceMerge(rows)
	if len(survivors) != 0 {
		t.Errorf("survivors = %+v, want no rewrites", survivors)
	}
	if !slices.Equal(drop, []uint{1, 2}) {
		t.Errorf("drop = %v, want both blank rows", drop)
	}
}

func TestPlanFindingReferenceMerge_leavesCleanRowsAlone(t *testing.T) {
	rows := []FindingReference{
		{ID: 1, FindingID: 7, URL: "https://example.com/a", Tags: "cve"},
		{ID: 2, FindingID: 7, URL: "https://example.com/b"},
		{ID: 3, FindingID: 8, URL: "https://example.com/a", Summary: "s"},
	}
	survivors, drop := planFindingReferenceMerge(rows)
	if len(survivors) != 0 {
		t.Errorf("survivors = %+v, want no rewrites for an already-clean table", survivors)
	}
	if len(drop) != 0 {
		t.Errorf("drop = %v, want nothing deleted", drop)
	}
}

func TestSBOMUpload_originAndCurrent(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/r", Name: "r"}
	gdb.Create(&repo)
	// A row that omits Origin lands as "uploaded" via the column default,
	// matching rows written before the column existed.
	up := SBOMUpload{Name: "x"}
	if err := gdb.Create(&up).Error; err != nil {
		t.Fatal(err)
	}
	var got SBOMUpload
	gdb.First(&got, up.ID)
	if got.Origin != SBOMOriginUploaded {
		t.Errorf("default Origin = %q, want %q", got.Origin, SBOMOriginUploaded)
	}
	if got.Current {
		t.Error("uploaded SBOM should not be Current")
	}

	gen := SBOMUpload{Name: "g", Origin: SBOMOriginGenerated, RepositoryID: &repo.ID, Commit: "abc", Current: true}
	if err := gdb.Create(&gen).Error; err != nil {
		t.Fatal(err)
	}
	var current []SBOMUpload
	gdb.Where("repository_id = ? AND current = ?", repo.ID, true).Find(&current)
	if len(current) != 1 || current[0].ID != gen.ID {
		t.Errorf("current lookup = %+v, want [%d]", current, gen.ID)
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

func TestScanResumable(t *testing.T) {
	for _, tc := range []struct {
		name string
		scan Scan
		want bool
	}{
		{name: "failed with session", scan: Scan{Status: ScanFailed, SessionID: "session"}, want: true},
		{name: "done at max turns with session", scan: Scan{Status: ScanDone, MaxTurnsHit: true, SessionID: "session"}, want: true},
		{name: "failed without session", scan: Scan{Status: ScanFailed}},
		{name: "done at max turns without session", scan: Scan{Status: ScanDone, MaxTurnsHit: true}},
		{name: "ordinary done with session", scan: Scan{Status: ScanDone, SessionID: "session"}},
		{name: "cancelled with session", scan: Scan{Status: ScanCancelled, SessionID: "session"}},
		{name: "running with session", scan: Scan{Status: ScanRunning, SessionID: "session"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scan.Resumable(); got != tc.want {
				t.Fatalf("Resumable() = %t, want %t", got, tc.want)
			}
		})
	}
}
