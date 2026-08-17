package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/verification"
)

func TestParseSubprojectsOutput(t *testing.T) {
	report := `{"subprojects":[
		{"path":"packages/core","name":"core","kind":"library","description":"shared core"},
		{"path":" /packages/cli/ ","name":"cli","kind":"binary"},
		{"path":"","name":"ignored"},
		{"path":"   ","name":"also ignored"}
	]}`
	repo, gdb := runSkillWithReport(t, "subprojects", report)
	var rows []db.Subproject
	gdb.Where("repository_id = ?", repo.ID).Order("path").Find(&rows)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (empty paths dropped)", len(rows))
	}
	if rows[0].Path != "packages/cli" || rows[0].Name != "cli" {
		t.Errorf("row[0] = %+v, want trimmed cli", rows[0])
	}
	if rows[1].Path != "packages/core" || rows[1].Kind != "library" || rows[1].Description != "shared core" {
		t.Errorf("row[1] = %+v", rows[1])
	}

	// A second run replaces the previous set rather than appending. Reuse the
	// same DB and repo so the prior two rows are present to be replaced.
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseSubprojectsOutput(&scan, `{"subprojects":[{"path":"only","name":"only"}]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	if len(rows) != 1 || rows[0].Path != "only" {
		t.Errorf("second run rows = %+v, want [only] (prior set replaced, not appended)", rows)
	}
}

func TestParseSubprojectsOutput_stableIDsAcrossReruns(t *testing.T) {
	report := `{"subprojects":[
		{"path":"a","name":"a","kind":"go-module"},
		{"path":"b","name":"b","kind":"npm-package"}
	]}`
	repo, gdb := runSkillWithReport(t, "subprojects", report)

	var a db.Subproject
	gdb.Where("repository_id = ? AND path = ?", repo.ID, "a").First(&a)
	if a.ID == 0 {
		t.Fatal("subproject a not created")
	}
	// A disclosure channel written by the attribution reconcile must survive a
	// subprojects re-run (the parser owns name/kind/description, not this).
	gdb.Model(&a).Update("disclosure_channel", "security@a.example")

	// Re-run: keep a (renamed), drop b, add c.
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rerun := `{"subprojects":[
		{"path":"a","name":"a-renamed","kind":"go-module"},
		{"path":"c","name":"c","kind":"rust-crate"}
	]}`
	if err := w.parseSubprojectsOutput(&scan, rerun, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var a2 db.Subproject
	gdb.Where("repository_id = ? AND path = ?", repo.ID, "a").First(&a2)
	if a2.ID != a.ID {
		t.Errorf("subproject a id churned across re-run: was %d, now %d (breaks Package/Advisory.SubprojectID refs)", a.ID, a2.ID)
	}
	if a2.Name != "a-renamed" {
		t.Errorf("subproject a name not updated on re-run: %q", a2.Name)
	}
	if a2.DisclosureChannel != "security@a.example" {
		t.Errorf("disclosure channel clobbered on re-run: %q", a2.DisclosureChannel)
	}
	var b db.Subproject
	if err := gdb.Where("repository_id = ? AND path = ?", repo.ID, "b").First(&b).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("subproject b should be pruned, got %+v (err %v)", b, err)
	}
	var count int64
	gdb.Model(&db.Subproject{}).Where("repository_id = ?", repo.ID).Count(&count)
	if count != 2 {
		t.Errorf("subproject count = %d, want 2 (a,c)", count)
	}
}

func TestParseSubprojectsOutput_scopedRunDoesNotPrune(t *testing.T) {
	// Seed the full set from a whole-repository run.
	report := `{"subprojects":[
		{"path":"activesupport","name":"activesupport"},
		{"path":"actionpack","name":"actionpack"}
	]}`
	repo, gdb := runSkillWithReport(t, "subprojects", report)

	// A sub-path-scoped run only saw its own folder, so it reports just
	// activesupport. It must upsert what it saw without pruning actionpack —
	// the backstop that keeps a mis-scoped run from wiping the repo's table.
	scan := db.Scan{RepositoryID: repo.ID, SubPath: "activesupport"}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseSubprojectsOutput(&scan, `{"subprojects":[{"path":"activesupport","name":"activesupport-scoped"}]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var count int64
	gdb.Model(&db.Subproject{}).Where("repository_id = ?", repo.ID).Count(&count)
	if count != 2 {
		t.Errorf("subproject count = %d, want 2 (a scoped run must not prune siblings)", count)
	}
	var ap db.Subproject
	if err := gdb.Where("repository_id = ? AND path = ?", repo.ID, "actionpack").First(&ap).Error; err != nil {
		t.Errorf("actionpack pruned by a scoped run: %v", err)
	}
	var as db.Subproject
	gdb.Where("repository_id = ? AND path = ?", repo.ID, "activesupport").First(&as)
	if as.Name != "activesupport-scoped" {
		t.Errorf("activesupport not upserted by scoped run: name = %q", as.Name)
	}
}

func TestParseSubprojectsOutput_invalidJSON(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseSubprojectsOutput(&scan, "not json", func(Event) {}); err == nil {
		t.Error("expected error on invalid JSON")
	}
}

func TestParseRepoOverviewOutput(t *testing.T) {
	report := `{
		"git": {"default_branch": "develop"},
		"languages": [
			{"name":"Go","category":"language"},
			{"name":"Ruby","category":""},
			{"name":"Docker","category":"container"},
			{"name":"","category":"language"}
		],
		"resources": {"license_type": "MIT"}
	}`
	repo, gdb := runSkillWithReport(t, "repo_overview", report)
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.DefaultBranch != "develop" {
		t.Errorf("DefaultBranch = %q, want develop", got.DefaultBranch)
	}
	if got.Languages != "Go, Ruby" {
		t.Errorf("Languages = %q, want 'Go, Ruby' (non-language category and empty name dropped)", got.Languages)
	}
	if got.License != "MIT" {
		t.Errorf("License = %q, want MIT", got.License)
	}
}

func TestParseRepoOverviewOutput_partialAndEmpty(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x",
		DefaultBranch: "main", Languages: "Python", License: "Apache-2.0"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Unparseable JSON is skipped, no error.
	if err := w.parseRepoOverviewOutput(&scan, "not json", func(Event) {}); err != nil {
		t.Errorf("unparseable: %v", err)
	}
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.Languages != "Python" {
		t.Errorf("unparseable input should not touch repo: %+v", got)
	}

	// Empty document writes nothing (existing fields preserved).
	if err := w.parseRepoOverviewOutput(&scan, `{}`, func(Event) {}); err != nil {
		t.Errorf("empty: %v", err)
	}
	gdb.First(&got, repo.ID)
	if got.DefaultBranch != "main" || got.Languages != "Python" || got.License != "Apache-2.0" {
		t.Errorf("empty document overwrote repo: %+v", got)
	}

	// Partial document only writes the present fields.
	if err := w.parseRepoOverviewOutput(&scan, `{"git":{"default_branch":"trunk"}}`, func(Event) {}); err != nil {
		t.Errorf("partial: %v", err)
	}
	gdb.First(&got, repo.ID)
	if got.DefaultBranch != "trunk" || got.Languages != "Python" {
		t.Errorf("partial = %+v, want default_branch=trunk, languages preserved", got)
	}
}

// runSkillWithReport wires a fakeRunner that returns the given report, runs
// one skill scan against a fresh DB, and returns the scanned Repository and
// the *gorm.DB for further assertions.
func runSkillWithReport(t *testing.T, outputKind, report string) (db.Repository, *gorm.DB) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name:        "k",
		Description: "d",
		Body:        "b",
		OutputFile:  "report.json",
		OutputKind:  outputKind,
		Version:     1,
		Active:      true,
		Source:      "ui",
	}
	gdb.Create(&skill)
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		Status:       db.ScanQueued,
		Model:        "fake",
		SkillID:      &skill.ID,
	}
	gdb.Create(&scan)

	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	return repo, gdb
}

func TestParseRepoMetadata_updatesRepository(t *testing.T) {
	report := `{
		"full_name": "example/x",
		"owner": "example",
		"description": "Hello world",
		"default_branch": "main",
		"languages": ["Go", "JavaScript"],
		"license": "MIT",
		"stars": 42,
		"forks": 3,
		"archived": false,
		"pushed_at": "2026-04-01T00:00:00Z",
		"html_url": "https://github.com/example/x"
	}`
	repo, gdb := runSkillWithReport(t, "repo_metadata", report)
	var refreshed db.Repository
	gdb.First(&refreshed, repo.ID)
	if refreshed.FullName != "example/x" || refreshed.Stars != 42 || refreshed.License != "MIT" {
		t.Errorf("repo: %+v", refreshed)
	}
	if refreshed.Languages != "Go, JavaScript" {
		t.Errorf("languages: %q", refreshed.Languages)
	}
	if refreshed.Metadata == "" {
		t.Error("raw metadata not stored")
	}
}

func TestSafeURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://github.com/x/y", "https://github.com/x/y"},
		{"http://example.com", "http://example.com"},
		{"  https://example.com  ", "https://example.com"},
		{"javascript:alert(1)", ""},
		{"data:text/html,<script>alert(1)</script>", ""},
		{"vbscript:msgbox(1)", ""},
		{"//evil.com/x", ""},
		{"file:///etc/passwd", ""},
		{"HTTPS://example.com", ""},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range cases {
		if got := safeURL(tc.in); got != tc.want {
			t.Errorf("safeURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseRepoMetadata_dropsUnsafeURLs(t *testing.T) {
	report := `{
		"full_name": "example/x",
		"html_url": "javascript:alert(1)",
		"icon_url": "data:text/html,<script>alert(1)</script>"
	}`
	repo, gdb := runSkillWithReport(t, "repo_metadata", report)
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.HTMLURL != "" {
		t.Errorf("HTMLURL = %q, want empty (javascript: scheme rejected)", got.HTMLURL)
	}
	if got.IconURL != "" {
		t.Errorf("IconURL = %q, want empty (data: scheme rejected)", got.IconURL)
	}
	if got.FullName != "example/x" {
		t.Errorf("safe fields should still be written, got FullName=%q", got.FullName)
	}
}

func TestParsePackages_replacesPackageRows(t *testing.T) {
	report := `{"packages":[
		{"name":"foo","ecosystem":"rubygems","purl":"pkg:gem/foo","latest_version":"1.0.0","downloads":1000000,"dependent_repos":50,"dependent_packages_url":"https://packages.ecosyste.ms/api/v1/registries/rubygems/packages/foo/dependent_packages","metadata":{"foo":"bar"}},
		{"name":"foo-cli","ecosystem":"rubygems"}
	]}`
	repo, gdb := runSkillWithReport(t, "packages", report)
	var rows []db.Package
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Name != "foo" || rows[0].Downloads != 1000000 {
		t.Errorf("row0: %+v", rows[0])
	}
	if rows[0].Metadata == "" {
		t.Error("package metadata blob not stored")
	}
}

func TestParsePackages_riskFlagsCanonicallyOrdered(t *testing.T) {
	report := `{"packages":[
		{"name":"foo","ecosystem":"rubygems","risk_flags":[{"id":"stale_release","evidence":"latest release 2024-01-01"},{"id":"single_maintainer","evidence":"one owner listed"}]},
		{"name":"foo-cli","ecosystem":"rubygems"}
	]}`
	repo, gdb := runSkillWithReport(t, "packages", report)
	var rows []db.Package
	gdb.Where("repository_id = ?", repo.ID).Order("name").Find(&rows)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Name != "foo" || rows[0].RiskFlags != "single_maintainer,stale_release" {
		t.Errorf("row foo RiskFlags = %q, want canonically ordered single_maintainer,stale_release", rows[0].RiskFlags)
	}
	if rows[1].Name != "foo-cli" || rows[1].RiskFlags != "" {
		t.Errorf("row foo-cli RiskFlags = %q, want empty (no risk_flags key)", rows[1].RiskFlags)
	}
}

// An unknown risk-flag id must not cost the package its known flags: the
// scan still needs an accurate row for downstream health scoring.
func TestParsePackagesOutput_dropsUnknownRiskFlagAndWarns(t *testing.T) {
	repo, gdb := runSkillWithReport(t, "packages", `{"packages":[]}`)
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)

	var events []string
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := `{"packages":[{"name":"foo","ecosystem":"rubygems","risk_flags":[{"id":"single_maintainer","evidence":"one owner listed"},{"id":"made_up_flag","evidence":"n/a"}]}]}`
	if err := w.parsePackagesOutput(&scan, report, func(e Event) { events = append(events, e.Text) }); err != nil {
		t.Fatal(err)
	}

	var row db.Package
	if err := gdb.Where("repository_id = ? AND name = ?", repo.ID, "foo").First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.RiskFlags != "single_maintainer" {
		t.Errorf("RiskFlags = %q, want single_maintainer (unknown flag dropped, known flag kept)", row.RiskFlags)
	}
	var warned bool
	for _, e := range events {
		if strings.Contains(e, "made_up_flag") && strings.Contains(e, row.Ecosystem) {
			warned = true
		}
	}
	if !warned {
		t.Errorf("events = %v, want a warning naming the dropped flag and the ecosystem %q", events, row.Ecosystem)
	}
}

// A failed insert must not destroy the existing rows: the delete and the
// re-insert run in one transaction, so a mid-write failure rolls the delete
// back and the repository keeps the packages from its last good scan.
func TestParsePackagesOutput_rollsBackOnInsertFailure(t *testing.T) {
	repo, gdb := runSkillWithReport(t, "packages",
		`{"packages":[{"name":"old","ecosystem":"npm","purl":"pkg:npm/old"}]}`)
	var before int64
	gdb.Model(&db.Package{}).Where("repository_id = ?", repo.ID).Count(&before)
	if before != 1 {
		t.Fatalf("seed rows = %d, want 1", before)
	}

	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)

	const name = "test:fail_packages_insert"
	if err := gdb.Callback().Create().Before("gorm:create").Register(name, func(d *gorm.DB) {
		if d.Statement.Table == "packages" {
			_ = d.AddError(errors.New("injected insert failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := w.parsePackagesOutput(&scan, `{"packages":[{"name":"new","ecosystem":"npm","purl":"pkg:npm/new"}]}`, func(Event) {})
	if err == nil {
		t.Fatal("expected error from the injected insert failure")
	}
	if err := gdb.Callback().Create().Remove(name); err != nil {
		t.Fatal(err)
	}

	var after []db.Package
	gdb.Where("repository_id = ?", repo.ID).Find(&after)
	if len(after) != 1 || after[0].Name != "old" {
		t.Errorf("rows after failed insert = %+v, want [old] (delete must roll back)", after)
	}
}

func TestParseAdvisories_replacesAdvisoryRows(t *testing.T) {
	report := `{"advisories":[
		{"uuid":"u1","url":"https://x","title":"boom","severity":"HIGH","cvss_score":8.1,"classification":"CWE-79","packages":"foo,bar","published_at":"2026-01-01T00:00:00Z"}
	]}`
	repo, gdb := runSkillWithReport(t, "advisories", report)
	var rows []db.Advisory
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	if len(rows) != 1 || rows[0].UUID != "u1" || rows[0].CVSSScore != 8.1 {
		t.Fatalf("rows: %+v", rows)
	}
}

func TestParseAdvisoryAudit_recordsVerdictsAndMapsFindings(t *testing.T) {
	report := `{
		"audits":[
			{"advisory_uuid":"GHSA-fix","status":"fixed","evidence":"Repro fails at HEAD."},
			{"advisory_uuid":"GHSA-bad","status":"bypass","evidence":"Repro fires at HEAD.","finding_ids":["F001"]}
		],
		"findings":[
			{"id":"F001","title":"Bypass of GHSA-bad","severity":"High","confidence":"high","cwe":"CWE-22",
			 "location":"lib/x.rb:10","reachability":"reachable","quality_tier":"high",
			 "trace":"x","boundary":"x","validation":"x","rating":"x",
			 "references":[{"url":"https://github.com/advisories/GHSA-bad","tags":"advisory"}]}
		]
	}`
	repo, gdb := runSkillWithReport(t, "advisory_audit", report)

	var finding db.Finding
	if err := gdb.Where("repository_id = ? AND finding_id = ?", repo.ID, "F001").First(&finding).Error; err != nil {
		t.Fatalf("finding F001 not persisted: %v", err)
	}

	var audits []db.AdvisoryAudit
	gdb.Where("repository_id = ?", repo.ID).Order("advisory_uuid").Find(&audits)
	if len(audits) != 2 {
		t.Fatalf("audits = %d, want 2", len(audits))
	}
	// Ordered by advisory_uuid: GHSA-bad, GHSA-fix.
	if audits[0].AdvisoryUUID != "GHSA-bad" || audits[0].Status != "bypass" {
		t.Errorf("audit[0] = %+v, want GHSA-bad/bypass", audits[0])
	}
	if want := strconv.FormatUint(uint64(finding.ID), 10); audits[0].FindingIDs != want {
		t.Errorf("audit[0].FindingIDs = %q, want %q (mapped db id)", audits[0].FindingIDs, want)
	}
	if audits[1].AdvisoryUUID != "GHSA-fix" || audits[1].Status != "fixed" || audits[1].FindingIDs != "" {
		t.Errorf("audit[1] = %+v, want GHSA-fix/fixed with no findings", audits[1])
	}
}

func TestParseAdvisoryAudit_unknownFindingIDDropped(t *testing.T) {
	// A verdict naming a finding the report never emitted must not carry a
	// dangling id: unresolved report-local ids are dropped, not stored raw.
	report := `{
		"audits":[{"advisory_uuid":"GHSA-x","status":"variant","evidence":"e","finding_ids":["F001","F999"]}],
		"findings":[
			{"id":"F001","title":"t","severity":"Low","confidence":"high","cwe":"",
			 "location":"a.rb:1","reachability":"unclear","quality_tier":"low",
			 "trace":"x","boundary":"x","validation":"x","rating":"x"}
		]
	}`
	repo, gdb := runSkillWithReport(t, "advisory_audit", report)

	var finding db.Finding
	gdb.Where("repository_id = ?", repo.ID).First(&finding)
	var audit db.AdvisoryAudit
	gdb.Where("repository_id = ?", repo.ID).First(&audit)
	if want := strconv.FormatUint(uint64(finding.ID), 10); audit.FindingIDs != want {
		t.Errorf("FindingIDs = %q, want %q (F999 dropped)", audit.FindingIDs, want)
	}
}

// newAdvisoryAuditWorld seeds the repo, skill and scan a direct
// parseAdvisoryAuditOutput call needs, bypassing the full doSkill pipeline.
func newAdvisoryAuditWorld(t *testing.T, failOn string) (*Worker, *db.Skill, *db.Scan, *gorm.DB) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "k", Description: "d", Body: "b", OutputFile: "report.json", OutputKind: "advisory_audit", Version: 1, Active: true, Source: "ui", FailOn: failOn}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)
	return &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, &skill, &scan, gdb
}

func TestParseAdvisoryAudit_rejectsUnknownStatusBeforeWriting(t *testing.T) {
	w, skill, scan, gdb := newAdvisoryAuditWorld(t, "")
	report := `{"audits":[{"advisory_uuid":"u1","status":"held","evidence":"e"}],
		"findings":[{"id":"F001","title":"t","severity":"Low","confidence":"high","cwe":"",
		  "location":"a.rb:1","reachability":"unclear","quality_tier":"low",
		  "trace":"x","boundary":"x","validation":"x","rating":"x"}]}`
	if err := w.parseAdvisoryAuditOutput(skill, scan, report, func(Event) {}); err == nil || !strings.Contains(err.Error(), "held") {
		t.Fatalf("expected unknown-status error, got %v", err)
	}
	// The status gate runs before any write, so neither audits nor findings landed.
	var audits, findings int64
	gdb.Model(&db.AdvisoryAudit{}).Count(&audits)
	gdb.Model(&db.Finding{}).Count(&findings)
	if audits != 0 || findings != 0 {
		t.Errorf("rows written despite rejected report: audits=%d findings=%d", audits, findings)
	}
}

func TestParseAdvisoryAudit_failOnStillWritesVerdicts(t *testing.T) {
	// fail_on reports an error only after ingestFindings persisted the
	// findings, and the pipeline treats that error as "finalized with
	// findings committed" (see maybeFireScanFinalized). The verdicts must
	// land on that path too: it is exactly the run that found a
	// threshold-severity bypass.
	w, skill, scan, gdb := newAdvisoryAuditWorld(t, "High")

	report := `{"audits":[{"advisory_uuid":"GHSA-bad","status":"bypass","evidence":"Repro fires at HEAD.","finding_ids":["F001"]}],
		"findings":[{"id":"F001","title":"Bypass of GHSA-bad","severity":"High","cwe":"CWE-22","location":"lib/x.rb:10"}]}`
	err := w.parseAdvisoryAuditOutput(skill, scan, report, func(Event) {})
	if _, ok := errors.AsType[*FailOnThresholdError](err); !ok {
		t.Fatalf("expected FailOnThresholdError, got %v", err)
	}

	var finding db.Finding
	if err := gdb.Where("repository_id = ?", scan.RepositoryID).First(&finding).Error; err != nil {
		t.Fatalf("finding not persisted on fail_on path: %v", err)
	}
	var audit db.AdvisoryAudit
	if err := gdb.Where("repository_id = ?", scan.RepositoryID).First(&audit).Error; err != nil {
		t.Fatalf("audit verdict not persisted on fail_on path: %v", err)
	}
	if audit.AdvisoryUUID != "GHSA-bad" || audit.Status != "bypass" {
		t.Errorf("audit = %+v, want GHSA-bad/bypass", audit)
	}
	if want := strconv.FormatUint(uint64(finding.ID), 10); audit.FindingIDs != want {
		t.Errorf("FindingIDs = %q, want %q (mapped db id)", audit.FindingIDs, want)
	}
}

func TestParseAdvisoryAudit_rejectsDuplicateAdvisoryBeforeWriting(t *testing.T) {
	w, skill, scan, gdb := newAdvisoryAuditWorld(t, "")

	// The second entry repeats the first advisory modulo whitespace; readers
	// keep one row per advisory, so accepting both would drop a verdict.
	report := `{"audits":[
		{"advisory_uuid":"GHSA-x","status":"fixed","evidence":"held"},
		{"advisory_uuid":" GHSA-x ","status":"bypass","evidence":"broke"}],
		"findings":[{"id":"F001","title":"t","severity":"Low","cwe":"","location":"a.rb:1"}]}`
	if err := w.parseAdvisoryAuditOutput(skill, scan, report, func(Event) {}); err == nil || !strings.Contains(err.Error(), "duplicate advisory audit for GHSA-x") {
		t.Fatalf("expected duplicate-advisory error, got %v", err)
	}
	var audits, findings int64
	gdb.Model(&db.AdvisoryAudit{}).Count(&audits)
	gdb.Model(&db.Finding{}).Count(&findings)
	if audits != 0 || findings != 0 {
		t.Errorf("rows written despite rejected report: audits=%d findings=%d", audits, findings)
	}
}

func TestParseMaintainers_perSubprojectDisclosureChannel(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	sub := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport"}
	gdb.Create(&sub)
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)

	// Attribution on: the per-subproject channel lands on the subproject, the
	// repo-wide channel on the repo.
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MonorepoAttribution: true}
	report := `{"maintainers":[],"disclosure_channel":"repo@example.org","subprojects":[{"path":"activesupport","disclosure_channel":"as@example.org"}]}`
	if err := w.parseMaintainersOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var got db.Subproject
	gdb.First(&got, sub.ID)
	if got.DisclosureChannel != "as@example.org" {
		t.Errorf("subproject channel = %q, want as@example.org", got.DisclosureChannel)
	}
	var r db.Repository
	gdb.First(&r, repo.ID)
	if r.DisclosureChannel != "repo@example.org" {
		t.Errorf("repo channel = %q, want repo@example.org", r.DisclosureChannel)
	}

	// Attribution off: the subproject block is ignored.
	gdb.Model(&db.Subproject{}).Where("id = ?", sub.ID).Update("disclosure_channel", "")
	w2 := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MonorepoAttribution: false}
	report2 := `{"maintainers":[],"subprojects":[{"path":"activesupport","disclosure_channel":"as2@example.org"}]}`
	if err := w2.parseMaintainersOutput(&scan, report2, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	gdb.First(&got, sub.ID)
	if got.DisclosureChannel != "" {
		t.Errorf("attribution off must not write subproject channel, got %q", got.DisclosureChannel)
	}
}

func TestParseMaintainers_scopedRunLeavesRepoWideAlone(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	sub := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport"}
	gdb.Create(&sub)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MonorepoAttribution: true}

	// Seed repo-wide state from a normal repo-root run: two maintainers and a
	// repository disclosure channel.
	root := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&root)
	seed := `{"maintainers":[{"login":"alice","role":"lead","status":"active"},{"login":"bob","role":"dev","status":"active"}],"disclosure_channel":"repo@example.org"}`
	if err := w.parseMaintainersOutput(&root, seed, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	// A sub-path-scoped run reports a fragment (only alice) and a different
	// top-level channel. It must not clobber the repo-wide maintainer list or
	// channel, but must still record the sub-package's own channel.
	scoped := db.Scan{RepositoryID: repo.ID, SubPath: "activesupport"}
	gdb.Create(&scoped)
	report := `{"maintainers":[{"login":"alice","role":"lead","status":"active"}],"disclosure_channel":"WRONG@example.org","subprojects":[{"path":"activesupport","disclosure_channel":"as@example.org"}]}`
	if err := w.parseMaintainersOutput(&scoped, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var r db.Repository
	gdb.First(&r, repo.ID)
	if r.DisclosureChannel != "repo@example.org" {
		t.Errorf("scoped run clobbered repo channel: %q, want repo@example.org", r.DisclosureChannel)
	}
	if n := gdb.Model(&repo).Association("Maintainers").Count(); n != 2 {
		t.Errorf("scoped run changed repo maintainer set: %d associations, want 2 (alice,bob)", n)
	}
	var gotSub db.Subproject
	gdb.First(&gotSub, sub.ID)
	if gotSub.DisclosureChannel != "as@example.org" {
		t.Errorf("scoped run should still record the sub-package channel: %q", gotSub.DisclosureChannel)
	}
}

func TestParseMaintainers_persistsDisclosureChannel(t *testing.T) {
	report := `{
		"maintainers": [
			{"login": "alice", "name": "Alice", "email": "a@example.org", "role": "lead", "status": "active", "evidence": "14 PRs merged"}
		],
		"disclosure_channel": "security@example.org"
	}`
	repo, gdb := runSkillWithReport(t, "maintainers", report)

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.DisclosureChannel != "security@example.org" {
		t.Errorf("DisclosureChannel = %q, want security@example.org", got.DisclosureChannel)
	}
	var m db.Maintainer
	gdb.Where("login = ?", "alice").First(&m)
	if m.Login != "alice" {
		t.Error("maintainer not upserted")
	}
}

func TestParseMaintainers_emptyChannelLeavesRepoAlone(t *testing.T) {
	// If the skill reports no channel, we must not clobber a previous
	// value or an analyst-edited value.
	report := `{"maintainers": [{"login":"a","role":"lead","status":"active"}]}`
	repo, gdb := runSkillWithReport(t, "maintainers", report)
	gdb.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("disclosure_channel", "kept-by-analyst@example.org")

	// Re-run the parser via another skill scan with still no channel.
	report2 := `{"maintainers": []}`
	// Spin up a second scan to invoke the parser again with the same DB.
	skill := db.Skill{Name: "k2", Description: "d", Body: "b", OutputFile: "report.json", OutputKind: "maintainers", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, Model: "fake", SkillID: &skill.ID}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(),
		Runner: fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report2}}, PrepareRepoSrc: stubPrepareRepoSrc}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.DisclosureChannel != "kept-by-analyst@example.org" {
		t.Errorf("prior value clobbered: got %q", got.DisclosureChannel)
	}
}

func TestParsePosture_writesTierAndSummary(t *testing.T) {
	report := `{
		"tier": "partial",
		"summary": "SECURITY.md present but PVR disabled",
		"checks": [{"id":"security_policy","present":true}]
	}`
	repo, gdb := runSkillWithReport(t, "posture", report)
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.Posture != "partial" {
		t.Errorf("Posture = %q, want partial", got.Posture)
	}
	if got.PostureSummary != "SECURITY.md present but PVR disabled" {
		t.Errorf("PostureSummary = %q", got.PostureSummary)
	}
}

func TestParsePosture_rejectsUnknownTier(t *testing.T) {
	gdb, _ := db.Open(filepath.Join(t.TempDir(), "p.db"))
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := w.parsePostureOutput(&scan, `{"tier":"medium"}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "medium") {
		t.Fatalf("expected tier validation error, got %v", err)
	}
}

func TestParsePosture_emptyTierLeavesRepoAlone(t *testing.T) {
	repo, gdb := runSkillWithReport(t, "posture", `{"summary":"x"}`)
	gdb.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("posture", "ready")

	scan := db.Scan{RepositoryID: repo.ID}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parsePostureOutput(&scan, `{"checks":[]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.Posture != "ready" {
		t.Errorf("prior tier clobbered: %q", got.Posture)
	}
}

func runSkillWithFinding(t *testing.T, outputKind, report string, startStatus db.FindingLifecycle) (db.Finding, *gorm.DB) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	priorScan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	gdb.Create(&priorScan)
	finding := db.Finding{ScanID: priorScan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: startStatus}
	gdb.Create(&finding)
	skill := db.Skill{Name: "verify", Description: "d", Body: "b", OutputFile: "report.json", OutputKind: outputKind, Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		Status:       db.ScanQueued,
		Model:        "fake",
		SkillID:      &skill.ID,
		FindingID:    new(finding.ID),
	}
	gdb.Create(&scan)

	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	var refreshed db.Finding
	gdb.First(&refreshed, finding.ID)
	return refreshed, gdb
}

// findingNotes fetches the notes rows for a finding. Used by the verify
// tests to assert the evidence trail lands in FindingNote now that the
// old Finding.Notes column is gone.
func findingNotes(gdb *gorm.DB, findingID uint) []db.FindingNote {
	var rows []db.FindingNote
	gdb.Where("finding_id = ?", findingID).Order("created_at desc").Find(&rows)
	return rows
}

func confirmedVerificationReport(t *testing.T) string {
	return verificationReport(t, "confirmed", nil)
}

func verificationReport(t *testing.T, status string, edit func(*verification.Report)) string {
	t.Helper()
	criterion := verification.Criterion{
		Verdict: "pass", Method: "executed supplied PoC", Evidence: "observed expected behavior", Confidence: "high",
	}
	root := "AT1"
	report := verification.Report{
		Status: "confirmed",
		AttackTree: &verification.AttackTree{
			Goal:    "Trigger the parser panic through the public API",
			RootID:  root,
			Verdict: "reachable",
			Nodes: []verification.AttackTreeNode{
				{ID: root, Kind: "goal", Description: "Trigger parser panic", Status: "satisfied", Evidence: "attempts 1-3 panic at parser.go:42"},
				{ID: "AT2", ParentID: &root, Kind: "entry_point", Description: "Supply input through Parse", Status: "satisfied", Evidence: "api.go:18 calls parser"},
				{ID: "AT3", ParentID: verificationStringPtr("AT2"), Kind: "sink", Description: "Reach parser panic", Status: "satisfied", Evidence: "parser.go:42 panics"},
			},
			Blockers: []string{},
		},
		Attempts: []verification.Attempt{
			{Number: 1, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 2, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
			{Number: 3, Outcome: "reproduced", Evidence: "boom", FailureClass: "panic", CrashSite: "parser.go:42"},
		},
		Criteria: &verification.Criteria{
			PoCWellFormed:                   criterion,
			ReproducesThreeOfThree:          criterion,
			ClaimedFailureClass:             criterion,
			PublicInterfaceToFirstPartySink: criterion,
			Deterministic:                   criterion,
			ControlBypass: &verification.ControlBypass{
				MatchedControls: []string{},
				Assessments:     []verification.ControlAssessment{},
			},
		},
		Reproducer: "go run ./poc.go",
		Evidence:   "3/3 attempts reached parser.go:42",
	}
	switch status {
	case "fixed":
		report.Status = status
		report.AttackTree.Verdict = "blocked"
		report.AttackTree.Nodes[0].Status = "blocked"
		report.AttackTree.Nodes[2].Status = "blocked"
		report.AttackTree.Blockers = []string{"guard rejects the crafted input"}
		for i := range report.Attempts {
			report.Attempts[i].Outcome = "not_reproduced"
			report.Attempts[i].FailureClass = ""
			report.Attempts[i].CrashSite = ""
		}
		report.Criteria.ReproducesThreeOfThree.Verdict = "fail"
	case "inconclusive":
		report.Status = status
		report.AttackTree.Verdict = "unproven"
		report.AttackTree.Nodes[0].Status = "unproven"
		report.AttackTree.Nodes[2].Status = "unproven"
	case "deferred", "not_attempted":
		report.Status = status
		report.AttackTree.Verdict = "not_attempted"
		for i := range report.AttackTree.Nodes {
			report.AttackTree.Nodes[i].Status = "not_attempted"
		}
		for i := range report.Attempts {
			report.Attempts[i].Outcome = "not_attempted"
			report.Attempts[i].FailureClass = ""
			report.Attempts[i].CrashSite = ""
		}
		notAttempted := criterion
		notAttempted.Verdict = "not_attempted"
		report.Criteria = &verification.Criteria{
			PoCWellFormed:                   notAttempted,
			ReproducesThreeOfThree:          notAttempted,
			ClaimedFailureClass:             notAttempted,
			PublicInterfaceToFirstPartySink: notAttempted,
			Deterministic:                   notAttempted,
			ControlBypass: &verification.ControlBypass{
				MatchedControls: []string{},
				Assessments:     []verification.ControlAssessment{},
			},
		}
	}
	if edit != nil {
		edit(&report)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func verificationStringPtr(value string) *string {
	return &value
}

func TestParseVerify_recordsStructuredRubric(t *testing.T) {
	f, gdb := runSkillWithFinding(t, "verify", confirmedVerificationReport(t), db.FindingNew)
	var rows []db.FindingVerification
	if err := gdb.Where("finding_id = ?", f.ID).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("verification rows = %d, want 1", len(rows))
	}
	if rows[0].Status != "confirmed" || rows[0].Score == nil || *rows[0].Score != 1 {
		t.Fatalf("verification = %+v, want confirmed score 1", rows[0])
	}
	note := findingNotes(gdb, f.ID)[0].Body
	if !strings.Contains(note, "score: 1.00") {
		t.Error("verify note should include the derived score")
	}
	if !strings.Contains(note, "attack tree: reachable") {
		t.Error("verify note should include the attack-tree verdict")
	}
	if strings.Contains(note, "control bypass:") {
		t.Error("verify note should omit an empty control-bypass gate")
	}
}

func TestParseVerify_isIdempotentPerScan(t *testing.T) {
	report := confirmedVerificationReport(t)
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	var row db.FindingVerification
	if err := gdb.Where("finding_id = ?", f.ID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	var scan db.Scan
	if err := gdb.First(&scan, row.ScanID).Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var verificationCount int64
	if err := gdb.Model(&db.FindingVerification{}).Where("finding_id = ?", f.ID).Count(&verificationCount).Error; err != nil {
		t.Fatal(err)
	}
	if verificationCount != 1 {
		t.Fatalf("verification rows = %d, want 1", verificationCount)
	}
	if notes := findingNotes(gdb, f.ID); len(notes) != 1 {
		t.Fatalf("verify notes = %d, want 1", len(notes))
	}
}

func TestParseCritic_recordsImmutableAssessmentAndProjection(t *testing.T) {
	report := `{"production_viability":"CONDITIONAL_VIABLE","source_state":"PRESENT","reason":"The parser ships only behind the experimental build tag.","counterevidence":["release workflow omits the tag"],"attacker_position":"remote unauthenticated client","preconditions":["operator enables experimental parser"],"impact":"attacker-controlled input reaches the parser sink","likelihood":"plausible","applied_adjustments":[],"facts_that_would_change_the_result":["a default release enables the parser"]}`
	f, gdb := runSkillWithFinding(t, "critic", report, db.FindingEnriched)
	if f.ProductionViability != db.ProductionViabilityConditionalViable {
		t.Fatalf("production viability = %q, want CONDITIONAL_VIABLE", f.ProductionViability)
	}
	var rows []db.FindingAttackPath
	if err := gdb.Where("finding_id = ?", f.ID).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Report != report {
		t.Fatalf("attack path rows = %+v, want one immutable raw report", rows)
	}
	var scan db.Scan
	if err := gdb.First(&scan, rows[0].ScanID).Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := w.parseCriticOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var count int64
	gdb.Model(&db.FindingAttackPath{}).Where("finding_id = ?", f.ID).Count(&count)
	if count != 1 || len(findingNotes(gdb, f.ID)) != 1 {
		t.Fatalf("parser retry created duplicates: rows=%d notes=%d", count, len(findingNotes(gdb, f.ID)))
	}
}

func TestParseCritic_rejectsMissingSourceAsNonViable(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "critic.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&prior)
	f := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, Title: "x", Severity: "High"}
	gdb.Create(&f)
	scan := db.Scan{RepositoryID: repo.ID, FindingID: new(f.ID)}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := `{"production_viability":"NON_VIABLE","source_state":"MISSING","reason":"path absent","attacker_position":"remote client","impact":"code execution","likelihood":"unknown"}`
	err = w.parseCriticOutput(&scan, report, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "must not classify source_state MISSING as NON_VIABLE") {
		t.Fatalf("error = %v, want source-drift fail-closed error", err)
	}
	var count int64
	gdb.Model(&db.FindingAttackPath{}).Where("finding_id = ?", f.ID).Count(&count)
	if count != 0 {
		t.Fatalf("attack path rows = %d, want 0", count)
	}
}

func TestValidateCriticOutput_allowsMovedViableAndSampleOnly(t *testing.T) {
	for _, viability := range []string{db.ProductionViabilityViable, db.ProductionViabilitySampleOrTest} {
		t.Run(viability, func(t *testing.T) {
			empty := []any{}
			result := criticOutput{
				ProductionViability: viability,
				SourceState:         "MOVED",
				Reason:              "The implementation moved and its current release path was checked.",
				AttackerPosition:    "remote client",
				Impact:              "code execution",
				Likelihood:          "plausible",
				AppliedAdjustments:  &empty,
			}
			if err := validateCriticOutput(result); err != nil {
				t.Fatalf("validateCriticOutput() error = %v", err)
			}
		})
	}
}

func TestParseCritic_usesStoredSeverityWithoutRoundTrip(t *testing.T) {
	report := `{"production_viability":"VIABLE","source_state":"PRESENT","reason":"The shipped server target calls the parser.","counterevidence":[],"attacker_position":"remote client","preconditions":[],"impact":"code execution","likelihood":"plausible","applied_adjustments":[],"facts_that_would_change_the_result":[]}`
	gdb, err := db.Open(filepath.Join(t.TempDir(), "critic.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/critic", Name: "critic"}
	gdb.Create(&repo)
	parent := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&parent)
	finding := db.Finding{ScanID: parent.ID, RepositoryID: repo.ID, Title: "x", Severity: "Unrated"}
	gdb.Create(&finding)
	scan := db.Scan{RepositoryID: repo.ID, FindingID: new(finding.ID), Kind: JobSkill, Status: db.ScanDone, SkillName: criticSkillName}
	gdb.Create(&scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	err = w.parseCriticOutput(&scan, report, func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	var got db.Finding
	if err := gdb.First(&got, finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Severity != "Unrated" {
		t.Fatalf("severity = %q, want stored value unchanged", got.Severity)
	}
	notes := findingNotes(gdb, finding.ID)
	if len(notes) != 1 || !strings.Contains(notes[0].Body, "severity: Unrated") {
		t.Fatalf("critic notes = %+v, want stored severity", notes)
	}
}

func TestParseCritic_rejectsAppliedAdjustments(t *testing.T) {
	report := `{"production_viability":"VIABLE","source_state":"PRESENT","reason":"The shipped server target calls the parser.","counterevidence":[],"attacker_position":"remote client","preconditions":[],"impact":"code execution","likelihood":"plausible","applied_adjustments":[{"kind":"cap"}],"facts_that_would_change_the_result":[]}`
	var result criticOutput
	if err := json.Unmarshal([]byte(report), &result); err != nil {
		t.Fatal(err)
	}
	if err := validateCriticOutput(result); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("error = %v, want applied_adjustments rejection", err)
	}
}

func TestParseCritic_requiresAppliedAdjustmentsArray(t *testing.T) {
	for name, field := range map[string]string{
		"missing": "",
		"null":    `,"applied_adjustments":null`,
	} {
		t.Run(name, func(t *testing.T) {
			report := `{"production_viability":"VIABLE","source_state":"PRESENT","reason":"The shipped server target calls the parser.","counterevidence":[],"attacker_position":"remote client","preconditions":[],"impact":"code execution","likelihood":"plausible"` + field + `,"facts_that_would_change_the_result":[]}`
			var result criticOutput
			if err := json.Unmarshal([]byte(report), &result); err != nil {
				t.Fatal(err)
			}
			if err := validateCriticOutput(result); err == nil || !strings.Contains(err.Error(), "must be present as an empty array") {
				t.Fatalf("error = %v, want required applied_adjustments array rejection", err)
			}
		})
	}
}

func TestParseVerify_invalidRubricIsStoredUngraded(t *testing.T) {
	report := strings.Replace(confirmedVerificationReport(t), `"number":2`, `"number":1`, 1)
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	if f.Status != db.FindingNew {
		t.Fatalf("status = %s, want new: an ungraded report must not change lifecycle", f.Status)
	}
	var row db.FindingVerification
	if err := gdb.Where("finding_id = ?", f.ID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != "confirmed" || row.Score != nil || row.Report != report {
		t.Fatalf("ungraded verification = %+v", row)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) != 1 {
		t.Fatalf("verify notes = %d, want 1", len(notes))
	}
	for _, want := range []string{"grading: ungraded", "not unique", "3/3 attempts reached parser.go:42"} {
		if !strings.Contains(notes[0].Body, want) {
			t.Errorf("ungraded note missing %q: %s", want, notes[0].Body)
		}
	}
}

func TestParseVerify_rejectsPriorRubricWithoutAttackTree(t *testing.T) {
	var report verification.Report
	if err := json.Unmarshal([]byte(confirmedVerificationReport(t)), &report); err != nil {
		t.Fatal(err)
	}
	report.AttackTree = nil
	assertRejectedVerifyReport(t, report, "requires attack_tree")
}

func TestParseVerify_rejectsAttackTreeWithoutCriteria(t *testing.T) {
	var report verification.Report
	if err := json.Unmarshal([]byte(confirmedVerificationReport(t)), &report); err != nil {
		t.Fatal(err)
	}
	report.Criteria = nil
	assertRejectedVerifyReport(t, report, "no grading rubric")
}

func TestParseVerify_storesLiveReportWithoutControlBypassUngraded(t *testing.T) {
	var report verification.Report
	if err := json.Unmarshal([]byte(confirmedVerificationReport(t)), &report); err != nil {
		t.Fatal(err)
	}
	report.Criteria.ControlBypass = nil
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	f, gdb := runSkillWithFinding(t, "verify", string(raw), db.FindingNew)
	if f.Status != db.FindingNew {
		t.Fatalf("status = %s, want new: an ungraded report must not change lifecycle", f.Status)
	}
	var row db.FindingVerification
	if err := gdb.Where("finding_id = ?", f.ID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Status != "confirmed" || row.Score != nil || row.Report != string(raw) {
		t.Fatalf("ungraded verification = %+v", row)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) != 1 || !strings.Contains(notes[0].Body, "verify report requires criteria.control_bypass") {
		t.Fatalf("notes = %+v, want missing control-bypass validation reason", notes)
	}
}

func TestParseVerify_validatesControlBypassAgainstHostMatch(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		matched               []string
		assessments           []verification.ControlAssessment
		threatModel           string
		copyUnavailableReason bool
		wantStatus            db.FindingLifecycle
		wantScore             bool
		wantNotePart          string
	}{
		{
			name:         "matched control bypassed",
			matched:      []string{"web-authz"},
			assessments:  []verification.ControlAssessment{{ControlID: "web-authz", Disposition: "bypassed", Evidence: "attempt reaches the handler without authentication"}},
			threatModel:  controlsModel,
			wantStatus:   db.FindingEnriched,
			wantScore:    true,
			wantNotePart: "control: web-authz = bypassed",
		},
		{
			name:         "reported IDs omit host match",
			matched:      []string{},
			assessments:  []verification.ControlAssessment{},
			threatModel:  controlsModel,
			wantStatus:   db.FindingNew,
			wantScore:    false,
			wantNotePart: "do not match host-resolved controls",
		},
		{
			name:                  "unavailable resolution preserved",
			matched:               []string{},
			assessments:           []verification.ControlAssessment{},
			threatModel:           `{"controls":[`,
			copyUnavailableReason: true,
			wantStatus:            db.FindingEnriched,
			wantScore:             true,
			wantNotePart:          "control resolution unavailable",
		},
		{
			name:         "unavailable resolution omitted",
			matched:      []string{},
			assessments:  []verification.ControlAssessment{},
			threatModel:  `{"controls":[`,
			wantStatus:   db.FindingNew,
			wantScore:    false,
			wantNotePart: "does not match host-resolved reason",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gdb, err := db.Open(filepath.Join(t.TempDir(), "controls-verify.db"))
			if err != nil {
				t.Fatal(err)
			}
			repo := db.Repository{URL: "https://example.com/x", Name: "x", ThreatModel: tc.threatModel}
			if err := gdb.Create(&repo).Error; err != nil {
				t.Fatal(err)
			}
			prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
			gdb.Create(&prior)
			finding := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, Location: "internal/web/server.go:120", Title: "x", Severity: "High", Status: db.FindingNew}
			gdb.Create(&finding)
			scan := db.Scan{RepositoryID: repo.ID, Repository: repo, FindingID: new(finding.ID), SkillName: verifySkillName}
			gdb.Create(&scan)
			report := verificationReport(t, "confirmed", func(report *verification.Report) {
				gate := &verification.ControlBypass{MatchedControls: tc.matched, Assessments: tc.assessments}
				if tc.copyUnavailableReason {
					gate.UnavailableReason = resolveFindingControls(repo.ThreatModel, finding).UnavailableWhy
				}
				report.Criteria.ControlBypass = gate
			})
			w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err != nil {
				t.Fatal(err)
			}
			var refreshed db.Finding
			gdb.First(&refreshed, finding.ID)
			if refreshed.Status != tc.wantStatus {
				t.Fatalf("status = %s, want %s", refreshed.Status, tc.wantStatus)
			}
			var row db.FindingVerification
			gdb.Where("finding_id = ?", finding.ID).First(&row)
			if (row.Score != nil) != tc.wantScore {
				t.Fatalf("score = %v, want present=%t", row.Score, tc.wantScore)
			}
			notes := findingNotes(gdb, finding.ID)
			if len(notes) != 1 || !strings.Contains(notes[0].Body, tc.wantNotePart) {
				t.Fatalf("notes = %+v, want %q", notes, tc.wantNotePart)
			}
		})
	}
}

func assertRejectedVerifyReport(t *testing.T, report verification.Report, wantError string) {
	t.Helper()

	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	f, gdb := runSkillWithFinding(t, "verify", string(raw), db.FindingNew)
	if f.Status != db.FindingNew {
		t.Fatalf("status = %s, want new: a rejected live report must not change lifecycle", f.Status)
	}
	var verificationCount int64
	if err := gdb.Model(&db.FindingVerification{}).Where("finding_id = ?", f.ID).Count(&verificationCount).Error; err != nil {
		t.Fatal(err)
	}
	if verificationCount != 0 {
		t.Fatalf("verification rows = %d, want 0 for a rejected live report", verificationCount)
	}
	var scan db.Scan
	if err := gdb.Where("finding_id = ? AND skill_name = ?", f.ID, "verify").First(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if scan.Status != db.ScanFailed || !strings.Contains(scan.Error, wantError) {
		t.Fatalf("scan status/error = %s/%q, want failed error containing %q", scan.Status, scan.Error, wantError)
	}
}

func TestParseVerify_rejectsLegacyLiveReportWithoutAttackTree(t *testing.T) {
	f, gdb := runSkillWithFinding(t, "verify", `{"status":"inconclusive","notes":"old queued scan"}`, db.FindingNew)
	var verificationCount int64
	if err := gdb.Model(&db.FindingVerification{}).Where("finding_id = ?", f.ID).Count(&verificationCount).Error; err != nil {
		t.Fatal(err)
	}
	if verificationCount != 0 {
		t.Fatalf("verification rows = %d, want 0 for legacy live output", verificationCount)
	}
}

func TestParseVerify_confirmedMovesNewToEnriched(t *testing.T) {
	report := verificationReport(t, "confirmed", func(report *verification.Report) {
		report.Reproducer = "ruby -e 'load %q(./src/x.rb); X.call(%q(../etc))'"
		report.Evidence = "got the same error"
		report.Notes = "no code change"
	})
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	if f.Status != db.FindingEnriched {
		t.Errorf("status = %s, want enriched", f.Status)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "confirmed") {
		t.Errorf("notes missing verify record: %+v", notes)
	}
	body := notes[0].Body
	if !strings.Contains(body, "ruby -e") {
		t.Errorf("reproducer source not recorded in note: %q", body)
	}
	r := strings.Index(body, "ruby -e")
	e := strings.Index(body, "got the same error")
	if r == -1 || e == -1 || r > e {
		t.Errorf("reproducer should land ahead of evidence in note: %q", body)
	}
}

func TestParseVerify_fixedJumpsToFixed(t *testing.T) {
	report := verificationReport(t, "fixed", func(report *verification.Report) {
		report.Evidence = "repro no longer reproduces"
		report.Notes = "commit abc added guard"
	})
	f, _ := runSkillWithFinding(t, "verify", report, db.FindingTriaged)
	if f.Status != db.FindingFixed {
		t.Errorf("status = %s, want fixed", f.Status)
	}
}

func TestParseVerify_fixedAgainstRefDoesNotFlipStatus(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	priorScan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	gdb.Create(&priorScan)
	finding := db.Finding{ScanID: priorScan.ID, RepositoryID: repo.ID, Title: "x", Severity: "High", Status: db.FindingTriaged}
	gdb.Create(&finding)
	// A verify scan the validate-fix pipeline points at a candidate fix ref,
	// not the default branch.
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanRunning,
		SkillName: "verify", FindingID: new(finding.ID), Ref: "fix-branch"}
	gdb.Create(&scan)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := verificationReport(t, "fixed", func(report *verification.Report) {
		report.Evidence = "no longer reproduces on the PR branch"
	})
	if err := w.parseVerifyOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var refreshed db.Finding
	gdb.First(&refreshed, finding.ID)
	if refreshed.Status != db.FindingTriaged {
		t.Errorf("status = %s, want triaged: a fixed verdict on a specific ref must not flip the lifecycle", refreshed.Status)
	}
	notes := findingNotes(gdb, finding.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "fixed") {
		t.Errorf("the per-ref verdict should still be recorded in notes: %+v", notes)
	}
}

func TestParseVerify_inconclusiveLeavesStatus(t *testing.T) {
	report := verificationReport(t, "inconclusive", func(report *verification.Report) {
		report.Notes = "tooling missing"
	})
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	if f.Status != db.FindingNew {
		t.Errorf("status = %s, want new (unchanged)", f.Status)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "inconclusive") {
		t.Errorf("notes missing status header: %+v", notes)
	}
}

func TestParseVerify_deferredLeavesStatusAndRecordsPreflight(t *testing.T) {
	report := verificationReport(t, "deferred", func(report *verification.Report) {
		report.Preflight = &verification.Preflight{
			Classification: "external-reach",
			Justification:  "requests.get('http://169.254.169.254/latest/')",
		}
		report.Notes = "SSRF repro dials link-local metadata; needs a callback listener"
	})
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	if f.Status != db.FindingNew {
		t.Errorf("status = %s, want new (unchanged): deferred means the repro was not run, not that the finding is dead", f.Status)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 {
		t.Fatal("no verify note recorded")
	}
	body := notes[0].Body
	for _, want := range []string{"verify: deferred", "preflight: external-reach", "169.254.169.254", "callback listener"} {
		if !strings.Contains(body, want) {
			t.Errorf("verify note missing %q:\n%s", want, body)
		}
	}
}

func TestParseVerify_deferredRequiresPreflight(t *testing.T) {
	gdb, _ := db.Open(filepath.Join(t.TempDir(), "d.db"))
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&prior)
	finding := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, Title: "x", Severity: "High", Status: db.FindingNew}
	gdb.Create(&finding)
	scan := &db.Scan{RepositoryID: repo.ID, FindingID: new(finding.ID)}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	for name, report := range map[string]string{
		"missing preflight": verificationReport(t, "deferred", func(report *verification.Report) {
			report.Preflight = nil
		}),
		"empty class": verificationReport(t, "deferred", func(report *verification.Report) {
			report.Preflight = &verification.Preflight{Justification: "x"}
		}),
		"empty justification": verificationReport(t, "deferred", func(report *verification.Report) {
			report.Preflight = &verification.Preflight{Classification: "external-reach", Justification: "  "}
		}),
	} {
		if err := w.parseVerifyOutput(scan, report, func(Event) {}); err == nil || !strings.Contains(err.Error(), "requires preflight") {
			t.Errorf("%s: want deferred-requires-preflight error, got %v", name, err)
		}
	}
	// deferred WITH preflight is fine (covered in the main deferred test),
	// and inconclusive without preflight is also fine (early-exit cases).
	inconclusive := verificationReport(t, "inconclusive", func(report *verification.Report) {
		report.Notes = "no finding_id"
	})
	if err := w.parseVerifyOutput(scan, inconclusive, func(Event) {}); err != nil {
		t.Errorf("inconclusive without preflight should be accepted: %v", err)
	}
}

func TestParseVerify_preflightRecordedOnConfirmed(t *testing.T) {
	report := verificationReport(t, "confirmed", func(report *verification.Report) {
		report.Preflight = &verification.Preflight{Classification: "local-safe", Justification: "stdin only"}
		report.Reproducer = "echo x | ./bin"
		report.Evidence = "boom"
	})
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	if f.Status != db.FindingEnriched {
		t.Errorf("status = %s, want enriched", f.Status)
	}
	body := findingNotes(gdb, f.ID)[0].Body
	if !strings.Contains(body, "preflight: local-safe") {
		t.Errorf("preflight classification not recorded in note: %q", body)
	}
	// Preflight lands between the header and the reproducer so the note
	// reads in the same order the skill worked: classify, run, observe.
	p := strings.Index(body, "preflight:")
	r := strings.Index(body, "echo x")
	if p == -1 || r == -1 || p > r {
		t.Errorf("preflight should land ahead of reproducer in note: %q", body)
	}
}

func TestParseVerify_rejectsUnknownStatus(t *testing.T) {
	gdb, _ := db.Open(filepath.Join(t.TempDir(), "u.db"))
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&prior)
	finding := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, Title: "x", Severity: "High", Status: db.FindingNew}
	gdb.Create(&finding)
	scan := db.Scan{RepositoryID: repo.ID, FindingID: new(finding.ID)}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := verificationReport(t, "confirmed", func(report *verification.Report) {
		report.Status = "maybe"
	})
	err := w.parseVerifyOutput(&scan, report, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "confirmed|fixed|inconclusive|deferred") {
		t.Errorf("want unknown-status error listing all four values, got %v", err)
	}
}

func TestParseBreakingChange_writesVerdictAndRationale(t *testing.T) {
	report := `{
		"verdict": "breaking",
		"rationale": "removes the public Init() return type.",
		"api_changes": [{"kind":"signature_change","symbol":"foo.Init","diff_lines":"foo.go:10-12"}],
		"affected_dependents": [{"name":"@scope/cli","registry":"npm","reason":"calls Init directly"}]
	}`
	f, gdb := runSkillWithFinding(t, "breaking_change", report, db.FindingTriaged)
	if f.BreakingChange != "breaking" {
		t.Errorf("verdict = %q, want breaking", f.BreakingChange)
	}
	if !strings.Contains(f.BreakingChangeRationale, "Affected dependents:") {
		t.Errorf("rationale missing dependent list: %q", f.BreakingChangeRationale)
	}
	if !strings.Contains(f.BreakingChangeRationale, "API changes:") {
		t.Errorf("rationale missing API changes: %q", f.BreakingChangeRationale)
	}
	var hist db.FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", f.ID, "breaking_change").First(&hist).Error; err != nil {
		t.Fatalf("missing breaking_change history: %v", err)
	}
	if hist.By != "breaking-change" || hist.NewValue != "breaking" {
		t.Errorf("history = %+v", hist)
	}
}

func TestParseBreakingChange_nonBreakingNoListSection(t *testing.T) {
	report := `{"verdict":"non_breaking","rationale":"diff is a pure addition of an optional argument."}`
	f, _ := runSkillWithFinding(t, "breaking_change", report, db.FindingTriaged)
	if f.BreakingChange != "non_breaking" {
		t.Errorf("verdict = %q", f.BreakingChange)
	}
	if strings.Contains(f.BreakingChangeRationale, "Affected dependents:") {
		t.Errorf("rationale should not include empty dependent list: %q", f.BreakingChangeRationale)
	}
}

func TestParseBreakingChange_rejectsUnknownVerdict(t *testing.T) {
	w := &Worker{}
	scan := &db.Scan{}
	err := w.parseBreakingChangeOutput(scan, `{"verdict":"breaking","rationale":"x"}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Fatalf("missing-finding error = %v", err)
	}
	fid := uint(1)
	scan.FindingID = &fid
	err = w.parseBreakingChangeOutput(scan, `{"verdict":"maybe","rationale":"x"}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "verdict") {
		t.Errorf("unknown-verdict error = %v", err)
	}
}

func TestParseRevalidate_truePositiveMovesNewToEnriched(t *testing.T) {
	report := `{"verdict":"true_positive","reason":"sink at line 42 still reaches user input; git log shows no guard added"}`
	f, gdb := runSkillWithFinding(t, "revalidate", report, db.FindingNew)
	if f.Status != db.FindingEnriched {
		t.Errorf("status = %s, want enriched", f.Status)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "true_positive") {
		t.Errorf("notes missing revalidate verdict: %+v", notes)
	}
}

func TestParseRevalidate_alreadyFixedMovesOpenFindingToFixed(t *testing.T) {
	report := `{"verdict":"already_fixed","reason":"commit abc1234 added a containment check before opening the path"}`
	f, gdb := runSkillWithFinding(t, "revalidate", report, db.FindingReady)
	if f.Status != db.FindingFixed {
		t.Errorf("status = %s, want fixed", f.Status)
	}
	if f.LastRevalidateVerdict != "already_fixed" {
		t.Errorf("last_revalidate_verdict = %q, want already_fixed", f.LastRevalidateVerdict)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "commit abc1234") {
		t.Errorf("notes missing already_fixed evidence: %+v", notes)
	}
	var hist db.FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", f.ID, "status").First(&hist).Error; err != nil {
		t.Fatalf("status history missing: %v", err)
	}
	if hist.By != "revalidate" || hist.OldValue != string(db.FindingReady) || hist.NewValue != string(db.FindingFixed) {
		t.Errorf("status history = %+v, want ready -> fixed by revalidate", hist)
	}
}

func TestParseRevalidate_recordsPrivilegeRequired(t *testing.T) {
	report := `{"verdict":"true_positive","reason":"trace holds","privilege_required":"authenticated"}`
	f, gdb := runSkillWithFinding(t, "revalidate", report, db.FindingNew)
	body := findingNotes(gdb, f.ID)[0].Body
	if !strings.Contains(body, "privilege: authenticated") {
		t.Errorf("privilege line missing from note: %q", body)
	}
	// The privilege line sits directly under the verdict header, above the
	// reason paragraph, so an analyst scanning the notes column sees it
	// without reading the prose.
	v := strings.Index(body, "revalidate:")
	p := strings.Index(body, "privilege:")
	r := strings.Index(body, "trace holds")
	if v == -1 || p == -1 || r == -1 || v >= p || p >= r {
		t.Errorf("want verdict < privilege < reason ordering, got %q", body)
	}
	_ = f
}

func TestParseRevalidate_rejectsUnknownPrivilege(t *testing.T) {
	gdb, _ := db.Open(filepath.Join(t.TempDir(), "p.db"))
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	gdb.Create(&prior)
	finding := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, Title: "x", Severity: "High", Status: db.FindingNew}
	gdb.Create(&finding)
	scan := &db.Scan{RepositoryID: repo.ID, FindingID: new(finding.ID)}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err := w.parseRevalidateOutput(scan, `{"verdict":"true_positive","reason":"x","privilege_required":"superuser"}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "none|authenticated|admin|maintainer|local-root") {
		t.Errorf("want unknown-privilege error listing the enum, got %v", err)
	}
	// Empty is permitted (false_positive/already_fixed omit it).
	if err := w.parseRevalidateOutput(scan, `{"verdict":"false_positive","reason":"x"}`, func(Event) {}); err != nil {
		t.Errorf("empty privilege_required should be accepted: %v", err)
	}
}

func TestParseTimeField_emitsOnUnparseable(t *testing.T) {
	var events []Event
	emit := func(e Event) { events = append(events, e) }

	if _, ok := parseTimeField(emit, "pushed_at", "2026-06-01T12:00:00Z"); !ok {
		t.Error("RFC3339 should parse")
	}
	if _, ok := parseTimeField(emit, "pushed_at", "2026-06-01"); !ok {
		t.Error("date-only should parse")
	}
	if _, ok := parseTimeField(emit, "pushed_at", ""); ok {
		t.Error("empty should return ok=false")
	}
	if len(events) != 0 {
		t.Errorf("valid/empty inputs should not emit: %+v", events)
	}

	if _, ok := parseTimeField(emit, "pushed_at", "yesterday"); ok {
		t.Error("garbage should return ok=false")
	}
	if len(events) != 1 || !strings.Contains(events[0].Text, `pushed_at value "yesterday"`) {
		t.Errorf("unparseable input should emit a transcript line: %+v", events)
	}
}

func TestParseRevalidate_skipsClosedFinding(t *testing.T) {
	// A concurrent finding-dedup pass may close the finding between enqueue
	// and run. Revalidate must not promote it, cache a verdict, or chain a
	// verify on it.
	report := `{"verdict":"true_positive","reason":"sink still reachable"}`
	f, gdb := runSkillWithFinding(t, "revalidate", report, db.FindingDuplicate)
	if f.Status != db.FindingDuplicate {
		t.Errorf("status = %s, want duplicate (unchanged)", f.Status)
	}
	if f.LastRevalidateVerdict != "" {
		t.Errorf("last_revalidate_verdict = %q, want empty (no write on closed finding)", f.LastRevalidateVerdict)
	}
	if notes := findingNotes(gdb, f.ID); len(notes) != 0 {
		t.Errorf("want no notes on a skipped finding, got %+v", notes)
	}
}

func TestParseRevalidate_falsePositiveDoesNotAutoReject(t *testing.T) {
	report := `{"verdict":"false_positive","reason":"the path lives under test/ fixtures; threat model disclaims it"}`
	f, gdb := runSkillWithFinding(t, "revalidate", report, db.FindingNew)
	if f.Status != db.FindingNew {
		t.Errorf("status = %s, want new (analyst owns rejection)", f.Status)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "false_positive") {
		t.Errorf("notes missing revalidate verdict: %+v", notes)
	}
}

func TestParseRevalidate_uncertainLeavesStatus(t *testing.T) {
	report := `{"verdict":"uncertain","reason":"validation prose is missing the trigger; cannot decide from git log alone"}`
	f, _ := runSkillWithFinding(t, "revalidate", report, db.FindingNew)
	if f.Status != db.FindingNew {
		t.Errorf("status = %s, want new (unchanged)", f.Status)
	}
}

func TestParseRevalidate_adjustedSeverityWritesFieldAndHistory(t *testing.T) {
	report := `{"verdict":"true_positive","reason":"sink still live","adjusted_severity":"Medium","adjusted_severity_reason":"requires authenticated session"}`
	f, gdb := runSkillWithFinding(t, "revalidate", report, db.FindingNew)
	if f.Severity != "Medium" {
		t.Errorf("severity = %s, want Medium (the adjusted value)", f.Severity)
	}
	var hist db.FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", f.ID, "severity").First(&hist).Error; err != nil {
		t.Fatalf("missing severity history row: %v", err)
	}
	if hist.By != "revalidate" || hist.NewValue != "Medium" {
		t.Errorf("history = %+v", hist)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "-> Medium") {
		t.Errorf("note missing severity transition: %+v", notes)
	}
}

func TestParseRevalidate_invokesCallbackWithFinalSeverity(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "rcb.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	priorScan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	gdb.Create(&priorScan)
	f := db.Finding{ScanID: priorScan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "t", Severity: "Critical", Status: db.FindingNew}
	gdb.Create(&f)

	var gotVerdict, gotSeverity string
	var gotFindingID uint
	w := &Worker{
		DB:  gdb,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnRevalidateVerdict: func(_ *db.Scan, finding *db.Finding, verdict, severity string) {
			gotVerdict = verdict
			gotSeverity = severity
			gotFindingID = finding.ID
		},
	}
	fid := f.ID
	scan := &db.Scan{RepositoryID: repo.ID, SkillName: "revalidate", FindingID: &fid}
	report := `{"verdict":"true_positive","reason":"sink still live","adjusted_severity":"Medium","adjusted_severity_reason":"requires auth"}`
	if err := w.parseRevalidateOutput(scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if gotVerdict != "true_positive" {
		t.Errorf("verdict = %q, want true_positive", gotVerdict)
	}
	if gotSeverity != "Medium" {
		t.Errorf("severity = %q, want Medium (the adjusted value)", gotSeverity)
	}
	if gotFindingID != f.ID {
		t.Errorf("finding id = %d, want %d", gotFindingID, f.ID)
	}
}

func TestParseRevalidate_callbackGetsOriginalSeverityWhenUnadjusted(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "rcbu.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	priorScan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	gdb.Create(&priorScan)
	f := db.Finding{ScanID: priorScan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "t", Severity: "High", Status: db.FindingNew}
	gdb.Create(&f)

	var gotSeverity string
	w := &Worker{
		DB:  gdb,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnRevalidateVerdict: func(_ *db.Scan, _ *db.Finding, _, severity string) {
			gotSeverity = severity
		},
	}
	fid := f.ID
	scan := &db.Scan{RepositoryID: repo.ID, SkillName: "revalidate", FindingID: &fid}
	if err := w.parseRevalidateOutput(scan, `{"verdict":"true_positive","reason":"x"}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if gotSeverity != "High" {
		t.Errorf("severity = %q, want High (the original)", gotSeverity)
	}
}

func TestParseRevalidate_rejectsUnknownVerdict(t *testing.T) {
	w := &Worker{}
	scan := &db.Scan{}
	err := w.parseRevalidateOutput(scan, `{"verdict":"true_positive","reason":"x"}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Fatalf("missing-finding error = %v", err)
	}
	fid := uint(1)
	scan.FindingID = &fid
	err = w.parseRevalidateOutput(scan, `{"verdict":"banana","reason":"x"}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "verdict") {
		t.Errorf("unknown-verdict error = %v", err)
	}
}

func TestParseMitigation_writesGuidanceAndRule(t *testing.T) {
	report := `{
		"guidance": "## Workarounds\n\nDisable the eval flag.\n\n## Detection\n\nWatch for stack frames matching foo.eval.",
		"semgrep_rule": "rules:\n  - id: foo-eval\n    pattern: foo.eval(...)\n    message: 'foo.eval is vulnerable to CVE-2026-XXXX'\n    severity: ERROR\n    languages: [go]"
	}`
	f, gdb := runSkillWithFinding(t, "mitigation", report, db.FindingTriaged)
	if !strings.Contains(f.Mitigation, "Workarounds") {
		t.Errorf("Mitigation missing workarounds section: %q", f.Mitigation)
	}
	if !strings.Contains(f.MitigationSemgrep, "foo-eval") {
		t.Errorf("MitigationSemgrep missing rule id: %q", f.MitigationSemgrep)
	}
	var hist db.FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", f.ID, "mitigation").First(&hist).Error; err != nil {
		t.Fatalf("missing mitigation history: %v", err)
	}
	if hist.By != "mitigate" {
		t.Errorf("history.By = %q, want mitigate", hist.By)
	}
}

func TestParseMitigation_emptySemgrepClearsRule(t *testing.T) {
	report := `{"guidance":"## Workarounds\n\nset debug=false","semgrep_rule":""}`
	f, _ := runSkillWithFinding(t, "mitigation", report, db.FindingTriaged)
	if f.MitigationSemgrep != "" {
		t.Errorf("MitigationSemgrep should remain empty, got %q", f.MitigationSemgrep)
	}
	if f.Mitigation == "" {
		t.Errorf("Mitigation should be populated")
	}
}

func TestParseMitigation_rejectsEmptyGuidance(t *testing.T) {
	w := &Worker{}
	scan := &db.Scan{}
	if err := w.parseMitigationOutput(scan, `{"guidance":"  "}`, func(Event) {}); err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Fatalf("expected missing finding_id error, got %v", err)
	}
	fid := uint(1)
	scan.FindingID = &fid
	err := w.parseMitigationOutput(scan, `{"guidance":"   "}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "empty guidance") {
		t.Errorf("expected empty-guidance error, got %v", err)
	}
}

func TestParseReleaseWatch_releasedWritesColumnsAndReference(t *testing.T) {
	report := `{
		"released": true,
		"release_tag": "v2.3.1",
		"release_url": "https://github.com/example/lib/releases/tag/v2.3.1",
		"release_at": "2026-06-02T14:00:00Z",
		"notes": "matched by fix_commit"
	}`
	f, gdb := runSkillWithFinding(t, "release_watch", report, db.FindingFixed)
	if f.ReleaseTag != "v2.3.1" {
		t.Errorf("ReleaseTag = %q, want v2.3.1", f.ReleaseTag)
	}
	if f.ReleaseURL == "" {
		t.Errorf("ReleaseURL empty")
	}
	if f.ReleasedAt == nil {
		t.Fatalf("ReleasedAt is nil")
	}
	if !f.ReleasedAt.Equal(time.Date(2026, 6, 2, 14, 0, 0, 0, time.UTC)) {
		t.Errorf("ReleasedAt = %v", f.ReleasedAt)
	}
	var refs []db.FindingReference
	gdb.Where("finding_id = ?", f.ID).Find(&refs)
	if len(refs) != 1 || refs[0].Tags != "upstream-release" {
		t.Errorf("references = %+v, want one upstream-release", refs)
	}
	var hist []db.FindingHistory
	gdb.Where("finding_id = ? AND field IN ?", f.ID, []string{"release_tag", "release_url", "released_at"}).Find(&hist)
	if len(hist) != 3 {
		t.Errorf("history rows = %d, want 3 (tag/url/released_at): %+v", len(hist), hist)
	}
}

func TestParseReleaseWatch_idempotentOnRepeatedRun(t *testing.T) {
	report := `{
		"released": true,
		"release_tag": "v2.3.1",
		"release_url": "https://github.com/example/lib/releases/tag/v2.3.1",
		"release_at": "2026-06-02T14:00:00Z",
		"notes": "matched by fix_commit"
	}`
	f, gdb := runSkillWithFinding(t, "release_watch", report, db.FindingFixed)

	// Replay the parser by hand against the same finding row so we are
	// testing the parser's idempotency contract (the SKILL.md says
	// "Idempotent: a finding with a release already recorded re-confirms
	// the existing value rather than flapping").
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	scan := &db.Scan{RepositoryID: f.RepositoryID, FindingID: &f.ID, SkillName: "release-watch"}
	if err := w.parseReleaseWatchOutput(scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var refs []db.FindingReference
	gdb.Where("finding_id = ? AND tags = ?", f.ID, "upstream-release").Find(&refs)
	if len(refs) != 1 {
		t.Errorf("references = %d, want 1 (re-run must not duplicate the reference row)", len(refs))
	}
	// History rows: the no-op WriteFindingField / WriteFindingTimeField
	// path means the second run logs no new history.
	var hist []db.FindingHistory
	gdb.Where("finding_id = ? AND field IN ?", f.ID, []string{"release_tag", "release_url", "released_at"}).Find(&hist)
	if len(hist) != 3 {
		t.Errorf("history rows = %d, want 3 (one per field, unchanged on re-run): %+v", len(hist), hist)
	}
}

func TestParseReleaseWatch_notReleasedAddsNote(t *testing.T) {
	report := `{"released": false, "notes": "latest release v2.2.0 predates fix_commit"}`
	f, gdb := runSkillWithFinding(t, "release_watch", report, db.FindingFixed)
	if f.ReleaseTag != "" {
		t.Errorf("ReleaseTag should remain empty: %q", f.ReleaseTag)
	}
	var notes []db.FindingNote
	gdb.Where(map[string]any{"finding_id": f.ID, "by": "release-watch"}).Find(&notes)
	if len(notes) != 1 || !strings.Contains(notes[0].Body, "not released") {
		t.Errorf("notes = %+v, want one release-watch note", notes)
	}
}

func TestParseReleaseWatch_rejectsMissingTimestamp(t *testing.T) {
	w := &Worker{}
	scan := &db.Scan{}
	if err := w.parseReleaseWatchOutput(scan, `{"released":true,"release_tag":"v1","release_url":"http://x"}`, func(Event) {}); err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Fatalf("missing finding_id error = %v", err)
	}
	fid := uint(1)
	scan.FindingID = &fid
	err := w.parseReleaseWatchOutput(scan, `{"released":true,"release_tag":"v1","release_url":"http://x","release_at":"not-a-date"}`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "release_at") {
		t.Errorf("expected release_at parse error, got %v", err)
	}
}

func TestParseDisclose_postsSummaryNote(t *testing.T) {
	report := `{
		"ghsa": {"summary": "Command injection in run()"},
		"patched": ["cvss_vector", "affected", "disclosure_draft", "suggested_recipients"],
		"preserved": ["title"],
		"suggested_recipients": "@alice (CODEOWNERS: crypto/*), @org/crypto-team (CODEOWNERS: crypto/*)",
		"references_added": 2,
		"references_skipped": 1,
		"notes": "Source-only advisory; no published packages."
	}`
	f, gdb := runSkillWithFinding(t, "disclose", report, db.FindingTriaged)

	var notes []db.FindingNote
	gdb.Where(map[string]any{"finding_id": f.ID, "by": "disclose"}).Find(&notes)
	if len(notes) != 1 {
		t.Fatalf("want one disclose note, got %d: %+v", len(notes), notes)
	}
	body := notes[0].Body
	for _, want := range []string{
		`disclose: drafted "Command injection in run()"`,
		"Patched: cvss_vector, affected, disclosure_draft, suggested_recipients",
		"Preserved: title",
		"Suggested recipients: @alice (CODEOWNERS: crypto/*), @org/crypto-team (CODEOWNERS: crypto/*)",
		"References: 2 added, 1 skipped",
		"Source-only advisory; no published packages.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("note body missing %q:\n%s", want, body)
		}
	}
}

func TestParseDisclose_omitsRecipientsLineWhenEmpty(t *testing.T) {
	report := `{"ghsa": {"summary": "X"}, "patched": ["disclosure_draft"]}`
	f, gdb := runSkillWithFinding(t, "disclose", report, db.FindingTriaged)

	var notes []db.FindingNote
	gdb.Where("finding_id = ? AND `by` = ?", f.ID, "disclose").Find(&notes)
	if len(notes) != 1 {
		t.Fatalf("want one disclose note, got %d", len(notes))
	}
	if strings.Contains(notes[0].Body, "Suggested recipients") {
		t.Errorf("note body should not mention recipients when the report has none:\n%s", notes[0].Body)
	}
}

func TestParseDisclose_errorReportRecordsRefusal(t *testing.T) {
	report := `{"error": "finding has no Trace prose; cannot draft a description"}`
	f, gdb := runSkillWithFinding(t, "disclose", report, db.FindingNew)

	var notes []db.FindingNote
	gdb.Where(map[string]any{"finding_id": f.ID, "by": "disclose"}).Find(&notes)
	if len(notes) != 1 {
		t.Fatalf("want one disclose note, got %d", len(notes))
	}
	if !strings.Contains(notes[0].Body, "disclose: refused") {
		t.Errorf("note body = %q, want refused header", notes[0].Body)
	}
	if !strings.Contains(notes[0].Body, "no Trace prose") {
		t.Errorf("note body = %q, want error reason", notes[0].Body)
	}
}

func TestParseDisclose_requiresFindingID(t *testing.T) {
	w := &Worker{}
	if err := w.parseDiscloseOutput(&db.Scan{}, `{}`, func(Event) {}); err == nil || !strings.Contains(err.Error(), "finding_id") {
		t.Errorf("missing finding_id error = %v", err)
	}
}

func TestParseFindingDedup_marksDuplicatesWithHistoryAndNote(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "dedup.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, SkillName: "finding-dedup"}
	gdb.Create(&scan)
	canonical := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "canonical", Severity: "High", Status: db.FindingTriaged}
	duplicate := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F2", Title: "duplicate", Severity: "High", Status: db.FindingNew}
	gdb.Create(&canonical)
	gdb.Create(&duplicate)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := `{"duplicates":[{"canonical_id":` + strconv.Itoa(int(canonical.ID)) + `,"duplicate_ids":[` + strconv.Itoa(int(duplicate.ID)) + `],"reason":"same sink and dataflow; only the line range differs"}]}`
	if err := w.parseFindingDedupOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var refreshed db.Finding
	gdb.First(&refreshed, duplicate.ID)
	if refreshed.Status != db.FindingDuplicate {
		t.Fatalf("status = %s, want duplicate", refreshed.Status)
	}
	var hist db.FindingHistory
	if err := gdb.Where("finding_id = ? AND field = ?", duplicate.ID, "status").First(&hist).Error; err != nil {
		t.Fatalf("missing status history: %v", err)
	}
	if hist.By != findingDedupSkill || hist.NewValue != string(db.FindingDuplicate) {
		t.Fatalf("history = %+v", hist)
	}
	notes := findingNotes(gdb, duplicate.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "duplicates finding #") {
		t.Fatalf("missing dedup note: %+v", notes)
	}
}

// setupDedupRepo creates a repo, a scan, and n open findings, returning the
// scan and the findings in creation order. Cuts the boilerplate the
// duplicate/subsumed/chain tests each repeat.
func setupDedupRepo(t *testing.T, gdb *gorm.DB, n int) (db.Scan, []db.Finding) {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, SkillName: "finding-dedup"}
	gdb.Create(&scan)
	fs := make([]db.Finding, n)
	for i := range fs {
		fs[i] = db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F" + strconv.Itoa(i+1),
			Title: "f" + strconv.Itoa(i+1), Severity: "High", Status: db.FindingNew}
		gdb.Create(&fs[i])
	}
	return scan, fs
}

func TestParseFindingDedup_subsumedNotesWithoutStatusChange(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "sub.db"))
	if err != nil {
		t.Fatal(err)
	}
	scan, fs := setupDedupRepo(t, gdb, 3)
	parent, childA, childB := fs[0], fs[1], fs[2]

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := fmt.Sprintf(`{"duplicates":[],"subsumed":[{"parent_id":%d,"subsumed_ids":[%d,%d],"reason":"only reachable via the unauth admin route in the parent"}]}`,
		parent.ID, childA.ID, childB.ID)
	if err := w.parseFindingDedupOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	for _, child := range []db.Finding{childA, childB} {
		var got db.Finding
		gdb.First(&got, child.ID)
		if got.Status != db.FindingNew {
			t.Errorf("child %d status = %s; subsumed must not change lifecycle", child.ID, got.Status)
		}
		notes := findingNotes(gdb, child.ID)
		if len(notes) == 0 {
			t.Fatalf("child %d: no note", child.ID)
		}
		wantHeader := fmt.Sprintf("finding-dedup: subsumed by finding #%d", parent.ID)
		if !strings.HasPrefix(notes[0].Body, wantHeader) {
			t.Errorf("child %d note header = %q, want prefix %q", child.ID, firstLine(notes[0].Body), wantHeader)
		}
		if !strings.Contains(notes[0].Body, "unauth admin route") {
			t.Errorf("child %d note missing reason", child.ID)
		}
	}
	if len(findingNotes(gdb, parent.ID)) != 0 {
		t.Error("parent should not get a subsumed note; only children carry the marker")
	}
}

func TestParseFindingDedup_chainsNotesEachMemberWithOthers(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "chain.db"))
	if err != nil {
		t.Fatal(err)
	}
	scan, fs := setupDedupRepo(t, gdb, 3)
	a, b, c := fs[0], fs[1], fs[2]

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := fmt.Sprintf(`{"duplicates":[],"chains":[{"finding_ids":[%d,%d,%d],"reason":"traversal + predictable secret path = credential disclosure"}]}`,
		a.ID, b.ID, c.ID)
	if err := w.parseFindingDedupOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	// Each member's note lists the OTHER members, not itself, so disclose on
	// any one of them can fetch exactly the ids it needs to compose.
	cases := []struct {
		on     db.Finding
		others []uint
	}{
		{a, []uint{b.ID, c.ID}},
		{b, []uint{a.ID, c.ID}},
		{c, []uint{a.ID, b.ID}},
	}
	for _, tc := range cases {
		var got db.Finding
		gdb.First(&got, tc.on.ID)
		if got.Status != db.FindingNew {
			t.Errorf("chain member %d status = %s; chains must not change lifecycle", tc.on.ID, got.Status)
		}
		notes := findingNotes(gdb, tc.on.ID)
		if len(notes) == 0 {
			t.Fatalf("member %d: no note", tc.on.ID)
		}
		header := firstLine(notes[0].Body)
		if !strings.HasPrefix(header, "finding-dedup: chains with finding #") {
			t.Errorf("member %d header = %q", tc.on.ID, header)
		}
		for _, other := range tc.others {
			if !strings.Contains(header, fmt.Sprintf("#%d", other)) {
				t.Errorf("member %d header missing #%d: %q", tc.on.ID, other, header)
			}
		}
		if strings.Contains(header, fmt.Sprintf("#%d", tc.on.ID)) {
			t.Errorf("member %d header should not reference itself: %q", tc.on.ID, header)
		}
	}
}

func TestParseFindingDedup_chainOfOneAfterFilterIsNoop(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "chain1.db"))
	if err != nil {
		t.Fatal(err)
	}
	scan, fs := setupDedupRepo(t, gdb, 2)
	// Close the second so only one open member survives the repo/open filter.
	gdb.Model(&fs[1]).Update("status", db.FindingRejected)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := fmt.Sprintf(`{"duplicates":[],"chains":[{"finding_ids":[%d,%d],"reason":"x"}]}`, fs[0].ID, fs[1].ID)
	if err := w.parseFindingDedupOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if len(findingNotes(gdb, fs[0].ID)) != 0 {
		t.Error("chain with a single surviving member should write no notes")
	}
}

func TestParseFindingDedup_subsumedSkipsClosedParentAndSelfRef(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "subskip.db"))
	if err != nil {
		t.Fatal(err)
	}
	scan, fs := setupDedupRepo(t, gdb, 2)
	gdb.Model(&fs[0]).Update("status", db.FindingFixed) // closed parent

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := fmt.Sprintf(`{"duplicates":[],"subsumed":[{"parent_id":%d,"subsumed_ids":[%d],"reason":"x"},{"parent_id":%d,"subsumed_ids":[%d],"reason":"self"}]}`,
		fs[0].ID, fs[1].ID, fs[1].ID, fs[1].ID)
	if err := w.parseFindingDedupOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if len(findingNotes(gdb, fs[1].ID)) != 0 {
		t.Error("closed parent and self-reference should both be skipped")
	}
}

func TestParseFindingDedup_skipsClosedAndCrossRepoFindings(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "dedup-skip.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	otherRepo := db.Repository{URL: "https://example.com/y", Name: "y"}
	gdb.Create(&repo)
	gdb.Create(&otherRepo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, SkillName: "finding-dedup"}
	gdb.Create(&scan)
	canonical := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "canonical", Severity: "High", Status: db.FindingTriaged}
	closed := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F2", Title: "closed", Severity: "High", Status: db.FindingFixed}
	crossRepo := db.Finding{ScanID: scan.ID, RepositoryID: otherRepo.ID, FindingID: "F3", Title: "cross", Severity: "High", Status: db.FindingNew}
	gdb.Create(&canonical)
	gdb.Create(&closed)
	gdb.Create(&crossRepo)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := `{"duplicates":[{"canonical_id":` + strconv.Itoa(int(canonical.ID)) + `,"duplicate_ids":[` + strconv.Itoa(int(closed.ID)) + `,` + strconv.Itoa(int(crossRepo.ID)) + `],"reason":"same issue"}]}`
	if err := w.parseFindingDedupOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var gotClosed, gotCross db.Finding
	gdb.First(&gotClosed, closed.ID)
	gdb.First(&gotCross, crossRepo.ID)
	if gotClosed.Status != db.FindingFixed {
		t.Fatalf("closed finding status changed: %s", gotClosed.Status)
	}
	if gotCross.Status != db.FindingNew {
		t.Fatalf("cross-repo finding status changed: %s", gotCross.Status)
	}
}

// depEnvelope wraps a JSON fragment of inventory rows and an optional
// CycloneDX document in the versioned envelope the dependencies parser
// expects.
func depEnvelope(inventory, sbom string) string {
	if sbom == "" {
		sbom = "{}"
	}
	return `{"schema_version":1,"commit":"cafef00d","analyses":{` +
		`"inventory":{"status":"ok","result":` + inventory + `},` +
		`"sbom":{"status":"ok","result":` + sbom + `}}}`
}

func TestParseDependencies_acceptsTypeOrDependencyType(t *testing.T) {
	report := depEnvelope(`[
		{"name":"a","ecosystem":"npm","type":"runtime","manifest_path":"package.json"},
		{"name":"b","ecosystem":"npm","dependency_type":"development","manifest_path":"package.json"},
		{"name":"c","ecosystem":"cpan","dependency_type":"test_requires","manifest_path":"META.json"},
		{"name":"d","ecosystem":"cpan","dependency_type":"configure_requires","manifest_path":"META.json"},
		{"name":"m","ecosystem":"maven","requirement":"${missing.version}","requirement_unresolved":true,"manifest_path":"pom.xml"}
	]`, "")
	repo, gdb := runSkillWithReport(t, "dependencies", report)
	var rows []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	if len(rows) != 5 {
		t.Fatalf("rows = %d, want 5", len(rows))
	}
	gotTypes := map[string]string{}
	for _, row := range rows {
		gotTypes[row.Name] = row.DependencyType
	}
	if gotTypes["a"] != db.DependencyRuntime || gotTypes["b"] != db.DependencyDev ||
		gotTypes["c"] != db.DependencyTest || gotTypes["d"] != db.DependencyBuild {
		t.Errorf("types: %+v", gotTypes)
	}
	var maven db.Dependency
	if err := gdb.Where("repository_id = ? AND name = ?", repo.ID, "m").First(&maven).Error; err != nil {
		t.Fatalf("missing maven dep: %v", err)
	}
	if !maven.RequirementUnresolved {
		t.Errorf("RequirementUnresolved = false, want true")
	}
}

func TestParseDependencies_resolvesMavenRequirementsWithPOM(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)
	src := filepath.Join(w.scanWorkRoot(scan), "src")
	writeMavenResolverFixture(t, src)

	report := depEnvelope(`[
		{"name":"org.openjdk.jmh:jmh-core","ecosystem":"maven","requirement":"${jmh.version}","manifest_path":"pom.xml"},
		{"name":"org.example:child-dep","ecosystem":"maven","requirement":"${project.version}","manifest_path":"module/pom.xml"},
		{"name":"org.example:missing","ecosystem":"maven","requirement":"${missing.version}","manifest_path":"pom.xml"}
	]`, "")
	if err := w.parseDependenciesOutput(scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	got := map[string]db.Dependency{}
	var rows []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	for _, row := range rows {
		got[row.Name] = row
	}
	if got["org.openjdk.jmh:jmh-core"].Requirement != "1.37" || got["org.openjdk.jmh:jmh-core"].RequirementUnresolved {
		t.Fatalf("direct property not resolved: %+v", got["org.openjdk.jmh:jmh-core"])
	}
	if got["org.openjdk.jmh:jmh-core"].RequirementResolution != "resolved" {
		t.Fatalf("direct property resolution = %q", got["org.openjdk.jmh:jmh-core"].RequirementResolution)
	}
	if got["org.example:child-dep"].Requirement != "2.0.0" || got["org.example:child-dep"].RequirementUnresolved {
		t.Fatalf("parent project.version not resolved: %+v", got["org.example:child-dep"])
	}
	if got["org.example:missing"].Requirement != "${missing.version}" || !got["org.example:missing"].RequirementUnresolved {
		t.Fatalf("missing property should be flagged unresolved: %+v", got["org.example:missing"])
	}
	if got["org.example:missing"].RequirementResolution != "unresolved_property" {
		t.Fatalf("missing property resolution = %q", got["org.example:missing"].RequirementResolution)
	}
}

func TestParseDependencies_skipsMavenParentOutsideSrc(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)
	writeEscapingMavenResolverFixture(t, w.scanWorkRoot(scan))

	report := depEnvelope(`[
		{"name":"org.example:escape","ecosystem":"maven","requirement":"${secret.version}","manifest_path":"escape/pom.xml"}
	]`, "")
	if err := w.parseDependenciesOutput(scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var dep db.Dependency
	if err := gdb.Where("repository_id = ? AND name = ?", repo.ID, "org.example:escape").First(&dep).Error; err != nil {
		t.Fatal(err)
	}
	if dep.Requirement != "${secret.version}" {
		t.Fatalf("requirement = %q, want unresolved placeholder", dep.Requirement)
	}
	if !dep.RequirementUnresolved {
		t.Fatalf("RequirementUnresolved = false, want true")
	}
	if dep.RequirementResolution != "unresolved_parent" {
		t.Fatalf("RequirementResolution = %q, want unresolved_parent", dep.RequirementResolution)
	}
}

func TestParseDependencies_largeBatchExceedsSQLiteVariableLimit(t *testing.T) {
	const n = 200
	deps := make([]map[string]string, n)
	for i := range n {
		deps[i] = map[string]string{
			"name":          "dep-" + strconv.Itoa(i),
			"ecosystem":     "npm",
			"type":          "runtime",
			"manifest_path": "package.json",
		}
	}
	b, _ := json.Marshal(deps)
	repo, gdb := runSkillWithReport(t, "dependencies", depEnvelope(string(b), ""))
	var count int64
	gdb.Model(&db.Dependency{}).Where("repository_id = ?", repo.ID).Count(&count)
	if count != n {
		t.Fatalf("count = %d, want %d", count, n)
	}
}

const cdxEnvelopeFixture = `{
  "bomFormat":"CycloneDX","specVersion":"1.5",
  "metadata":{"component":{"type":"application","name":"demo","version":"1.0.0"}},
  "components":[
    {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21",
     "licenses":[{"license":{"id":"MIT"}}]}
  ]
}`

func TestParseDependencies_createsGeneratedSBOM(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)

	report := depEnvelope(
		`[{"name":"lodash","ecosystem":"npm","requirement":"^4.17.0","manifest_path":"package.json"}]`,
		cdxEnvelopeFixture)
	if err := w.parseDependenciesOutput(scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var deps []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&deps)
	if len(deps) != 1 || deps[0].Name != "lodash" {
		t.Fatalf("dependencies = %+v", deps)
	}

	var up db.SBOMUpload
	if err := gdb.Preload("Packages").
		Where("repository_id = ? AND origin = ?", repo.ID, db.SBOMOriginGenerated).
		First(&up).Error; err != nil {
		t.Fatalf("generated snapshot not created: %v", err)
	}
	if up.Commit != "cafef00d" {
		t.Errorf("Commit = %q, want cafef00d from envelope", up.Commit)
	}
	if !up.Current {
		t.Error("first generated snapshot should be Current")
	}
	if up.ScanID == nil || *up.ScanID != scan.ID {
		t.Errorf("ScanID = %v, want %d", up.ScanID, scan.ID)
	}
	if up.Raw != nil {
		t.Errorf("generated snapshot stored Raw (%d bytes)", len(up.Raw))
	}
	if up.PackageCount != 1 || len(up.Packages) != 1 {
		t.Fatalf("packages = %d (%d rows)", up.PackageCount, len(up.Packages))
	}
	pkg := up.Packages[0]
	if pkg.PURL != "pkg:npm/lodash@4.17.21" || pkg.Ecosystem != "npm" || pkg.License != "MIT" {
		t.Errorf("package = %+v", pkg)
	}

	// A second scan writes a new snapshot and moves Current in the same
	// transaction so at most one row per repository has Current=true.
	scan2 := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan2)
	if err := w.parseDependenciesOutput(&scan2, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var uploads []db.SBOMUpload
	gdb.Where("repository_id = ? AND origin = ?", repo.ID, db.SBOMOriginGenerated).
		Order("id").Find(&uploads)
	if len(uploads) != 2 {
		t.Fatalf("uploads = %d, want 2 (history retained)", len(uploads))
	}
	if uploads[0].Current {
		t.Error("prior snapshot still Current after second scan")
	}
	if !uploads[1].Current {
		t.Error("newest snapshot should be Current")
	}
	var currentCount int64
	gdb.Model(&db.SBOMUpload{}).Where("repository_id = ? AND current = ?", repo.ID, true).Count(&currentCount)
	if currentCount != 1 {
		t.Errorf("current snapshots for repo = %d, want 1", currentCount)
	}

	// A generated snapshot for one repository must not touch another
	// repository's Current flag.
	other := db.Repository{URL: "https://example.com/y", Name: "y"}
	gdb.Create(&other)
	gdb.Create(&db.SBOMUpload{Origin: db.SBOMOriginGenerated, RepositoryID: &other.ID, Current: true})
	if err := w.parseDependenciesOutput(&scan2, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var otherCurrent int64
	gdb.Model(&db.SBOMUpload{}).Where("repository_id = ? AND current = ?", other.ID, true).Count(&otherCurrent)
	if otherCurrent != 1 {
		t.Errorf("unrelated repo current = %d, want 1", otherCurrent)
	}
}

func TestParseDependencies_sbomSectionErrorKeepsInventory(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)

	report := `{"schema_version":1,"analyses":{
		"inventory":{"status":"ok","result":[{"name":"x","ecosystem":"npm"}]},
		"sbom":{"status":"error","error":"boom"}
	}}`
	var events []Event
	if err := w.parseDependenciesOutput(scan, report, func(e Event) { events = append(events, e) }); err != nil {
		t.Fatalf("errored sbom section should not fail parse: %v", err)
	}

	var deps int64
	gdb.Model(&db.Dependency{}).Where("repository_id = ?", repo.ID).Count(&deps)
	if deps != 1 {
		t.Errorf("inventory rows = %d, want 1", deps)
	}
	var uploads int64
	gdb.Model(&db.SBOMUpload{}).Where("repository_id = ?", repo.ID).Count(&uploads)
	if uploads != 0 {
		t.Errorf("errored sbom section should not create a snapshot, got %d", uploads)
	}
	joined := ""
	for _, e := range events {
		joined += e.Text + "\n"
	}
	if !strings.Contains(joined, "sbom section skipped: boom") {
		t.Errorf("events missing sbom skip message:\n%s", joined)
	}
}

func TestParseDependencies_inventoryErrorKeepsPriorRows(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)

	// Seed a prior successful run so there is something to lose.
	if err := w.parseDependenciesOutput(scan,
		depEnvelope(`[{"name":"prior","ecosystem":"npm"}]`, cdxEnvelopeFixture),
		func(Event) {}); err != nil {
		t.Fatal(err)
	}

	// A run where git-pkgs list failed but sbom succeeded: prior Dependency
	// rows must survive, and the sbom section is still applied independently.
	report := `{"schema_version":1,"commit":"deadbeef","analyses":{
		"inventory":{"status":"error","error":"git-pkgs list: exit 1"},
		"sbom":{"status":"ok","result":` + cdxEnvelopeFixture + `}
	}}`
	var events []Event
	if err := w.parseDependenciesOutput(scan, report, func(e Event) { events = append(events, e) }); err != nil {
		t.Fatalf("errored inventory section should not fail parse: %v", err)
	}

	var deps []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&deps)
	if len(deps) != 1 || deps[0].Name != "prior" {
		t.Errorf("prior dependency rows should survive an errored inventory, got %+v", deps)
	}
	var current db.SBOMUpload
	if err := gdb.Where("repository_id = ? AND current = ?", repo.ID, true).First(&current).Error; err != nil {
		t.Fatalf("current snapshot: %v", err)
	}
	if current.Commit != "deadbeef" {
		t.Errorf("sbom section not applied independently: current commit = %q", current.Commit)
	}
	joined := ""
	for _, e := range events {
		joined += e.Text + "\n"
	}
	if !strings.Contains(joined, "inventory failed, prior dependency rows kept") {
		t.Errorf("events missing inventory-kept message:\n%s", joined)
	}
}

func TestParseDependencies_scriptFallbackKeepsPriorRows(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)

	if err := w.parseDependenciesOutput(scan,
		depEnvelope(`[{"name":"prior","ecosystem":"npm"}]`, ""),
		func(Event) {}); err != nil {
		t.Fatal(err)
	}

	// The SKILL.md fallback for a wholesale script failure has an empty
	// analyses object. Status is "" for both sections; that must be treated
	// as failure, not as an ok run that found nothing.
	report := `{"schema_version":1,"analyses":{},"error":"git-pkgs init: exit 1"}`
	var events []Event
	if err := w.parseDependenciesOutput(scan, report, func(e Event) { events = append(events, e) }); err != nil {
		t.Fatalf("script fallback should not fail parse: %v", err)
	}

	var deps []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&deps)
	if len(deps) != 1 || deps[0].Name != "prior" {
		t.Errorf("script fallback wiped prior dependency rows: %+v", deps)
	}
	var uploads int64
	gdb.Model(&db.SBOMUpload{}).Where("repository_id = ?", repo.ID).Count(&uploads)
	if uploads != 0 {
		t.Errorf("script fallback should not create a snapshot, got %d", uploads)
	}
	joined := ""
	for _, e := range events {
		joined += e.Text + "\n"
	}
	if !strings.Contains(joined, "no inventory section in report") {
		t.Errorf("events missing missing-section reason:\n%s", joined)
	}
}

func TestParseDependencies_subPathScanLeavesRepoLevelRows(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)

	// Seed the whole-repo state.
	if err := w.parseDependenciesOutput(scan,
		depEnvelope(`[{"name":"full-repo","ecosystem":"npm"}]`, cdxEnvelopeFixture),
		func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var seeded db.SBOMUpload
	gdb.Where("repository_id = ? AND current = ?", repo.ID, true).First(&seeded)

	// A sub-path-scoped scan sees only one sub-package's manifests; it must
	// not replace the full-repo Dependency set nor demote its Current
	// snapshot with a partial one.
	scoped := db.Scan{RepositoryID: repo.ID, SubPath: "packages/foo"}
	gdb.Create(&scoped)
	var events []Event
	if err := w.parseDependenciesOutput(&scoped,
		depEnvelope(`[{"name":"partial","ecosystem":"npm"}]`, cdxEnvelopeFixture),
		func(e Event) { events = append(events, e) }); err != nil {
		t.Fatal(err)
	}

	var deps []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&deps)
	if len(deps) != 1 || deps[0].Name != "full-repo" {
		t.Errorf("sub-path scan replaced repo-level dependency rows: %+v", deps)
	}
	var uploads []db.SBOMUpload
	gdb.Where("repository_id = ?", repo.ID).Find(&uploads)
	if len(uploads) != 1 || uploads[0].ID != seeded.ID || !uploads[0].Current {
		t.Errorf("sub-path scan touched repo-level snapshot: %+v", uploads)
	}
	joined := ""
	for _, e := range events {
		joined += e.Text + "\n"
	}
	if !strings.Contains(joined, "sub-path scan") {
		t.Errorf("events missing sub-path skip message:\n%s", joined)
	}
}

func TestParseDependencies_malformedSBOMKeepsInventory(t *testing.T) {
	w, scan, gdb, repo := newDependencyParser(t)

	report := depEnvelope(`[{"name":"x","ecosystem":"npm"}]`, `{"bomFormat":"garbage"}`)
	if err := w.parseDependenciesOutput(scan, report, func(Event) {}); err != nil {
		t.Fatalf("malformed sbom document should not fail parse: %v", err)
	}
	var deps int64
	gdb.Model(&db.Dependency{}).Where("repository_id = ?", repo.ID).Count(&deps)
	if deps != 1 {
		t.Errorf("inventory rows = %d, want 1", deps)
	}
	var uploads int64
	gdb.Model(&db.SBOMUpload{}).Count(&uploads)
	if uploads != 0 {
		t.Errorf("malformed sbom should not create a snapshot, got %d", uploads)
	}
}

func newDependencyParser(t *testing.T) (*Worker, *db.Scan, *gorm.DB, db.Repository) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)
	w := &Worker{
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
	}
	if err := os.MkdirAll(filepath.Join(w.scanWorkRoot(&scan), "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	return w, &scan, gdb, repo
}

func writeMavenResolverFixture(t *testing.T, src string) {
	t.Helper()
	writeFile(t, filepath.Join(src, "pom.xml"), `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>parent</artifactId>
  <version>2.0.0</version>
  <properties>
    <jmh.version>1.37</jmh.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.openjdk.jmh</groupId>
      <artifactId>jmh-core</artifactId>
      <version>${jmh.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>missing</artifactId>
      <version>${missing.version}</version>
    </dependency>
  </dependencies>
</project>
`)
	if err := os.Mkdir(filepath.Join(src, "module"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "module", "pom.xml"), `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>2.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>child-dep</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>
`)
}

func writeEscapingMavenResolverFixture(t *testing.T, workRoot string) {
	t.Helper()
	writeFile(t, filepath.Join(workRoot, "host-parent.xml"), `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>host-parent</artifactId>
  <version>9.9.9</version>
  <properties>
    <secret.version>leaked-from-outside-src</secret.version>
  </properties>
</project>
`)
	escapeDir := filepath.Join(workRoot, "src", "escape")
	if err := os.Mkdir(escapeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(escapeDir, "pom.xml"), `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.example</groupId>
    <artifactId>host-parent</artifactId>
    <version>9.9.9</version>
    <relativePath>../../host-parent.xml</relativePath>
  </parent>
  <artifactId>escape</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>escape</artifactId>
      <version>${secret.version}</version>
    </dependency>
  </dependencies>
</project>
`)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A failed maintainer lookup must skip the record, not fall through into the
// Save below. FirstOrCreate leaves the destination zero on a query error, so
// saving it inserts a second maintainer row with an empty login and hands the
// repository's association to that row instead of the real one.
func TestParseMaintainers_lookupFailureSkipsRecord(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	seed := `{"maintainers":[{"login":"alice","name":"Real Alice","role":"lead","status":"active"}]}`
	if err := w.parseMaintainersOutput(&scan, seed, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	// Fail only the first lookup, the way a timeout or a dropped connection
	// would: the writes that follow still succeed.
	fired := false
	const name = "test:fail_maintainer_lookup"
	if err := gdb.Callback().Query().Before("gorm:query").Register(name, func(d *gorm.DB) {
		if d.Statement.Table == "maintainers" && !fired {
			fired = true
			_ = d.AddError(errors.New("injected lookup failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	report := `{"maintainers":[{"login":"alice","name":"Alice","role":"lead","status":"active","evidence":"commits"}]}`
	if err := w.parseMaintainersOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatalf("a per-maintainer failure must not fail the whole report: %v", err)
	}
	if err := gdb.Callback().Query().Remove(name); err != nil {
		t.Fatal(err)
	}

	var blank int64
	gdb.Model(&db.Maintainer{}).Where("login = ?", "").Count(&blank)
	if blank != 0 {
		t.Errorf("failed lookup inserted %d blank-login maintainer row(s), want 0", blank)
	}
	var linked []db.Maintainer
	if err := gdb.Model(&repo).Association("Maintainers").Find(&linked); err != nil {
		t.Fatal(err)
	}
	if len(linked) != 1 || linked[0].Login != "alice" {
		t.Errorf("repository maintainers = %+v, want the real alice still linked", linked)
	}
}

// The opposite case, and the reason the failed Save is NOT skipped: the row
// exists and is correctly identified, only its field refresh was lost. Dropping
// it from linked would unlink a real maintainer through the wholesale
// Association.Replace, which loses more than a stale name does.
func TestParseMaintainers_saveFailureKeepsMaintainerLinked(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID}
	gdb.Create(&scan)
	gdb.Create(&db.Maintainer{Login: "alice", Name: "Real Alice"})

	const name = "test:fail_maintainer_save"
	if err := gdb.Callback().Update().Before("gorm:update").Register(name, func(d *gorm.DB) {
		if d.Statement.Table == "maintainers" {
			_ = d.AddError(errors.New("injected save failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	report := `{"maintainers":[{"login":"alice","name":"Updated Alice","role":"lead","status":"active"}]}`
	if err := w.parseMaintainersOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatalf("a failed save must not fail the whole report: %v", err)
	}
	if err := gdb.Callback().Update().Remove(name); err != nil {
		t.Fatal(err)
	}

	var linked []db.Maintainer
	if err := gdb.Model(&repo).Association("Maintainers").Find(&linked); err != nil {
		t.Fatal(err)
	}
	if len(linked) != 1 || linked[0].Login != "alice" {
		t.Errorf("repository maintainers = %+v, want alice linked despite the failed save", linked)
	}
}
