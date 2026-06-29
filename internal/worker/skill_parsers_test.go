package worker

import (
	"context"
	"encoding/json"
	"errors"
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

func TestParseVerify_confirmedMovesNewToEnriched(t *testing.T) {
	report := `{"status":"confirmed","reproducer":"ruby -e 'load %q(./src/x.rb); X.call(%q(../etc))'","evidence":"got the same error","notes":"no code change"}`
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
	report := `{"status":"fixed","evidence":"repro no longer reproduces","notes":"commit abc added guard"}`
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
	report := `{"status":"fixed","evidence":"no longer reproduces on the PR branch"}`
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
	report := `{"status":"inconclusive","notes":"tooling missing"}`
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	if f.Status != db.FindingNew {
		t.Errorf("status = %s, want new (unchanged)", f.Status)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "inconclusive") {
		t.Errorf("notes missing status header: %+v", notes)
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
	gdb.Where("finding_id = ? AND `by` = ?", f.ID, "release-watch").Find(&notes)
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
		"patched": ["cvss_vector", "affected", "disclosure_draft"],
		"preserved": ["title"],
		"references_added": 2,
		"references_skipped": 1,
		"notes": "Source-only advisory; no published packages."
	}`
	f, gdb := runSkillWithFinding(t, "disclose", report, db.FindingTriaged)

	var notes []db.FindingNote
	gdb.Where("finding_id = ? AND `by` = ?", f.ID, "disclose").Find(&notes)
	if len(notes) != 1 {
		t.Fatalf("want one disclose note, got %d: %+v", len(notes), notes)
	}
	body := notes[0].Body
	for _, want := range []string{
		`disclose: drafted "Command injection in run()"`,
		"Patched: cvss_vector, affected, disclosure_draft",
		"Preserved: title",
		"References: 2 added, 1 skipped",
		"Source-only advisory; no published packages.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("note body missing %q:\n%s", want, body)
		}
	}
}

func TestParseDisclose_errorReportRecordsRefusal(t *testing.T) {
	report := `{"error": "finding has no Trace prose; cannot draft a description"}`
	f, gdb := runSkillWithFinding(t, "disclose", report, db.FindingNew)

	var notes []db.FindingNote
	gdb.Where("finding_id = ? AND `by` = ?", f.ID, "disclose").Find(&notes)
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

func TestParseDependencies_acceptsTypeOrDependencyType(t *testing.T) {
	report := `{"dependencies":[
		{"name":"a","ecosystem":"npm","type":"runtime","manifest_path":"package.json"},
		{"name":"b","ecosystem":"npm","dependency_type":"development","manifest_path":"package.json"},
		{"name":"c","ecosystem":"cpan","dependency_type":"test_requires","manifest_path":"META.json"},
		{"name":"d","ecosystem":"cpan","dependency_type":"configure_requires","manifest_path":"META.json"},
		{"name":"m","ecosystem":"maven","requirement":"${missing.version}","requirement_unresolved":true,"manifest_path":"pom.xml"}
	]}`
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

	report := `{"dependencies":[
		{"name":"org.openjdk.jmh:jmh-core","ecosystem":"maven","requirement":"${jmh.version}","manifest_path":"pom.xml"},
		{"name":"org.example:child-dep","ecosystem":"maven","requirement":"${project.version}","manifest_path":"module/pom.xml"},
		{"name":"org.example:missing","ecosystem":"maven","requirement":"${missing.version}","manifest_path":"pom.xml"}
	]}`
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

	report := `{"dependencies":[
		{"name":"org.example:escape","ecosystem":"maven","requirement":"${secret.version}","manifest_path":"escape/pom.xml"}
	]}`
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
	b, _ := json.Marshal(map[string]any{"dependencies": deps})
	repo, gdb := runSkillWithReport(t, "dependencies", string(b))
	var count int64
	gdb.Model(&db.Dependency{}).Where("repository_id = ?", repo.ID).Count(&count)
	if count != n {
		t.Fatalf("count = %d, want %d", count, n)
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
