package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

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
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		Runner:  fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}},
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
		Runner: fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report2}}}
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

func TestParseDependents_replacesDependentRows(t *testing.T) {
	report := `{"dependents":[
		{"name":"rails-x","ecosystem":"rubygems","purl":"pkg:gem/rails-x","downloads":5000,"dependent_repos":200,"latest_version":"7.0.0"}
	]}`
	repo, gdb := runSkillWithReport(t, "dependents", report)
	var rows []db.Dependent
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	if len(rows) != 1 || rows[0].Name != "rails-x" || rows[0].DependentRepos != 200 {
		t.Fatalf("rows: %+v", rows)
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
	fid := finding.ID
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		Status:       db.ScanQueued,
		Model:        "fake",
		SkillID:      &skill.ID,
		FindingID:    &fid,
	}
	gdb.Create(&scan)

	w := &Worker{
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		Runner:  fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}},
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
	report := `{"status":"confirmed","evidence":"ran repro.rb, got the same error","notes":"no code change"}`
	f, gdb := runSkillWithFinding(t, "verify", report, db.FindingNew)
	if f.Status != db.FindingEnriched {
		t.Errorf("status = %s, want enriched", f.Status)
	}
	notes := findingNotes(gdb, f.ID)
	if len(notes) == 0 || !strings.Contains(notes[0].Body, "confirmed") {
		t.Errorf("notes missing verify record: %+v", notes)
	}
}

func TestParseVerify_fixedJumpsToFixed(t *testing.T) {
	report := `{"status":"fixed","evidence":"repro no longer reproduces","notes":"commit abc added guard"}`
	f, _ := runSkillWithFinding(t, "verify", report, db.FindingTriaged)
	if f.Status != db.FindingFixed {
		t.Errorf("status = %s, want fixed", f.Status)
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

func TestParseDependencies_acceptsTypeOrDependencyType(t *testing.T) {
	report := `{"dependencies":[
		{"name":"a","ecosystem":"npm","type":"runtime","manifest_path":"package.json"},
		{"name":"b","ecosystem":"npm","dependency_type":"development","manifest_path":"package.json"}
	]}`
	repo, gdb := runSkillWithReport(t, "dependencies", report)
	var rows []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	gotTypes := map[string]string{rows[0].Name: rows[0].DependencyType, rows[1].Name: rows[1].DependencyType}
	if gotTypes["a"] != "runtime" || gotTypes["b"] != "development" {
		t.Errorf("types: %+v", gotTypes)
	}
}
