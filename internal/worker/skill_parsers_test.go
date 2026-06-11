package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
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
		{"name":"d","ecosystem":"cpan","dependency_type":"configure_requires","manifest_path":"META.json"}
	]}`
	repo, gdb := runSkillWithReport(t, "dependencies", report)
	var rows []db.Dependency
	gdb.Where("repository_id = ?", repo.ID).Find(&rows)
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	gotTypes := map[string]string{}
	for _, row := range rows {
		gotTypes[row.Name] = row.DependencyType
	}
	if gotTypes["a"] != db.DependencyRuntime || gotTypes["b"] != db.DependencyDev ||
		gotTypes["c"] != db.DependencyTest || gotTypes["d"] != db.DependencyBuild {
		t.Errorf("types: %+v", gotTypes)
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
