package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/repoconfig"
)

func TestStageThreatModel(t *testing.T) {
	dir := t.TempDir()
	if err := stageThreatModel(dir, "", ""); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "threat_model.json")); err == nil {
		t.Error("empty model should not write threat_model.json")
	}

	model := `{"spec_version":1}`
	if err := stageThreatModel(dir, "packages/core", model); err != nil {
		t.Fatalf("subpath: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "threat_model.json")); err == nil {
		t.Error("subpath-scoped scan should not receive the root override")
	}

	if err := stageThreatModel(dir, "", model); err != nil {
		t.Fatalf("non-empty: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "threat_model.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != model {
		t.Errorf("contents = %q, want %q", got, model)
	}
}

const maintainersReport = `{"maintainers":[
  {"login":"alice","name":"Alice","email":"alice@example.com","role":"lead","status":"active","evidence":"80% of past-year commits"},
  {"login":"bob","role":"contributor","status":"inactive","evidence":"last commit 2022"}
],"disclosure_channel":"SECURITY.md","notes":""}`

func TestDoSkill_findingsKind(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name:        "spec-deep",
		Description: "Deep audit",
		Body:        "## Instructions\n\nDo the thing.",
		OutputFile:  "report.json",
		OutputKind:  "findings",
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

	report := `{"repository":"https://example.com/x","commit":"abc","spec_version":10,
	  "model":"t","date":"2026-01-01","languages":["Go"],"boundaries":[{"actor":"u","trusted":"no","controls":"c","source":"derived"}],
	  "inventory":[],"ruled_out":[],
	  "findings":[{"id":"F1","sinks":["S1"],"title":"t","severity":"High","cwe":"CWE-1","location":"x:1",
	    "trace":"t","boundary":"b","validation":"v","rating":"High"}]}`

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

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Errorf("status = %s: %s", got.Status, got.Error)
	}
	if got.SkillName != "spec-deep" || got.SkillVersion != 1 {
		t.Errorf("skill denorm fields: %q v=%d", got.SkillName, got.SkillVersion)
	}
	if got.FindingsCount != 1 {
		t.Errorf("findings count: %d", got.FindingsCount)
	}
	if !strings.Contains(got.Prompt, "spec-deep") || !strings.Contains(got.Prompt, "report.json") {
		t.Errorf("prompt missing skill name or output file: %q", got.Prompt)
	}
	if !strings.Contains(got.Prompt, "--- SKILL.md ---") || !strings.Contains(got.Prompt, "Do the thing.") {
		t.Errorf("prompt missing rendered SKILL.md body: %q", got.Prompt)
	}
}

func TestDoSkill_maintainersKind(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name:        "maintainers",
		Description: "Identify maintainers",
		Body:        "Fetch ecosyste.ms and classify.",
		OutputFile:  "report.json",
		OutputKind:  "maintainers",
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
		Runner:         fakeRunner{skillRes: SkillResult{Commit: "abc", Report: maintainersReport}},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	var alice db.Maintainer
	if err := gdb.Where("login = ?", "alice").First(&alice).Error; err != nil {
		t.Fatalf("alice not upserted: %v", err)
	}
	if alice.Status != db.MaintainerActive || alice.Email != "alice@example.com" {
		t.Errorf("alice row: %+v", alice)
	}
	var bob db.Maintainer
	if err := gdb.Where("login = ?", "bob").First(&bob).Error; err != nil {
		t.Fatalf("bob not upserted: %v", err)
	}
	if bob.Status != db.MaintainerInactive {
		t.Errorf("bob status: %s", bob.Status)
	}

	var fresh db.Repository
	gdb.Preload("Maintainers").First(&fresh, repo.ID)
	if len(fresh.Maintainers) != 2 {
		t.Errorf("repo linked to %d maintainers, want 2", len(fresh.Maintainers))
	}
}

func TestDoSkill_cloneErrorFlagsRepo(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "ce.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/gone", Name: "gone"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name: "metadata", Description: "d", Body: "b",
		OutputFile: "report.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui",
	}
	gdb.Create(&skill)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: JobSkill,
		Status: db.ScanQueued, Model: "fake", SkillID: &skill.ID,
	}
	gdb.Create(&scan)

	cloneErr := &RepoUnreachableError{
		URL: repo.URL,
		Err: fmt.Errorf("fatal: repository 'https://example.com/gone' not found"),
	}
	w := &Worker{
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		Runner:  fakeRunner{},
		PrepareRepoSrc: func(context.Context, string, string, string, func(Event)) (string, error) {
			return "", cloneErr
		},
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Errorf("status = %s, want done (err=%q)", got.Status, got.Error)
	}
	if !strings.Contains(got.Report, "repository unreachable") {
		t.Errorf("report should mention unreachable: %q", got.Report)
	}

	var fresh db.Repository
	gdb.First(&fresh, repo.ID)
	if fresh.CloneError == "" {
		t.Error("repo CloneError should be set after clone failure")
	}
}

func TestDoSkill_successClearsCloneError(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "cc.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{
		URL: "https://example.com/back", Name: "back",
		CloneError: "previously unreachable",
	}
	gdb.Create(&repo)
	skill := db.Skill{
		Name: "metadata", Description: "d", Body: "b",
		OutputFile: "report.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui",
	}
	gdb.Create(&skill)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: JobSkill,
		Status: db.ScanQueued, Model: "fake", SkillID: &skill.ID,
	}
	gdb.Create(&scan)

	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillRes: SkillResult{Commit: "abc", Report: "{}"}},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	var fresh db.Repository
	gdb.First(&fresh, repo.ID)
	if fresh.CloneError != "" {
		t.Errorf("CloneError should be cleared after success, got %q", fresh.CloneError)
	}
}

func TestStageContext_writesRepoFacts(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{
		URL:           "https://example.com/x",
		HTMLURL:       "https://example.com/x",
		Name:          "x",
		FullName:      "example/x",
		DefaultBranch: "main",
	}
	scan := &db.Scan{ID: 7, RepositoryID: 3, APIToken: "tok"}
	if err := stageContext(dir, "http://127.0.0.1:8080/api", "", "", scan, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Repository.URL != repo.URL || got.Repository.DefaultBranch != "main" {
		t.Errorf("context: %+v", got)
	}
	if got.Scrutineer.Token != "tok" || got.Scrutineer.APIBase == "" {
		t.Errorf("scrutineer block: %+v", got.Scrutineer)
	}
}

func TestStageContext_includesRepositoryScanConfig(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{
		URL:  "https://example.com/config",
		Name: "config",
		ScanConfig: `focus_areas:
  - name: parser
    paths: [src/parse/**]
    surface: accepts arbitrary bytes
known_bugs: [GHSA-xxxx-yyyy]
attack_surface: stdin is attacker controlled
skip: [tests/**]`,
	}
	scan := &db.Scan{ID: 7, RepositoryID: 3, APIToken: "tok"}
	if err := stageContext(dir, "http://127.0.0.1:8080/api", "", "", scan, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scrutineer.ScanConfig == nil || got.Scrutineer.ScanConfig.FocusAreas[0].Name != "parser" {
		t.Fatalf("scan_config = %+v", got.Scrutineer.ScanConfig)
	}
	if got.Scrutineer.ScanConfig.Skip[0] != "tests/**" || got.Scrutineer.ScanConfig.KnownBugs[0] != "GHSA-xxxx-yyyy" {
		t.Fatalf("scan_config = %+v", got.Scrutineer.ScanConfig)
	}
}

func TestStageContext_includesReconFocusAreas(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{URL: "https://example.com/recon", Name: "recon"}
	scan := &db.Scan{ID: 7, RepositoryID: 3, APIToken: "tok"}
	recon := &skillContextRecon{
		FocusAreas: []repoconfig.FocusArea{{
			Name: "XML parser", Paths: []string{"lib/xml*.c"}, Surface: "XML documents from callers",
		}},
		Notes: []string{"Examples excluded."},
	}
	if err := stageContextWithRecon(dir, "http://127.0.0.1:8080/api", "", "", scan, repo, recon); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scrutineer.Recon == nil || got.Scrutineer.Recon.FocusAreas[0].Name != "XML parser" {
		t.Fatalf("recon = %+v", got.Scrutineer.Recon)
	}
}

func TestStageContext_includesFocusArea(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{URL: "https://example.com/focus", Name: "focus"}
	raw, err := repoconfig.EncodeFocusAreaJSON(repoconfig.FocusArea{
		Name: "XML parser", Paths: []string{"lib/xml*.c"}, Surface: "untrusted XML",
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := &db.Scan{ID: 7, RepositoryID: 3, APIToken: "tok", FocusArea: raw}
	if err := stageContext(dir, "http://127.0.0.1:8080/api", "", "", scan, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scrutineer.FocusArea == nil || got.Scrutineer.FocusArea.Name != "XML parser" {
		t.Fatalf("focus_area = %+v", got.Scrutineer.FocusArea)
	}
}

type reconContextFixture struct {
	worker      *Worker
	repository  db.Repository
	reconSkill  db.Skill
	threatModel db.Skill
}

func newReconContextFixture(t *testing.T) reconContextFixture {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "recon.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/recon", Name: "recon"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../../skills/recon/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	reconSkill := db.Skill{Name: "recon", SchemaJSON: string(schema)}
	if err := gdb.Create(&reconSkill).Error; err != nil {
		t.Fatal(err)
	}
	return reconContextFixture{
		worker:      &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))},
		repository:  repo,
		reconSkill:  reconSkill,
		threatModel: db.Skill{Name: threatModelSkillName},
	}
}

func (f reconContextFixture) seedReconScan(t *testing.T, scan db.Scan) db.Scan {
	t.Helper()
	scan.RepositoryID = f.repository.ID
	scan.SkillID = &f.reconSkill.ID
	scan.SkillName = reconSkillName
	scan.Status = db.ScanDone
	if err := f.worker.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return scan
}

func (f reconContextFixture) context(t *testing.T, scan db.Scan) *skillContextRecon {
	t.Helper()
	scan.RepositoryID = f.repository.ID
	ctx, err := f.worker.reconContext(&scan, &f.threatModel)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func requireReconArea(t *testing.T, ctx *skillContextRecon, name string) {
	t.Helper()
	if ctx == nil || len(ctx.FocusAreas) != 1 || ctx.FocusAreas[0].Name != name {
		t.Fatalf("recon context = %+v, want %q", ctx, name)
	}
}

func TestReconContextPrefersGroupAndFallsBack(t *testing.T) {
	f := newReconContextFixture(t)
	f.seedReconScan(t, db.Scan{ScanGroup: "batch-a", Report: `{"focus_areas":[{"name":"XML parser","paths":["  lib\\xml*.c  "],"surface":"XML documents from callers"}],"notes":["Examples excluded."]}`})
	f.seedReconScan(t, db.Scan{Report: `{"focus_areas":[{"name":"CLI parser","paths":["cmd/**/*.go"],"surface":"Command-line input from operators"}],"notes":[]}`})
	// This newer report is the repo-wide fallback but must not replace a
	// same-group result.
	f.seedReconScan(t, db.Scan{ScanGroup: "other", Report: `{"focus_areas":[{"name":"fallback parser","paths":["fallback/**"],"surface":"latest compatible recon report"}],"notes":[]}`})

	grouped := f.context(t, db.Scan{ScanGroup: "batch-a"})
	requireReconArea(t, grouped, "XML parser")
	if got, want := grouped.FocusAreas[0].Paths, []string{"lib/xml*.c"}; !slices.Equal(got, want) {
		t.Errorf("paths = %q, want %q", got, want)
	}
	requireReconArea(t, f.context(t, db.Scan{}), "fallback parser")
	requireReconArea(t, f.context(t, db.Scan{ScanGroup: "batch-b"}), "fallback parser")
}

func TestReconContextFallbackMatchesRefAndSubPath(t *testing.T) {
	f := newReconContextFixture(t)
	f.seedReconScan(t, db.Scan{Ref: "topic", Report: `{"focus_areas":[{"name":"topic parser","paths":["topic/**"],"surface":"topic branch input"}],"notes":[]}`})
	f.seedReconScan(t, db.Scan{SubPath: "cmd", Report: `{"focus_areas":[{"name":"CLI parser","paths":["cmd/**/*.go"],"surface":"command-line input"}],"notes":[]}`})

	requireReconArea(t, f.context(t, db.Scan{Ref: "topic"}), "topic parser")
	requireReconArea(t, f.context(t, db.Scan{SubPath: "cmd"}), "CLI parser")
}

func TestReconContextRejectsInvalidReports(t *testing.T) {
	f := newReconContextFixture(t)
	recon := f.seedReconScan(t, db.Scan{ScanGroup: "batch-a", Report: `{"focus_areas":[{"name":"XML parser","paths":["lib/xml*.c"],"surface":"XML documents from callers"}],"notes":[]}`})
	if err := f.worker.DB.Model(&recon).Update("report", `{"focus_areas":[{"name":"bad","paths":["../private/**"],"surface":"bad"}],"notes":[]}`).Error; err != nil {
		t.Fatal(err)
	}
	if ctx := f.context(t, db.Scan{ScanGroup: "batch-a"}); ctx != nil {
		t.Fatalf("invalid recon context = %+v", ctx)
	}
	if err := f.worker.DB.Model(&recon).Update("report", `{"focus_areas":[]}`).Error; err != nil {
		t.Fatal(err)
	}
	if ctx := f.context(t, db.Scan{ScanGroup: "batch-a"}); ctx != nil {
		t.Fatalf("schema-invalid recon context = %+v", ctx)
	}
}

func TestStageImportPayload(t *testing.T) {
	dir := t.TempDir()
	if err := stageImportPayload(dir, []byte("scanner output")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "import", "report"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "scanner output" {
		t.Errorf("payload = %q", string(b))
	}
}

func TestStageImportPayload_emptyStagesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := stageImportPayload(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "import")); !os.IsNotExist(err) {
		t.Errorf("import dir should not exist, stat err = %v", err)
	}
}

func TestStageSkill_writesMarkdownAndSchema(t *testing.T) {
	work := t.TempDir()
	dir := filepath.Join(work, ".claude", "skills", "s")
	skill := &db.Skill{
		Name:        "s",
		Description: "d",
		Body:        "body",
		SchemaJSON:  `{"x":1}`,
		Source:      "ui",
	}
	if err := stageSkill(skill, work, dir); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "name: s") || !strings.Contains(string(md), "description: d") {
		t.Errorf("missing frontmatter: %q", string(md))
	}
	if !strings.Contains(string(md), "body") {
		t.Errorf("missing body: %q", string(md))
	}
	sch, err := os.ReadFile(filepath.Join(dir, "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(sch) != `{"x":1}` {
		t.Errorf("schema in skill dir: %q", string(sch))
	}
	rootSch, err := os.ReadFile(filepath.Join(work, "schema.json"))
	if err != nil {
		t.Fatalf("schema.json not staged at work root: %v", err)
	}
	if string(rootSch) != `{"x":1}` {
		t.Errorf("schema at work root: %q", string(rootSch))
	}
}

func TestStageSkill_mirrorsScriptsToWorkRoot(t *testing.T) {
	// On-disk skill with a scripts/ dir: stageSkill should copy it to the
	// workspace root so `bash scripts/...` resolves from cwd, not from
	// .claude/skills/{name}/scripts/.
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "scripts", "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "scripts", "helper.py"), []byte("print('x')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# placeholder\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	skill := &db.Skill{Name: "s", Description: "d", Body: "body", SourcePath: src, Source: "disk"}
	if err := stageSkill(skill, work, filepath.Join(work, ".claude", "skills", "s")); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"scripts/run.sh", "scripts/helper.py"} {
		if _, err := os.Stat(filepath.Join(work, rel)); err != nil {
			t.Errorf("expected %s at work root: %v", rel, err)
		}
	}
	// File mode of executable scripts should be preserved so `bash` /
	// direct invocation works.
	info, err := os.Stat(filepath.Join(work, "scripts", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("run.sh executable bit lost: %v", info.Mode())
	}
}

func TestStageSkill_remirrorClearsStaleScripts(t *testing.T) {
	// A retry restages into the same workspace. After the skill's scripts/
	// changed on disk, the mirror must not leave a removed script behind,
	// and a dangling symlink in scripts/ must not abort staging.
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# placeholder\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "scripts", "old.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	skill := &db.Skill{Name: "s", Description: "d", Body: "body", SourcePath: src, Source: "disk"}
	if err := stageSkill(skill, work, filepath.Join(work, ".claude", "skills", "s")); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(src, "scripts", "old.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "scripts", "new.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("does-not-exist", filepath.Join(src, "scripts", "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := stageSkill(skill, work, filepath.Join(work, ".claude", "skills", "s")); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(work, "scripts", "old.sh")); !os.IsNotExist(err) {
		t.Errorf("stale old.sh survived remirror, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(work, "scripts", "new.sh")); err != nil {
		t.Errorf("new.sh not mirrored: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(work, "scripts", "dangling")); err != nil {
		t.Errorf("dangling symlink should be recreated, not dropped or fatal: %v", err)
	}
	// copyAux stages the same scripts/ into .claude/skills/{name}/ before
	// mirrorScripts runs; it must also recreate the dangling link rather
	// than choke on it.
	if _, err := os.Lstat(filepath.Join(work, ".claude", "skills", "s", "scripts", "dangling")); err != nil {
		t.Errorf("copyAux dropped dangling symlink under .claude/skills: %v", err)
	}
}

func TestStageSkill_noScriptsDirIsNoop(t *testing.T) {
	// A skill without scripts/ on disk must not error out and must not
	// leave a stray empty scripts/ at work root.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "SKILL.md"), []byte("# placeholder\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	skill := &db.Skill{Name: "s", Description: "d", Body: "body", SourcePath: src, Source: "disk"}
	if err := stageSkill(skill, work, filepath.Join(work, ".claude", "skills", "s")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, "scripts")); !os.IsNotExist(err) {
		t.Errorf("expected no scripts/ dir at work root, got err=%v", err)
	}
}

func TestStageSkill_mirrorsContextJSONToSkillDir(t *testing.T) {
	// stageContext writes context.json to workRoot; stageSkill must copy it
	// into the skill directory so ./context.json resolves from the skill dir.
	work := t.TempDir()
	ctx := `{"repository":{"url":"https://example.com/r"}}`
	if err := os.WriteFile(filepath.Join(work, "context.json"), []byte(ctx), 0o644); err != nil {
		t.Fatal(err)
	}
	skill := &db.Skill{Name: "s", Description: "d", Body: "body", Source: "ui"}
	dst := filepath.Join(work, ".claude", "skills", "s")
	if err := stageSkill(skill, work, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "context.json"))
	if err != nil {
		t.Fatalf("context.json not mirrored into skill dir: %v", err)
	}
	if string(got) != ctx {
		t.Errorf("mirrored context.json = %q, want %q", string(got), ctx)
	}
}

func TestStageContext_includesRef(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{URL: "https://example.com/x", Name: "x"}
	scan := &db.Scan{ID: 1, RepositoryID: 1, APIToken: "t", Ref: "2.4.x"}
	if err := stageContext(dir, "http://127.0.0.1:8080/api", "", "", scan, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scrutineer.ScanRef != "2.4.x" {
		t.Errorf("scan_ref = %q, want %q", got.Scrutineer.ScanRef, "2.4.x")
	}
}

func TestStageContext_omitsRefWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{URL: "https://example.com/x", Name: "x"}
	scan := &db.Scan{ID: 1, RepositoryID: 1, APIToken: "t"}
	if err := stageContext(dir, "http://127.0.0.1:8080/api", "", "", scan, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "scan_ref") {
		t.Errorf("scan_ref should be omitted when empty, got: %s", b)
	}
	if strings.Contains(string(b), "fork_org") {
		t.Errorf("fork_org should be omitted when empty, got: %s", b)
	}
}

func TestStageContext_includesForkOrg(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{URL: "https://github.com/o/r", Name: "r"}
	scan := &db.Scan{ID: 1, RepositoryID: 1, APIToken: "t"}
	if err := stageContext(dir, "http://127.0.0.1:8080/api", "fork-central", "", scan, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scrutineer.ForkOrg != "fork-central" {
		t.Errorf("fork_org = %q, want fork-central", got.Scrutineer.ForkOrg)
	}
}

func TestStageContext_includesMetadataDir(t *testing.T) {
	dir := t.TempDir()
	repo := &db.Repository{URL: "https://github.com/o/r", Name: "r"}
	scan := &db.Scan{ID: 1, RepositoryID: 1, APIToken: "t"}
	if err := stageContext(dir, "http://127.0.0.1:8080/api", "", ".ossprey/", scan, repo); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got skillContext
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Scrutineer.MetadataDir != ".ossprey/" {
		t.Errorf("metadata_dir = %q, want .ossprey/", got.Scrutineer.MetadataDir)
	}
}

func TestWorker_metadataDir_defaultsWhenUnset(t *testing.T) {
	w := &Worker{}
	if got := w.metadataDir(); got != DefaultMetadataDir {
		t.Errorf("default = %q, want %q", got, DefaultMetadataDir)
	}
	w.MetadataDir = ".custom/"
	if got := w.metadataDir(); got != ".custom/" {
		t.Errorf("override = %q, want .custom/", got)
	}
}

func TestApplyPathFilters_builtinSkipList(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{
		"main.go":                   "package main",
		"node_modules/foo/index.js": "x",
		"package-lock.json":         "{}",
		"dist/bundle.js":            "x",
		"src/app.go":                "x",
		"app.min.js":                "x",
	})
	var events []string
	emit := func(e Event) { events = append(events, e.Text) }

	if err := applyPathFilters(work, &db.Skill{}, emit); err != nil {
		t.Fatalf("applyPathFilters: %v", err)
	}
	assertExists(t, src, "main.go", "src/app.go")
	assertGone(t, src, "node_modules/foo/index.js", "package-lock.json", "dist/bundle.js", "app.min.js")
	if !hasMatchingEvent(events, "excluded by path filters") {
		t.Errorf("expected scan-log event, got %v", events)
	}
}

func TestApplyPathFilters_pathsOverrideSkipList(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{
		"src/main.go":               "x",
		"lib/util.go":               "x",
		"docs/readme.md":            "x",
		"node_modules/foo/index.js": "x",
	})
	skill := &db.Skill{Paths: "node_modules/**\nsrc/**"}
	if err := applyPathFilters(work, skill, func(Event) {}); err != nil {
		t.Fatalf("applyPathFilters: %v", err)
	}
	assertExists(t, src, "src/main.go", "node_modules/foo/index.js")
	assertGone(t, src, "lib/util.go", "docs/readme.md")
}

func TestApplyPathFilters_ignorePathsCumulative(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{
		"src/foo.go":      "x",
		"src/foo_test.go": "x",
		"src/bar.go":      "x",
	})
	skill := &db.Skill{IgnorePaths: "**/*_test.go"}
	if err := applyPathFilters(work, skill, func(Event) {}); err != nil {
		t.Fatalf("applyPathFilters: %v", err)
	}
	assertExists(t, src, "src/foo.go", "src/bar.go")
	assertGone(t, src, "src/foo_test.go")
}

func TestApplyRepositoryPathFilters_layersRepositorySkip(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{
		"src/main.go":    "x",
		"tests/main.go":  "x",
		"docs/readme.md": "x",
	})
	skill := &db.Skill{Paths: "src/**\ntests/**\ndocs/**"}
	if err := applyRepositoryPathFilters(work, skill, "skip: [tests/**]", func(Event) {}); err != nil {
		t.Fatalf("applyRepositoryPathFilters: %v", err)
	}
	assertExists(t, src, "src/main.go", "docs/readme.md")
	assertGone(t, src, "tests/main.go")
}

func TestApplyFocusAreaPathFilter(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{
		"lib/xmlparse.c": "x",
		"lib/xmlrole.c":  "x",
		"cmd/tool.c":     "x",
		".git/HEAD":      "ref: refs/heads/main",
	})
	area := repoconfig.FocusArea{Name: "XML parser", Paths: []string{"lib/xml*.c"}, Surface: "untrusted XML"}
	if err := applyFocusAreaPathFilter(work, area, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	assertExists(t, src, "lib/xmlparse.c", "lib/xmlrole.c", ".git/HEAD")
	assertGone(t, src, "cmd/tool.c")
}

func TestApplyPathFilters_gitPreserved(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{
		".git/HEAD":         "ref: refs/heads/main",
		".git/objects/info": "x",
		"main.go":           "x",
	})
	skill := &db.Skill{Paths: "src/**"} // would otherwise wipe everything
	if err := applyPathFilters(work, skill, func(Event) {}); err != nil {
		t.Fatalf("applyPathFilters: %v", err)
	}
	assertExists(t, src, ".git/HEAD", ".git/objects/info")
	assertGone(t, src, "main.go")
}

func TestApplyPathFilters_skipsExcludedSubtree(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{
		"main.go":                        "x",
		"node_modules/a/b/c/d/deep.js":   "x",
		"node_modules/.bin/cli":          "x",
		"pkg/node_modules/inner/leaf.js": "x",
		"dist/bundle.js":                 "x",
	})
	var events []string
	emit := func(e Event) { events = append(events, e.Text) }

	if err := applyPathFilters(work, &db.Skill{}, emit); err != nil {
		t.Fatalf("applyPathFilters: %v", err)
	}

	assertExists(t, src, "main.go")
	assertGone(t, src,
		"node_modules",
		"node_modules/a/b/c/d/deep.js",
		"pkg/node_modules",
		"pkg/node_modules/inner/leaf.js",
		"dist",
		"dist/bundle.js",
	)
	if _, err := os.Stat(filepath.Join(src, "pkg")); err != nil {
		t.Errorf("pkg/ (parent of an excluded subtree) should survive: %v", err)
	}
	if !hasMatchingEvent(events, "4 file(s) excluded by path filters") {
		t.Errorf("expected count of 4 file(s) in event, got %v", events)
	}
}

func TestApplyPathFilters_noopWhenNoSrcDir(t *testing.T) {
	work := t.TempDir()
	if err := applyPathFilters(work, &db.Skill{}, func(Event) {}); err != nil {
		t.Errorf("missing src/ should not be an error, got %v", err)
	}
}

func TestApplyPathFilters_noEventWhenNothingExcluded(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	writeFiles(t, src, map[string]string{"main.go": "x"})
	var emitted int
	if err := applyPathFilters(work, &db.Skill{}, func(Event) { emitted++ }); err != nil {
		t.Fatal(err)
	}
	if emitted != 0 {
		t.Errorf("emitted %d event(s), want 0 when nothing is excluded", emitted)
	}
}

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func assertExists(t *testing.T, root string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("expected %s to survive: %v", rel, err)
		}
	}
}

func assertGone(t *testing.T, root string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Errorf("expected %s to be filtered out", rel)
		}
	}
}

func hasMatchingEvent(events []string, substr string) bool {
	for _, e := range events {
		if strings.Contains(e, substr) {
			return true
		}
	}
	return false
}
