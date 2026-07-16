package worker

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
)

func TestPrepareDiffRescanStagesDiffInputs(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	repoDir := initGitRepo(t)
	writeDiffTestFile(t, repoDir, "app.go", "package main\n\nfunc old() {}\n")
	base := gitCommit(t, repoDir, "base")
	writeDiffTestFile(t, repoDir, "app.go", "package main\n\nfunc old() {}\nfunc added() {}\n")
	head := gitCommit(t, repoDir, "head")

	repo := db.Repository{URL: "file://" + repoDir, Name: "r"}
	gdb.Create(&repo)
	baseline := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone, Commit: base}
	gdb.Create(&baseline)
	tm := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "threat-model", Status: db.ScanDone, Commit: base, Report: `{"spec_version":1}`}
	gdb.Create(&tm)
	scan := db.Scan{
		RepositoryID: repo.ID,
		Repository:   repo,
		Kind:         JobSkill,
		SkillName:    "security-deep-dive",
		Status:       db.ScanRunning,
		Commit:       head,
		RescanMode:   db.ScanRescanModeDiff,
	}
	gdb.Create(&scan)

	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.Default()}
	workRoot := w.scanWorkRoot(&scan)
	if err := CopyTree(repoDir, filepath.Join(workRoot, "src")); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareDiffRescan(context.Background(), &scan, workRoot, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	patch := readDiffTestFile(t, filepath.Join(workRoot, diffPatchFile))
	if !strings.Contains(patch, "func added") {
		t.Fatalf("diff.patch missing changed code:\n%s", patch)
	}
	var changed []changedFile
	readDiffTestJSONFile(t, filepath.Join(workRoot, changedFilesFile), &changed)
	if len(changed) != 1 || changed[0].Path != "app.go" || changed[0].Status != "M" {
		t.Fatalf("changed files = %+v, want modified app.go", changed)
	}
	if got := readDiffTestFile(t, filepath.Join(workRoot, oldThreatModelFile)); got != tm.Report {
		t.Fatalf("old threat model = %q, want %q", got, tm.Report)
	}

	var stored db.Scan
	gdb.First(&stored, scan.ID)
	if stored.RescanMode != db.ScanRescanModeDiff || stored.DiffBaseCommit != base {
		t.Fatalf("stored diff metadata mode=%q base=%q", stored.RescanMode, stored.DiffBaseCommit)
	}
	if stored.DiffBaseScanID == nil || *stored.DiffBaseScanID != baseline.ID {
		t.Fatalf("diff base scan id = %v, want %d", stored.DiffBaseScanID, baseline.ID)
	}
	if stored.DiffThreatModelScanID == nil || *stored.DiffThreatModelScanID != tm.ID {
		t.Fatalf("threat model scan id = %v, want %d", stored.DiffThreatModelScanID, tm.ID)
	}

	if err := stageContext(workRoot, "http://api", "", DefaultMetadataDir, &stored, &repo); err != nil {
		t.Fatal(err)
	}
	var ctx skillContext
	readDiffTestJSONFile(t, filepath.Join(workRoot, "context.json"), &ctx)
	if ctx.Scrutineer.Rescan == nil || ctx.Scrutineer.Rescan.BaseCommit != base || ctx.Scrutineer.Rescan.HeadCommit != head {
		t.Fatalf("context rescan = %+v, want base/head", ctx.Scrutineer.Rescan)
	}
	if ctx.Scrutineer.Rescan.DiffFile != diffPatchFile || ctx.Scrutineer.Rescan.ChangedFilesFile != changedFilesFile {
		t.Fatalf("context files = %+v", ctx.Scrutineer.Rescan)
	}
}

func TestDiffBaselineMatchesFocusArea(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "file:///tmp/focus", Name: "focus"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	focus := `{"name":"parser","paths":["src/**"],"surface":"request bytes"}`
	matching := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone, Commit: "base-focus", FocusArea: focus}
	newerOther := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone, Commit: "base-whole"}
	gdb.Create(&matching)
	gdb.Create(&newerOther)

	w := &Worker{DB: gdb}
	scan := &db.Scan{RepositoryID: repo.ID, SkillName: "security-deep-dive", FocusArea: focus}
	baseline, ok := w.diffBaseline(scan)
	if !ok || baseline.ID != matching.ID {
		t.Fatalf("baseline = %+v ok=%v, want focus scan %d", baseline, ok, matching.ID)
	}
}

func TestPrepareDiffRescanScopesDiffToSubPath(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	repoDir := initGitRepo(t)
	writeDiffTestFile(t, repoDir, "pkg/app.go", "package pkg\n\nfunc old() {}\n")
	writeDiffTestFile(t, repoDir, "README.md", "old\n")
	base := gitCommit(t, repoDir, "base")
	writeDiffTestFile(t, repoDir, "pkg/app.go", "package pkg\n\nfunc old() {}\nfunc added() {}\n")
	writeDiffTestFile(t, repoDir, "README.md", "new\n")
	head := gitCommit(t, repoDir, "head")

	repo := db.Repository{URL: "file://" + repoDir, Name: "r"}
	gdb.Create(&repo)
	baseline := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone, Commit: base, SubPath: "pkg"}
	gdb.Create(&baseline)
	scan := db.Scan{
		RepositoryID: repo.ID,
		Repository:   repo,
		Kind:         JobSkill,
		SkillName:    "security-deep-dive",
		Status:       db.ScanRunning,
		Commit:       head,
		RescanMode:   db.ScanRescanModeDiff,
		SubPath:      "pkg",
	}
	gdb.Create(&scan)

	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.Default()}
	workRoot := w.scanWorkRoot(&scan)
	if err := CopyTree(repoDir, filepath.Join(workRoot, "src")); err != nil {
		t.Fatal(err)
	}
	if err := w.prepareDiffRescan(context.Background(), &scan, workRoot, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	patch := readDiffTestFile(t, filepath.Join(workRoot, diffPatchFile))
	if !strings.Contains(patch, "pkg/app.go") || strings.Contains(patch, "README.md") {
		t.Fatalf("diff.patch not scoped to subpath:\n%s", patch)
	}
	var changed []changedFile
	readDiffTestJSONFile(t, filepath.Join(workRoot, changedFilesFile), &changed)
	if len(changed) != 1 || changed[0].Path != "pkg/app.go" {
		t.Fatalf("changed files = %+v, want only pkg/app.go", changed)
	}
}

func TestPrepareDiffRescanFallsBackWithoutBaseline(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "file://" + t.TempDir(), Name: "r"}
	gdb.Create(&repo)
	missingBaselineID := uint(999)
	staleThreatModelID := uint(123)
	scan := db.Scan{
		RepositoryID:          repo.ID,
		Repository:            repo,
		Kind:                  JobSkill,
		SkillName:             "security-deep-dive",
		Status:                db.ScanRunning,
		Commit:                "abc",
		RescanMode:            db.ScanRescanModeDiff,
		DiffBaseScanID:        &missingBaselineID,
		DiffBaseCommit:        "stale",
		DiffThreatModelScanID: &staleThreatModelID,
		DiffStats:             `{"stale":true}`,
	}
	gdb.Create(&scan)

	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.Default()}
	if err := w.prepareDiffRescan(context.Background(), &scan, w.scanWorkRoot(&scan), func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if scan.RescanMode != db.ScanRescanModeFull {
		t.Fatalf("mode = %q, want full fallback", scan.RescanMode)
	}
	var cov diffCoverage
	if err := json.Unmarshal([]byte(scan.Coverage), &cov); err != nil {
		t.Fatal(err)
	}
	if cov.RequestedMode != db.ScanRescanModeDiff || cov.ActualMode != db.ScanRescanModeFull || !strings.Contains(cov.FallbackReason, "baseline") {
		t.Fatalf("coverage = %+v", cov)
	}
	var stored db.Scan
	gdb.First(&stored, scan.ID)
	if stored.DiffBaseScanID != nil || stored.DiffBaseCommit != "" || stored.DiffThreatModelScanID != nil || stored.DiffStats != "" {
		t.Fatalf("fallback kept stale diff metadata: baseID=%v base=%q tmID=%v stats=%q",
			stored.DiffBaseScanID, stored.DiffBaseCommit, stored.DiffThreatModelScanID, stored.DiffStats)
	}
}

func TestParseChangedFilesPreservesPathWhitespaceAndSkipsMalformedStatus(t *testing.T) {
	got := parseChangedFiles("M\tpath/with trailing space \n\tmissing-status\nR100\told name \tnew name \r\n")
	if len(got) != 2 {
		t.Fatalf("changed files = %+v, want two valid rows", got)
	}
	if got[0].Status != "M" || got[0].Path != "path/with trailing space " {
		t.Fatalf("first changed file = %+v, want path whitespace preserved", got[0])
	}
	if got[1].Status != "R" || got[1].Old != "old name " || got[1].Path != "new name " {
		t.Fatalf("rename changed file = %+v, want whitespace preserved", got[1])
	}
}

func TestParseFindingsOutputDiffScanDoesNotMarkPriorFindingsMissed(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.Default()}

	baseline := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone, Commit: "base"}
	gdb.Create(baseline)
	report := `{"findings":[{"id":"F1","title":"old","severity":"High","cwe":"CWE-1","location":"old.go:10"}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, baseline, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	diffScan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive", Status: db.ScanDone, Commit: "head", RescanMode: db.ScanRescanModeDiff}
	gdb.Create(diffScan)
	if err := w.parseFindingsOutput(&db.Skill{}, diffScan, `{"findings":[]}`, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.MissedCount != 0 || f.LastMissedScanID != 0 {
		t.Fatalf("diff scan marked prior finding missed: missed=%d last=%d", f.MissedCount, f.LastMissedScanID)
	}
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, "init")
	return dir
}

func gitCommit(t *testing.T, dir, msg string) string {
	t.Helper()
	gitRun(t, dir, "add", ".")
	gitRun(t, dir, "commit", "-m", msg)
	out := gitRun(t, dir, "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = testutil.GitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func writeDiffTestFile(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readDiffTestFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func readDiffTestJSONFile(t *testing.T, path string, dst any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode %s: %v\n%s", path, err, raw)
	}
}
