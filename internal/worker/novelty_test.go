package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/testutil"
)

func TestNoveltyContextMarksUntouchedFileUnfixed(t *testing.T) {
	fixture := newNoveltyFixture(t)
	fixture.write(t, "README.md", "unrelated change\n")
	head := gitCommit(t, fixture.src, "update docs")

	got := fixture.check(t, head)
	if got.State != db.FindingNoveltyUnfixed || got.FileChanged {
		t.Fatalf("novelty = %+v, want untouched/unfixed", got)
	}
	if got.CommitLog != "" {
		t.Errorf("commit_log = %q, want empty", got.CommitLog)
	}
	fixture.requirePersisted(t, db.FindingNoveltyUnfixed, head)
}

func TestNoveltyContextStagesBoundedChangedFileEvidence(t *testing.T) {
	fixture := newNoveltyFixture(t)
	fixture.write(t, "pkg/parse.go", "package pkg\n\nfunc parse(input string) string { return clean(input) }\n")
	head := gitCommit(t, fixture.src, "guard parser input")

	got := fixture.check(t, head)
	if got.State != db.FindingNoveltyUnclear || !got.FileChanged {
		t.Fatalf("novelty = %+v, want changed/unclear", got)
	}
	if !strings.Contains(got.CommitLog, "guard parser input") || !strings.Contains(got.CommitLog, "clean(input)") {
		t.Errorf("commit_log missing bounded patch evidence:\n%s", got.CommitLog)
	}
	fixture.requirePersisted(t, db.FindingNoveltyUnclear, head)

	scan := fixture.scan(head)
	document, err := buildSkillContext(
		"http://127.0.0.1:8080/api", "", DefaultMetadataDir,
		scan, &fixture.repo, nil, got, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeSkillContext(fixture.workRoot, "", document); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(fixture.workRoot, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var staged skillContext
	if err := json.Unmarshal(data, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Scrutineer.Novelty == nil || staged.Scrutineer.Novelty.CommitLog != got.CommitLog {
		t.Fatalf("staged novelty = %+v, want host-generated evidence", staged.Scrutineer.Novelty)
	}

	scan.FindingID = new(fixture.finding.ID)
	if err := (&Worker{DB: fixture.gdb}).parseRevalidateOutput(
		scan,
		`{"verdict":"already_fixed","reason":"the staged commit adds the missing guard"}`,
		func(Event) {},
	); err != nil {
		t.Fatal(err)
	}
	fixture.requirePersisted(t, db.FindingNoveltyFixed, head)
}

func TestNoveltyContextMarksCommitCapTruncated(t *testing.T) {
	fixture := newNoveltyFixture(t)
	var head string
	for i := 1; i <= noveltyLogMaxCommits+1; i++ {
		fixture.write(t, "pkg/parse.go", "package pkg\n\n// revision "+strconv.Itoa(i)+"\n")
		head = gitCommit(t, fixture.src, "parser revision "+strconv.Itoa(i))
	}

	got := fixture.check(t, head)
	if got.State != db.FindingNoveltyUnclear || !got.LogTruncated {
		t.Fatalf("novelty = %+v, want unclear with truncated commit history", got)
	}
	if strings.Contains(got.CommitLog, "parser revision 1\n") {
		t.Error("commit_log includes a commit beyond the configured cap")
	}
}

func TestNoveltyContextTreatsFindingFileAsLiteralPathspec(t *testing.T) {
	fixture := newNoveltyFixture(t)
	fixture.finding.Location = "*:1"
	if err := fixture.gdb.Model(&fixture.finding).Update("location", fixture.finding.Location).Error; err != nil {
		t.Fatal(err)
	}
	// Change an unrelated top-level file so a glob "*" would match it.
	fixture.write(t, "README.md", "unrelated change\n")
	head := gitCommit(t, fixture.src, "update docs")

	got := fixture.check(t, head)
	if got.FileChanged || got.State != db.FindingNoveltyUnfixed {
		t.Fatalf("glob location matched repository files: %+v", got)
	}
	if strings.Contains(got.CommitLog, "README.md") {
		t.Fatalf("commit_log carries the unrelated file's diff:\n%s", got.CommitLog)
	}
}

func TestGitLimited_capsOutput(t *testing.T) {
	src := t.TempDir()
	gitRun(t, src, "init")
	// A commit whose patch is well over the cap we ask for.
	big := strings.Repeat("a line of body text to pad the diff\n", 2000)
	if err := os.WriteFile(filepath.Join(src, "big.txt"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	gitCommit(t, src, "add big file")

	const cap = 1024
	out, err := gitLimited(context.Background(), cap, nil, "-C", src, "log", "--patch")
	if err != nil {
		t.Fatalf("gitLimited: %v", err)
	}
	if len(out) != cap {
		t.Fatalf("gitLimited buffered %d bytes, cap is %d", len(out), cap)
	}
}

func TestGitLimited_boundsDiagnosticsAndPreservesFailure(t *testing.T) {
	fixture := newNoveltyFixture(t)
	fixture.write(t, "pkg/parse.go", "package pkg\nfunc parse(input string) string { return clean(input) }\n")
	head := gitCommit(t, fixture.src, "guard parser input")
	fixture.write(t, ".gitattributes", strings.Repeat("* invalid/attribute\n", 1000))

	const cap = 1024
	for _, tc := range []struct {
		name     string
		args     []string
		exitCode int
	}{
		{"unknown revision", []string{"log", "missing-revision"}, 128},
		{"partial output and diagnostics", []string{"diff", "--exit-code", fixture.base, head, "--", "pkg/parse.go"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-C", fixture.src}, tc.args...)
			out, err := gitLimited(context.Background(), cap, nil, args...)
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || out != "" {
				t.Fatalf("gitLimited = (%q, %v), want empty output and exit error", out, err)
			}
			if exitErr.ExitCode() != tc.exitCode {
				t.Fatalf("exit code = %d, want %d", exitErr.ExitCode(), tc.exitCode)
			}
			prefix := "git: " + exitErr.Error() + ": "
			diagnostic, ok := strings.CutPrefix(err.Error(), prefix)
			if !ok || diagnostic == "" || len(diagnostic) > cap {
				t.Fatalf("diagnostic length = %d, want 1..%d", len(diagnostic), cap)
			}
			if tc.name == "partial output and diagnostics" && !strings.Contains(diagnostic, "invalid/attribute") {
				t.Fatalf("missing Git diagnostic: %s", diagnostic)
			}
		})
	}
}

func TestCappedWriter(t *testing.T) {
	w := &cappedWriter{limit: 5}
	n, _ := w.Write([]byte("abc"))
	if n != 3 || w.buf.String() != "abc" {
		t.Fatalf("under-limit write: n=%d buf=%q", n, w.buf.String())
	}
	n, _ = w.Write([]byte("defgh"))
	if n != 5 || w.buf.String() != "abcde" {
		t.Fatalf("over-limit write: n=%d buf=%q", n, w.buf.String())
	}
	n, _ = w.Write([]byte("x"))
	if n != 1 || w.buf.Len() != 5 {
		t.Fatalf("post-cap write must report success without buffering: n=%d len=%d", n, w.buf.Len())
	}
}

func TestDoSkillNoveltyUsesLiteralPathsWithInheritedSettings(t *testing.T) {
	for _, variable := range []string{"GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS", "GIT_LITERAL_PATHSPECS"} {
		for _, location := range []string{"pkg/parse.go:3", "*:1"} {
			t.Run(variable+"/"+location, func(t *testing.T) {
				fixture := newNoveltyFixture(t)
				fixture.write(t, "pkg/parse.go", "package pkg\n"+strings.Repeat("// changed parser input\n", noveltyLogMaxBytes/10))
				head := gitCommit(t, fixture.src, "guard parser input")
				if err := fixture.gdb.Model(&fixture.finding).Update("location", location).Error; err != nil {
					t.Fatal(err)
				}
				t.Setenv(variable, "1")
				novelty := fixture.runScan(t, head)
				changed := location == "pkg/parse.go:3"
				wantState := db.FindingNoveltyUnfixed
				if changed {
					wantState = db.FindingNoveltyUnclear
				}
				if novelty == nil || novelty.State != wantState || novelty.FileChanged != changed || novelty.LogTruncated != changed {
					t.Fatalf("staged novelty = %+v, want state=%s changed=%v", novelty, wantState, changed)
				}
				if len(novelty.CommitLog) > noveltyLogMaxBytes || (changed && !strings.HasSuffix(novelty.CommitLog, "\n[truncated]\n")) || (!changed && novelty.CommitLog != "") {
					t.Fatalf("unexpected commit log: length=%d truncated=%v", len(novelty.CommitLog), novelty.LogTruncated)
				}
				fixture.requirePersisted(t, wantState, head)
			})
		}
	}
}

func TestNoveltyContextRecordsNotCheckedForUnsafeLocation(t *testing.T) {
	fixture := newNoveltyFixture(t)
	head := fixture.base
	previousCommit := strings.Repeat("a", 40)
	previousCheckedAt := time.Date(2026, time.July, 1, 12, 0, 0, 0, time.UTC)
	fixture.finding.Location = "../outside.go:4"
	if err := fixture.gdb.Model(&fixture.finding).Updates(map[string]any{
		"location":               fixture.finding.Location,
		"novelty_checked_commit": previousCommit,
		"novelty_checked_at":     previousCheckedAt,
	}).Error; err != nil {
		t.Fatal(err)
	}

	got := fixture.check(t, head)
	if got.State != db.FindingNoveltyNotChecked {
		t.Fatalf("novelty = %+v, want not_checked", got)
	}
	if !strings.Contains(got.NotCheckedWhy, "repository-relative") {
		t.Errorf("not_checked_reason = %q", got.NotCheckedWhy)
	}
	fixture.requirePersistedNotChecked(t, previousCommit, previousCheckedAt)

	if err := (&Worker{DB: fixture.gdb}).parseRevalidateOutput(
		fixture.scan(head),
		`{"verdict":"true_positive","reason":"model attempted a verdict without history"}`,
		func(Event) {},
	); err != nil {
		t.Fatal(err)
	}
	fixture.requirePersistedNotChecked(t, previousCommit, previousCheckedAt)
}

func TestPrepareNoveltyHistoryDeepensSharedCache(t *testing.T) {
	fixture := newNoveltyFixture(t)
	fixture.write(t, "README.md", "new head\n")
	head := gitCommit(t, fixture.src, "advance head")

	dataDir := t.TempDir()
	repoURL := "https://example.com/novelty-history"
	cacheSrc := filepath.Join(RepoCacheRoot(dataDir, repoURL), "src")
	if err := os.MkdirAll(filepath.Dir(cacheSrc), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "clone", "--quiet", "--depth=1", "file://"+fixture.src, cacheSrc)
	cmd.Env = testutil.GitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone shallow cache: %v\n%s", err, out)
	}
	if commitReachable(context.Background(), cacheSrc, fixture.base) {
		t.Fatal("base commit unexpectedly reachable before cache deepening")
	}

	scan := fixture.scan(head)
	scan.Repository.URL = repoURL
	w := &Worker{DB: fixture.gdb, DataDir: dataDir}
	// clone.Cache.EnsureCommit hardens fetch to https-only unless the
	// caller's env already sets GIT_ALLOW_PROTOCOL; this test's cache
	// origin is a file:// path.
	t.Setenv("GIT_ALLOW_PROTOCOL", "file")
	w.prepareNoveltyHistory(context.Background(), scan, &db.Skill{Name: revalidateSkillName})

	if !commitReachable(context.Background(), cacheSrc, fixture.base) {
		t.Fatal("base commit is not reachable after cache deepening")
	}
}

func TestTruncateNoveltyLogHonorsByteLimitAndUTF8(t *testing.T) {
	const marker = "\n[truncated]\n"
	prefixLimit := noveltyLogMaxBytes - len(marker)
	input := strings.Repeat("x", prefixLimit-1) + "€" + strings.Repeat("z", 100)

	got, truncated := truncateNoveltyLog(input)
	if !truncated {
		t.Fatal("truncateNoveltyLog did not report truncation")
	}
	if len(got) > noveltyLogMaxBytes {
		t.Fatalf("truncated log is %d bytes, want at most %d", len(got), noveltyLogMaxBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncated log is not valid UTF-8")
	}
	if !strings.HasSuffix(got, marker) {
		t.Fatalf("truncated log does not end with marker: %q", got[len(got)-32:])
	}
}

func TestRevalidateNoveltyRequiresDeterministicState(t *testing.T) {
	for _, current := range []db.FindingNovelty{"", db.FindingNoveltyNotChecked} {
		for _, verdict := range []string{"true_positive", "already_fixed"} {
			if got, ok := revalidateNovelty(current, verdict); ok || got != "" {
				t.Errorf("revalidateNovelty(%q, %q) = (%q, %v), want no update", current, verdict, got, ok)
			}
		}
	}
}

type noveltyFixture struct {
	workRoot string
	src      string
	gdb      *gorm.DB
	repo     db.Repository
	finding  db.Finding
	base     string
}

func newNoveltyFixture(t *testing.T) noveltyFixture {
	t.Helper()
	workRoot := t.TempDir()
	src := filepath.Join(workRoot, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, src, "init")
	if err := os.MkdirAll(filepath.Join(src, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(src, "pkg", "parse.go"),
		[]byte("package pkg\n\nfunc parse(input string) string { return input }\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	base := gitCommit(t, src, "add vulnerable parser")

	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "file://" + src, Name: "fixture"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	prior := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone, Commit: base}
	if err := gdb.Create(&prior).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{
		ScanID: prior.ID, RepositoryID: repo.ID, Title: "parser issue",
		Severity: "High", Status: db.FindingNew, Commit: base, Location: "pkg/parse.go:3",
	}
	if err := gdb.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	return noveltyFixture{
		workRoot: workRoot,
		src:      src,
		gdb:      gdb,
		repo:     repo,
		finding:  finding,
		base:     base,
	}
}

func (f noveltyFixture) write(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.src, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f noveltyFixture) scan(head string) *db.Scan {
	return &db.Scan{
		RepositoryID: f.repo.ID,
		Repository:   f.repo,
		FindingID:    new(f.finding.ID),
		Commit:       head,
	}
}

func (f noveltyFixture) runScan(t *testing.T, head string) *skillContextNovelty {
	t.Helper()
	skill := db.Skill{Name: revalidateSkillName, Body: "Check the finding.", OutputFile: "report.json", OutputKind: "revalidate", Active: true}
	if err := f.gdb.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan := f.scan(head)
	scan.Kind, scan.Status, scan.Model, scan.SkillID = JobSkill, db.ScanQueued, "fake", &skill.ID
	if err := f.gdb.Create(scan).Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: f.gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.PrepareRepoSrcWithOptions = func(_ context.Context, _, _, workRoot string, _ RepoSrcOptions, _ func(Event)) (string, error) {
		gitRun(t, f.src, "clone", "--quiet", "--local", f.src, filepath.Join(workRoot, "src"))
		return head, nil
	}
	var staged skillContext
	w.Runner = &capRunner{first: func(_ context.Context, _ func(Event)) (SkillResult, error) {
		data, err := os.ReadFile(filepath.Join(w.scanWorkRoot(scan), "context.json"))
		if err != nil {
			return SkillResult{}, err
		}
		if err := json.Unmarshal(data, &staged); err != nil {
			return SkillResult{}, err
		}
		return SkillResult{Commit: head, Report: `{"verdict":"uncertain","reason":"review the changed parser"}`}, nil
	}}
	got := runCapScan(t, w, scan)
	if got.Status != db.ScanDone {
		t.Fatalf("scan status = %s: %s", got.Status, got.Error)
	}
	return staged.Scrutineer.Novelty
}

func (f noveltyFixture) check(t *testing.T, head string) *skillContextNovelty {
	t.Helper()
	w := &Worker{DB: f.gdb}
	got, err := w.noveltyContext(
		context.Background(), f.workRoot, f.scan(head), &db.Skill{Name: revalidateSkillName},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("novelty context is nil")
	}
	return got
}

func (f noveltyFixture) requirePersisted(t *testing.T, state db.FindingNovelty, commit string) {
	t.Helper()
	var finding db.Finding
	if err := f.gdb.First(&finding, f.finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if finding.Novelty != state || finding.NoveltyCheckedCommit != commit || finding.NoveltyCheckedAt == nil {
		t.Errorf("persisted novelty = %+v, want state=%q commit=%q checked_at", finding, state, commit)
	}
}

func (f noveltyFixture) requirePersistedNotChecked(t *testing.T, commit string, checkedAt time.Time) {
	t.Helper()
	var finding db.Finding
	if err := f.gdb.First(&finding, f.finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if finding.Novelty != db.FindingNoveltyNotChecked ||
		finding.NoveltyCheckedCommit != commit ||
		finding.NoveltyCheckedAt == nil ||
		!finding.NoveltyCheckedAt.Equal(checkedAt) {
		t.Errorf(
			"persisted novelty = %+v, want not_checked with prior commit=%q checked_at=%s",
			finding, commit, checkedAt,
		)
	}
}
