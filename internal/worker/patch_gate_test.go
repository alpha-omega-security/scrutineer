package worker

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
)

func TestParseUnifiedDiff(t *testing.T) {
	tests := []struct {
		name string
		diff string
		want []diffFile
	}{
		{
			"single file single hunk",
			"--- a/pkg/foo.go\n+++ b/pkg/foo.go\n@@ -10,3 +10,4 @@ func x() {\n a\n-b\n+c\n+d\n",
			[]diffFile{{Path: "pkg/foo.go"}},
		},
		{
			"multi file",
			"diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n@@ -1 +1 @@\n-x\n+y\n" +
				"diff --git a/b.go b/b.go\n--- a/b.go\n+++ b/b.go\n@@ -5,2 +5,3 @@\n a\n-b\n+c\n+d\n",
			[]diffFile{{Path: "a.go"}, {Path: "b.go"}},
		},
		{
			"new file",
			"--- /dev/null\n+++ b/new.go\n@@ -0,0 +1,3 @@\n+a\n+b\n+c\n",
			[]diffFile{{Path: "new.go", NewFile: true}},
		},
		{
			"deleted file",
			"--- a/gone.go\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n",
			[]diffFile{{Path: ""}},
		},
		{
			"timestamp after path",
			"--- a/x.go\t2026-01-01\n+++ b/x.go\t2026-01-02\n@@ -3 +3 @@\n-a\n+b\n",
			[]diffFile{{Path: "x.go"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseUnifiedDiff(tc.diff)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseUnifiedDiff = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseUnifiedDiff_errors(t *testing.T) {
	if _, err := parseUnifiedDiff("+++ b/x.go\n"); err == nil {
		t.Error("expected error for +++ without ---")
	}
	if _, err := parseUnifiedDiff("@@ -1 +1 @@\n"); err == nil {
		t.Error("expected error for hunk before file header")
	}
	if _, err := parseUnifiedDiff("--- a/x\n+++ b/x\n@@ garbage @@\n"); err == nil {
		t.Error("expected error for bad hunk header")
	}
	if _, err := parseUnifiedDiff("--- a/x\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n"); err == nil {
		t.Error("expected error for .. escape in target path")
	}
	if _, err := parseUnifiedDiff("--- a/x\n+++ b//etc/passwd\n@@ -1 +1 @@\n"); err == nil {
		t.Error("expected error for absolute target path")
	}
	if _, err := parseUnifiedDiff("--- /dev/null\n+++ b/sub/new.go\n@@ -0,0 +1 @@\n"); err != nil {
		t.Errorf("local relative path should be accepted: %v", err)
	}
}

func TestLocationPaths(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"pkg/foo.go:42", []string{"pkg/foo.go"}},
		{"pkg/foo.go:10-20", []string{"pkg/foo.go"}},
		{"pkg/foo.go", []string{"pkg/foo.go"}},
		{"", nil},
		{"  pkg/foo.go:7  ", []string{"pkg/foo.go"}},
		// Composite location from a deep-dive finding: several flagged files
		// plus a "(data path: ...)" trace. Every path:line reference is pulled
		// out and the trailing ")" must not leak into the last path.
		{
			"internal/ui/logtable.go:227-352, internal/ui/logsidepanel.go:206 (data path: internal/fetcher/lognetlistener.go -> internal/fetcher/logentry.go:106-135)",
			[]string{"internal/ui/logtable.go", "internal/ui/logsidepanel.go", "internal/fetcher/logentry.go"},
		},
	}
	for _, tc := range tests {
		if got := locationPaths(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("locationPaths(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCheckLocationFile(t *testing.T) {
	files := []diffFile{{Path: "pkg/foo.go"}, {Path: "pkg/bar.go"}}
	tests := []struct {
		loc  string
		want string
	}{
		{"pkg/foo.go:12", ""},
		{"pkg/foo.go:50", ""},
		{"pkg/foo.go", ""},
		{"pkg/bar.go:100", ""},
		{"", ""},
		// File named in the location is patched even though the flagged line
		// (:99) sits far from the hunk: a choke-point fix must still pass.
		{"pkg/zzz.go:1, pkg/foo.go:99 (data path: pkg/a.go -> pkg/b.go:2)", ""},
		{"pkg/other.go:5", "no patched file matches location pkg/other.go:5"},
		{"pkg/other.go", "no patched file matches location pkg/other.go"},
	}
	for _, tc := range tests {
		if got := checkLocationFile(files, tc.loc); got != tc.want {
			t.Errorf("checkLocationFile(%q) = %q, want %q", tc.loc, got, tc.want)
		}
	}
}

// gateRepo creates a git repo under dir with one file pkg/foo.go containing
// numbered lines 1..20, edits line 12, captures a real `git diff`, then
// resets the working tree. The returned diff is what the patch skill would
// produce, so git apply --check accepts it without --unidiff-zero.
func gateRepo(t *testing.T, dir string) (relPath, diff string) {
	t.Helper()
	const targetLine = 12
	relPath = "pkg/foo.go"
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i := 1; i <= 20; i++ {
		lines = append(lines, fmt.Sprintf("line %d", i))
	}
	write := func(ls []string) {
		if err := os.WriteFile(full, []byte(strings.Join(ls, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(lines)
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = testutil.GitEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
		return string(out)
	}
	run("init", "-q")
	run("config", "user.email", "t@t")
	run("config", "user.name", "t")
	run("add", ".")
	run("commit", "-q", "-m", "init")

	patched := append([]string(nil), lines...)
	patched[targetLine-1] = fmt.Sprintf("patched %d", targetLine)
	write(patched)
	diff = run("diff")
	run("checkout", "--", ".")
	return relPath, diff
}

func TestGatePatch(t *testing.T) {
	src := t.TempDir()
	rel, diff := gateRepo(t, src)

	if r := gatePatch(src, rel+":12", diff); r != "" {
		t.Errorf("pass case rejected: %q", r)
	}
	// File-level match: a fix to pkg/foo.go passes even when the flagged line
	// (:3) sits far from the hunk (line 12). This is the choke-point case the
	// old line-overlap gate wrongly rejected.
	if r := gatePatch(src, rel+":3", diff); r != "" {
		t.Errorf("file-level pass case rejected: %q", r)
	}
	if r := gatePatch(src, "pkg/unrelated.go:12", diff); !strings.Contains(r, "no patched file matches location") {
		t.Errorf("expected unrelated-location rejection, got %q", r)
	}
	if r := gatePatch(src, "pkg/missing.go:12",
		"--- a/pkg/missing.go\n+++ b/pkg/missing.go\n@@ -1 +1 @@\n-x\n+y\n"); !strings.Contains(r, "missing file") {
		t.Errorf("expected missing-file rejection, got %q", r)
	}
	if r := gatePatch(src, rel+":12", "not a diff"); !strings.Contains(r, "no file headers") {
		t.Errorf("expected no-file-headers rejection, got %q", r)
	}
	bad := strings.Replace(diff, "-line 12", "-WRONG", 1)
	if r := gatePatch(src, rel+":12", bad); !strings.Contains(r, "git apply --check") {
		t.Errorf("expected git apply rejection, got %q", r)
	}
	newFileDiff := "--- /dev/null\n+++ b/pkg/foo_test.go\n@@ -0,0 +1 @@\n+test\n" + diff
	if r := gatePatch(src, rel+":12", newFileDiff); r != "" {
		t.Errorf("new-file alongside fix rejected: %q", r)
	}
}

func TestGatePatch_dirtyWorkspaceFromSkill(t *testing.T) {
	// The real patch skill captures its diff with `git diff HEAD` and leaves
	// the edits applied in the workspace (it never reverts). The gate must
	// reset to HEAD before git apply --check, otherwise re-applying an
	// already-applied diff fails. gateRepo resets the tree, so reproduce the
	// skill's behaviour by re-applying the diff to dirty it first.
	src := t.TempDir()
	rel, diff := gateRepo(t, src)
	apply := exec.Command("git", "-C", src, "apply", "-")
	apply.Env = testutil.GitEnv()
	apply.Stdin = strings.NewReader(diff)
	if out, err := apply.CombinedOutput(); err != nil {
		t.Fatalf("seed dirty workspace: %v: %s", err, out)
	}
	if r := gatePatch(src, rel+":12", diff); r != "" {
		t.Errorf("gate rejected a valid patch against a skill-dirtied workspace: %q", r)
	}
}

func newPatchOutputFixture(t *testing.T) (*Worker, db.Finding) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	base := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	if err := gdb.Create(&base).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{ScanID: base.ID, RepositoryID: repo.ID, Title: "t",
		Severity: "Low", Location: "pkg/foo.go:12"}
	if err := gdb.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir()}
	return w, finding
}

func TestParsePatchOutput_passWritesColumnsAndHistory(t *testing.T) {
	w, finding := newPatchOutputFixture(t)
	sc := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanRunning, FindingID: &finding.ID}
	if err := w.DB.Create(&sc).Error; err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(w.workRoot(sc.ID), "src")
	_, diff := gateRepo(t, src)
	report := fmt.Sprintf(`{"patch":%q,"base_commit":"abc123"}`, diff)

	var events []string
	if err := w.parsePatchOutput(&sc, report, func(e Event) { events = append(events, e.Text) }); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	w.DB.First(&f, finding.ID)
	if f.SuggestedFix != diff {
		t.Errorf("SuggestedFix not written; got %q", f.SuggestedFix)
	}
	if f.SuggestedFixCommit != "abc123" {
		t.Errorf("SuggestedFixCommit = %q, want abc123", f.SuggestedFixCommit)
	}
	var hist []db.FindingHistory
	w.DB.Where("finding_id = ? AND field = ?", finding.ID, "suggested_fix").Find(&hist)
	if len(hist) != 1 || hist[0].By != "patch" || hist[0].Source != db.SourceModel {
		t.Errorf("history = %+v, want one row by=patch source=model_suggested", hist)
	}
	if !containsSubstr(events, "gate passed") {
		t.Errorf("events = %v, want gate-passed message", events)
	}
}

func TestParsePatchOutput_resumedScanUsesLineageWorkspace(t *testing.T) {
	// A patch run that resumes a session (ResumedFromScanID set) stages its
	// src tree under the lineage-root workspace, not scan-<retryID>/src. The
	// gate must resolve through scanWorkRoot like every other stage; using
	// workRoot(scan.ID) here stat'd a directory that was never created and
	// rejected every valid diff with "diff targets missing file".
	w, finding := newPatchOutputFixture(t)
	root := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanDone}
	if err := w.DB.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	resumed := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill,
		Status: db.ScanRunning, FindingID: &finding.ID, ResumedFromScanID: &root.ID}
	if err := w.DB.Create(&resumed).Error; err != nil {
		t.Fatal(err)
	}
	// Stage where the workspace actually lives (lineage root), and confirm the
	// retry's own id resolves to a different, nonexistent dir.
	src := filepath.Join(w.scanWorkRoot(&resumed), "src")
	if got := w.scanWorkRoot(&resumed); got == w.workRoot(resumed.ID) {
		t.Fatalf("test precondition broken: lineage workspace %q equals retry workspace", got)
	}
	_, diff := gateRepo(t, src)
	report := fmt.Sprintf(`{"patch":%q,"base_commit":"abc123"}`, diff)

	var events []string
	if err := w.parsePatchOutput(&resumed, report, func(e Event) { events = append(events, e.Text) }); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	w.DB.First(&f, finding.ID)
	if f.SuggestedFix != diff {
		t.Errorf("SuggestedFix not written for resumed scan; got %q (events=%v)", f.SuggestedFix, events)
	}
	if !containsSubstr(events, "gate passed") {
		t.Errorf("events = %v, want gate-passed message", events)
	}
}

func TestParsePatchOutput_gateRejectLeavesColumnsEmpty(t *testing.T) {
	w, finding := newPatchOutputFixture(t)
	sc := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanRunning, FindingID: &finding.ID}
	if err := w.DB.Create(&sc).Error; err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(w.workRoot(sc.ID), "src")
	gateRepo(t, src)
	report := `{"patch":"--- a/pkg/missing.go\n+++ b/pkg/missing.go\n@@ -1 +1 @@\n-x\n+y\n","base_commit":"abc"}`

	var events []string
	if err := w.parsePatchOutput(&sc, report, func(e Event) { events = append(events, e.Text) }); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	w.DB.First(&f, finding.ID)
	if f.SuggestedFix != "" || f.SuggestedFixCommit != "" {
		t.Errorf("columns should be empty after gate reject: fix=%q commit=%q", f.SuggestedFix, f.SuggestedFixCommit)
	}
	if !containsSubstr(events, "gate rejected") {
		t.Errorf("events = %v, want gate-rejected message", events)
	}
}

func TestParsePatchOutput_skillRefused(t *testing.T) {
	w, finding := newPatchOutputFixture(t)
	sc := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanRunning, FindingID: &finding.ID}
	if err := w.DB.Create(&sc).Error; err != nil {
		t.Fatal(err)
	}
	var events []string
	if err := w.parsePatchOutput(&sc, `{"error":"thin prose"}`, func(e Event) { events = append(events, e.Text) }); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	w.DB.First(&f, finding.ID)
	if f.SuggestedFix != "" {
		t.Error("SuggestedFix should be empty when skill refused")
	}
	if !containsSubstr(events, "skill refused") {
		t.Errorf("events = %v", events)
	}
}

func TestParsePatchOutput_notFindingScoped(t *testing.T) {
	w, finding := newPatchOutputFixture(t)
	sc := db.Scan{RepositoryID: finding.RepositoryID, Kind: JobSkill, Status: db.ScanRunning}
	if err := w.DB.Create(&sc).Error; err != nil {
		t.Fatal(err)
	}
	var events []string
	if err := w.parsePatchOutput(&sc, `{"patch":"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"}`,
		func(e Event) { events = append(events, e.Text) }); err != nil {
		t.Fatal(err)
	}
	if !containsSubstr(events, "not finding-scoped") {
		t.Errorf("events = %v, want not-finding-scoped message", events)
	}
}

func containsSubstr(events []string, sub string) bool {
	for _, e := range events {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
