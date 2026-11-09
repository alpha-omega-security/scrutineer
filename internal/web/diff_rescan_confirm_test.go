package web

import (
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
)

// diffRescanRepo seeds a local git repository whose HEAD changes `changed`
// files since the baseline commit, plus the diff-rescan skills. With
// baselines set, each grouped skill gets a completed scan at the baseline.
func diffRescanRepo(t *testing.T, s *Server, changed int, baselines bool) db.Repository {
	t.Helper()
	dir := t.TempDir()
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = testutil.GitEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commitAll := func(msg string) string {
		t.Helper()
		runGit("add", ".")
		runGit("commit", "--quiet", "-m", msg)
		return runGit("rev-parse", "HEAD")
	}
	runGit("init", "--quiet", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := commitAll("base")
	for i := range changed {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%03d.go", i)), []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commitAll("head")

	repo := db.Repository{URL: "file://" + dir, Name: "local"}
	s.DB.Create(&repo)
	for _, name := range append(diffRescanSkillNames, deepDiveSkillName) {
		s.DB.Create(&db.Skill{Name: name, Body: "b", OutputFile: "r.json",
			OutputKind: "freeform", Version: 1, Active: true, Source: "ui"})
		if baselines && name != deepDiveSkillName {
			s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: name, Status: db.ScanDone, Commit: base})
		}
	}
	return repo
}

func postDiffRescan(s *Server, repo db.Repository, hx bool, extra string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/scan", repo.ID), strings.NewReader("rescan_mode=diff"+extra))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if hx {
		req.Header.Set("HX-Request", "true")
	}
	asOperator(req)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func queuedScans(t *testing.T, s *Server, repo db.Repository) int64 {
	t.Helper()
	var n int64
	if err := s.DB.Model(&db.Scan{}).Where("repository_id = ? AND status = ?", repo.ID, db.ScanQueued).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRepoDiffScan_underLimitQueuesWithoutConfirmation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := diffRescanRepo(t, s, 3, true)

	w := postDiffRescan(s, repo, true, "")

	if w.Header().Get("HX-Redirect") == "" || strings.Contains(w.Body.String(), "diff-rescan-confirm") {
		t.Fatalf("under-limit diff rescan asked for confirmation: code=%d body=%s", w.Code, w.Body.String())
	}
	if n := queuedScans(t, s, repo); n != int64(len(diffRescanSkillNames)) {
		t.Fatalf("queued scans = %d, want %d", n, len(diffRescanSkillNames))
	}
}

func TestRepoDiffScan_overLimitAsksConfirmationBeforeQueueing(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := diffRescanRepo(t, s, 201, true)

	w := postDiffRescan(s, repo, true, "")

	body := w.Body.String()
	for _, want := range []string{
		`id="diff-rescan-confirm" hx-swap-oob="outerHTML"`,
		"would cost a full scan",
		threatModelSkillName + ": diff changed 201 files; limit is 200",
		`name="confirm_full" value="1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("confirmation missing %q in body=%s", want, body)
		}
	}
	if n := queuedScans(t, s, repo); n != 0 {
		t.Fatalf("queued scans = %d before confirmation, want 0", n)
	}

	w = postDiffRescan(s, repo, true, "&confirm_full=1")

	if w.Header().Get("HX-Redirect") == "" {
		t.Fatalf("confirmed diff rescan did not redirect: code=%d body=%s", w.Code, w.Body.String())
	}
	if n := queuedScans(t, s, repo); n != int64(len(diffRescanSkillNames)) {
		t.Fatalf("queued scans after confirmation = %d, want %d", n, len(diffRescanSkillNames))
	}
}

func TestRepoDiffScan_noBaselineConfirmsOnPlainPost(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := diffRescanRepo(t, s, 1, false)

	w := postDiffRescan(s, repo, false, "")

	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "Confirm diff rescan") ||
		!strings.Contains(body, reconSkillName+": no compatible baseline scan with a commit") {
		t.Fatalf("plain post did not render the confirmation page: code=%d body=%s", w.Code, body)
	}
	if n := queuedScans(t, s, repo); n != 0 {
		t.Fatalf("queued scans = %d before confirmation, want 0", n)
	}
}
