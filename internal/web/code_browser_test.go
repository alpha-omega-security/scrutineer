package web

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/git-pkgs/clone"
	"github.com/git-pkgs/magic"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
	"scrutineer/internal/worker"
)

func TestValidCommit(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"abcd", true},
		{strings.Repeat("a", 40), true},
		{strings.Repeat("a", 64), true},
		{"abc", false},
		{strings.Repeat("a", 65), false},
		{"abcg", false},
		{"ABCDEF12", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := clone.ValidCommit(tc.in); got != tc.want {
			t.Errorf("ValidCommit(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSanitizeBlobPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"lib/x.rb", "lib/x.rb", true},
		{"a/b/c.go", "a/b/c.go", true},
		{"./a.go", "a.go", true},
		{"", "", false},
		{"../etc/passwd", "", false},
		{"a/../b", "", false},
		{"a/./b", "a/b", true},
		{"/etc/passwd", "", false},
		{"a\x00b", "", false},
		{"..", "", false},
		{".", "", false},
	}
	for _, c := range cases {
		got, ok := sanitizeBlobPath(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("sanitizeBlobPath(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseHighlight(t *testing.T) {
	cases := []struct {
		in   string
		want [2]int
	}{
		{"", [2]int{0, 0}},
		{"5", [2]int{5, 5}},
		{"5-10", [2]int{5, 10}},
		{"0", [2]int{0, 0}},
		{"-3", [2]int{0, 0}},
		{"5-2", [2]int{0, 0}},
		{"abc", [2]int{0, 0}},
	}
	for _, c := range cases {
		if got := parseHighlight(c.in); got != c.want {
			t.Errorf("parseHighlight(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// seedRepoCache makes a real git repo at the cache path the handler will
// resolve, with two commits so `git show <commit>:<path>` works for both.
func seedRepoCache(t *testing.T, dataDir, url string) (commit1, commit2 string) {
	t.Helper()
	cacheSrc := filepath.Join(worker.RepoCacheRoot(dataDir, url), "src")
	if err := os.MkdirAll(cacheSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", cacheSrc}, args...)...)
		cmd.Env = testutil.GitEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(cacheSrc, "hello.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheSrc, "image.png"), []byte("\x89PNG\r\n\x1a\ncontent without nul"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "hello.go", "image.png")
	run("commit", "--quiet", "-m", "first")
	commit1 = run("rev-parse", "HEAD")

	if err := os.WriteFile(filepath.Join(cacheSrc, "hello.go"), []byte("package main\n\nfunc main() { println(\"hi\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "hello.go")
	run("commit", "--quiet", "-m", "second")
	commit2 = run("rev-parse", "HEAD")
	return commit1, commit2
}

func TestRepoBlob_doesNotRenderUnsupportedContent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s, done := newTestServer(t)
	defer done()

	dataDir := t.TempDir()
	s.Worker = &worker.Worker{DataDir: dataDir}

	repo := db.Repository{URL: "https://example.com/foo", Name: "foo"}
	s.DB.Create(&repo)
	commit, _ := seedRepoCache(t, dataDir, repo.URL)

	id := strconv.FormatUint(uint64(repo.ID), 10)
	req := localReq("GET", "/repositories/"+id+"/blob/"+commit+"/image.png")
	req.SetPathValue("id", id)
	req.SetPathValue("commit", commit)
	req.SetPathValue("path", "image.png")
	rec := httptest.NewRecorder()
	s.repoBlob(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "not UTF-8 text") {
		t.Errorf("body missing unsupported-content notice:\n%s", body)
	}
	if strings.Contains(body, "content without nul") {
		t.Errorf("body rendered unsupported content:\n%s", body)
	}
}

func TestRepoBlob_servesHistoricalCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s, done := newTestServer(t)
	defer done()

	dataDir := t.TempDir()
	s.Worker = &worker.Worker{DataDir: dataDir}

	repo := db.Repository{URL: "https://example.com/foo", Name: "foo"}
	s.DB.Create(&repo)
	c1, c2 := seedRepoCache(t, dataDir, repo.URL)

	check := func(commit, want string) {
		t.Helper()
		req := localReq("GET", "/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/blob/"+commit+"/hello.go")
		req.SetPathValue("id", strconv.FormatUint(uint64(repo.ID), 10))
		req.SetPathValue("commit", commit)
		req.SetPathValue("path", "hello.go")
		rec := httptest.NewRecorder()
		s.repoBlob(rec, req)
		if rec.Code != 200 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("body missing %q for commit %s:\n%s", want, commit, rec.Body.String())
		}
	}
	check(c1, "func main() {}")
	check(c2, "println")

	req := localReq("GET", "/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/blob/"+c2+"/hello.go")
	req.SetPathValue("id", strconv.FormatUint(uint64(repo.ID), 10))
	req.SetPathValue("commit", c2)
	req.SetPathValue("path", "hello.go")
	rec := httptest.NewRecorder()
	s.repoBlob(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `<script src="/static/code_browser.js" defer></script>`) {
		t.Errorf("body missing external code_browser.js script tag:\n%s", body)
	}
	if strings.Contains(body, "balanceSpansAtNewlines") {
		t.Errorf("body still contains inline JS (CSP would block it):\n%s", body)
	}
}

func TestRepoBlob_rejectsBadInputs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker = &worker.Worker{DataDir: t.TempDir()}
	repo := db.Repository{URL: "https://example.com/foo", Name: "foo"}
	s.DB.Create(&repo)

	id := strconv.FormatUint(uint64(repo.ID), 10)
	cases := []struct {
		commit, path string
		wantStatus   int
	}{
		{"NOTHEX", "a.go", 400},
		{"abc123", "../x", 400},
		{"abc123", "", 400},
	}
	for _, c := range cases {
		req := localReq("GET", "/repositories/"+id+"/blob/"+c.commit+"/"+c.path)
		req.SetPathValue("id", id)
		req.SetPathValue("commit", c.commit)
		req.SetPathValue("path", c.path)
		rec := httptest.NewRecorder()
		s.repoBlob(rec, req)
		if rec.Code != c.wantStatus {
			t.Errorf("commit=%q path=%q: status = %d, want %d", c.commit, c.path, rec.Code, c.wantStatus)
		}
	}
}

func TestGitShowBlob_capsAtMaxBrowserBytes(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = testutil.GitEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	big := bytes.Repeat([]byte("a"), maxBrowserBytes+1024)
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "big.txt")
	run("commit", "--quiet", "-m", "big")
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	cmd.Env = testutil.GitEnv()
	headOut, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(headOut))

	blob, err := gitShowBlob(context.Background(), dir, commit, "big.txt")
	if err != nil {
		t.Fatalf("gitShowBlob: %v", err)
	}
	if !renderableBlob(blob.Detection) {
		t.Errorf("expected renderable detection, got %+v", blob.Detection)
	}
	if !blob.Truncated {
		t.Error("expected truncated=true")
	}
	if len(blob.Content) != maxBrowserBytes {
		t.Errorf("len(content) = %d, want %d", len(blob.Content), maxBrowserBytes)
	}
}

func TestGitShowBlob_readsWithoutGitOnPath(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	commitBlob(t, dir, "fixture", []byte("content"))
	commit := headCommit(t, dir)
	t.Setenv("PATH", t.TempDir())

	blob, err := gitShowBlob(context.Background(), dir, commit, "fixture")
	if err != nil {
		t.Fatalf("gitShowBlob: %v", err)
	}
	if string(blob.Content) != "content" || blob.Truncated {
		t.Errorf("blob = (%q, truncated %v), want complete content", blob.Content, blob.Truncated)
	}
}

func TestGitShowBlob_classifiesContent(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	tests := []struct {
		name         string
		content      []byte
		wantKind     magic.Kind
		wantEncoding string
		wantRender   bool
	}{
		{name: "UTF-8", content: []byte("hello, world\n"), wantKind: magic.KindText, wantEncoding: "utf-8", wantRender: true},
		{name: "empty", content: []byte{}, wantKind: magic.KindText, wantRender: true},
		{name: "PNG without NUL", content: []byte("\x89PNG\r\n\x1a\npayload"), wantKind: magic.KindBinary},
		{name: "invalid UTF-8", content: []byte{0xff, 'x'}, wantKind: magic.KindUnknown},
		{name: "UTF-16LE", content: []byte{0xff, 0xfe, 'h', 0, 'i', 0}, wantKind: magic.KindText, wantEncoding: "utf-16le"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			commitBlob(t, dir, "fixture", tt.content)

			blob, err := gitShowBlob(context.Background(), dir, headCommit(t, dir), "fixture")
			if err != nil {
				t.Fatalf("gitShowBlob: %v", err)
			}
			if blob.Detection.Kind != tt.wantKind {
				t.Errorf("Kind = %q, want %q", blob.Detection.Kind, tt.wantKind)
			}
			if blob.Detection.Encoding != tt.wantEncoding {
				t.Errorf("Encoding = %q, want %q", blob.Detection.Encoding, tt.wantEncoding)
			}
			if got := renderableBlob(blob.Detection); got != tt.wantRender {
				t.Errorf("renderableBlob() = %v, want %v", got, tt.wantRender)
			}
		})
	}
}

func TestGitShowBlob_doesNotRenderSplitUTF8Prefix(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	content := bytes.Repeat([]byte("a"), maxBrowserBytes-1)
	content = append(content, []byte("éx")...)
	commitBlob(t, dir, "split.txt", content)

	blob, err := gitShowBlob(context.Background(), dir, headCommit(t, dir), "split.txt")
	if err != nil {
		t.Fatalf("gitShowBlob: %v", err)
	}
	if !blob.Truncated {
		t.Fatal("expected truncated=true")
	}
	if blob.Detection.Kind != magic.KindUnknown || blob.Detection.Reason != magic.ReasonNeedMore {
		t.Errorf("Detection = %+v, want unknown needing more bytes", blob.Detection)
	}
	if renderableBlob(blob.Detection) {
		t.Error("expected split UTF-8 prefix not to render")
	}
}

func commitBlob(t *testing.T, dir, name string, content []byte) {
	t.Helper()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = testutil.GitEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init", "--quiet", "-b", "main")
	runGit("config", "user.email", "test@example.com")
	runGit("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", name)
	runGit("commit", "--quiet", "-m", "fixture")
}

func headCommit(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	cmd.Env = testutil.GitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestRepoBlob_rendersMissingNoticeWhenNoCache(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker = &worker.Worker{DataDir: t.TempDir()}
	repo := db.Repository{URL: "https://example.com/never-scanned", Name: "n"}
	s.DB.Create(&repo)

	id := strconv.FormatUint(uint64(repo.ID), 10)
	req := localReq("GET", "/repositories/"+id+"/blob/abc123/a.go")
	req.SetPathValue("id", id)
	req.SetPathValue("commit", "abc123")
	req.SetPathValue("path", "a.go")
	rec := httptest.NewRecorder()
	s.repoBlob(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No local clone") {
		t.Errorf("body missing 'No local clone' notice:\n%s", body)
	}
	if strings.Contains(body, "View on forge") {
		t.Errorf("body should not contain forge link for unknown host:\n%s", body)
	}
}

func TestRepoBlob_rendersForgeLinkInMissingState(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Worker = &worker.Worker{DataDir: t.TempDir()}
	repo := db.Repository{
		URL:     "https://github.com/owner/repo",
		HTMLURL: "https://github.com/owner/repo",
		Name:    "repo",
	}
	s.DB.Create(&repo)

	id := strconv.FormatUint(uint64(repo.ID), 10)
	req := localReq("GET", "/repositories/"+id+"/blob/abc123/a.go")
	req.SetPathValue("id", id)
	req.SetPathValue("commit", "abc123")
	req.SetPathValue("path", "a.go")
	rec := httptest.NewRecorder()
	s.repoBlob(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "https://github.com/owner/repo/blob/abc123/a.go") {
		t.Errorf("body missing forge blob link:\n%s", body)
	}
	if !strings.Contains(body, "https://github.com/owner/repo/commit/abc123") {
		t.Errorf("body missing forge commit link:\n%s", body)
	}
}
