package worker

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// seedCacheFile writes a file of n bytes into the clone cache for url under
// dataDir, so RepoDiskUsage reports a known non-zero size.
func seedCacheFile(t *testing.T, dataDir, url string, n int) {
	t.Helper()
	dir := RepoCacheRoot(dataDir, url)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blob"), make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRepoDiskUsage_storesComputedSize(t *testing.T) {
	dataDir := t.TempDir()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/a", Name: "a"}
	gdb.Create(&repo)
	seedCacheFile(t, dataDir, repo.URL, 2048)

	w := &Worker{DB: gdb, DataDir: dataDir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.refreshRepoDiskUsage(repo.ID)

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.DiskBytes != 2048 {
		t.Errorf("DiskBytes = %d, want 2048", got.DiskBytes)
	}
}

func TestBackfillRepoDiskUsage_fillsZeroRowsSkipsLocal(t *testing.T) {
	dataDir := t.TempDir()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	remote := db.Repository{URL: "https://example.com/remote", Name: "remote"}
	local := db.Repository{URL: "file:///tmp/local", Name: "local"}
	uncached := db.Repository{URL: "https://example.com/uncached", Name: "uncached"}
	gdb.Create(&remote)
	gdb.Create(&local)
	gdb.Create(&uncached)
	seedCacheFile(t, dataDir, remote.URL, 4096)
	// A local repo with a stray cache dir must still be skipped on IsLocal.
	seedCacheFile(t, dataDir, local.URL, 9999)

	BackfillRepoDiskUsage(gdb, dataDir)

	sizeOf := func(id uint) int64 {
		var r db.Repository
		gdb.First(&r, id)
		return r.DiskBytes
	}
	if got := sizeOf(remote.ID); got != 4096 {
		t.Errorf("remote DiskBytes = %d, want 4096", got)
	}
	if got := sizeOf(local.ID); got != 0 {
		t.Errorf("local DiskBytes = %d, want 0 (local repos skipped)", got)
	}
	if got := sizeOf(uncached.ID); got != 0 {
		t.Errorf("uncached DiskBytes = %d, want 0 (no cache dir)", got)
	}
}

func TestBackfillRepoDiskUsage_leavesNonZeroAlone(t *testing.T) {
	dataDir := t.TempDir()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/keep", Name: "keep", DiskBytes: 123}
	gdb.Create(&repo)
	// Cache on disk says 4096, but the row already carries a value; the
	// backfill only touches rows at 0, so the stored value must be kept.
	seedCacheFile(t, dataDir, repo.URL, 4096)

	BackfillRepoDiskUsage(gdb, dataDir)

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.DiskBytes != 123 {
		t.Errorf("DiskBytes = %d, want 123 (non-zero rows are not re-walked)", got.DiskBytes)
	}
}

func TestRepoCacheRoot(t *testing.T) {
	a := RepoCacheRoot("/data", "https://github.com/a/b")
	b := RepoCacheRoot("/data", "https://github.com/a/b")
	c := RepoCacheRoot("/data", "https://github.com/c/d")
	if a != b {
		t.Errorf("same URL should produce same path: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different URLs should produce different paths, both %q", a)
	}
	if !strings.HasPrefix(a, filepath.Join("/data", "repo-cache")+string(filepath.Separator)) {
		t.Errorf("path %q not under /data/repo-cache/", a)
	}
}

func TestEnsureCommit_noCacheIsNoOp(t *testing.T) {
	w := &Worker{DataDir: t.TempDir()}
	if err := w.EnsureCommit(context.Background(), "https://example.com/x", "deadbeef"); err != nil {
		t.Errorf("EnsureCommit with no cache: %v", err)
	}
}

func TestEnsureCommit_reachableCommitIsNoOp(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dataDir := t.TempDir()
	url := "https://example.com/repo"
	cacheSrc := filepath.Join(RepoCacheRoot(dataDir, url), "src")
	if err := os.MkdirAll(cacheSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", cacheSrc}, args...)...)
		cmd.Env = testGitEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "--quiet", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(cacheSrc, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "f")
	run("commit", "--quiet", "-m", "first")
	head := run("rev-parse", "HEAD")

	w := &Worker{DataDir: dataDir}
	if err := w.EnsureCommit(context.Background(), url, head); err != nil {
		t.Errorf("EnsureCommit with reachable commit: %v", err)
	}
}

func TestEnsureCommit_unreachableNonShallowIsNoOp(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dataDir := t.TempDir()
	url := "https://example.com/repo"
	cacheSrc := filepath.Join(RepoCacheRoot(dataDir, url), "src")
	if err := os.MkdirAll(cacheSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", cacheSrc, "init", "--quiet", "-b", "main")
	cmd.Env = testGitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	w := &Worker{DataDir: dataDir}
	if err := w.EnsureCommit(context.Background(), url, "0000000000000000000000000000000000000000"); err != nil {
		t.Errorf("EnsureCommit on non-shallow without commit should be no-op: %v", err)
	}
}
