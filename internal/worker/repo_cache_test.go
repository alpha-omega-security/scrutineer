package worker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

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
		out, err := exec.Command("git", append([]string{"-C", cacheSrc}, args...)...).CombinedOutput()
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
	out, err := exec.Command("git", "-C", cacheSrc, "init", "--quiet", "-b", "main").CombinedOutput()
	if err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	w := &Worker{DataDir: dataDir}
	if err := w.EnsureCommit(context.Background(), url, "0000000000000000000000000000000000000000"); err != nil {
		t.Errorf("EnsureCommit on non-shallow without commit should be no-op: %v", err)
	}
}
