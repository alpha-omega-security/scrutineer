package worker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/testutil"
)

// testGit runs git in dir with the isolated test environment, failing the
// test on error, and returns trimmed stdout+stderr.
func testGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = testutil.GitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %s: %v", args, out, err)
	}
	return strings.TrimSpace(string(out))
}

// initTestRepo creates a git repo with one commit and returns its HEAD SHA.
func initTestRepo(t *testing.T, dir string) string {
	t.Helper()
	testGit(t, dir, "init", "-q", "-b", "main", ".")
	testGit(t, dir, "config", "commit.gpgsign", "false")
	testGit(t, dir, "commit", "-q", "--allow-empty", "-m", "initial")
	return testGit(t, dir, "rev-parse", "HEAD")
}

func TestResolveRemoteHead(t *testing.T) {
	dir := t.TempDir()
	want := initTestRepo(t, dir)

	got, err := ResolveRemoteHead(context.Background(), dir)
	if err != nil {
		t.Fatalf("ResolveRemoteHead: %v", err)
	}
	if got != want {
		t.Fatalf("HEAD = %q, want %q", got, want)
	}
}

func TestResolveRemoteHead_missingRepo(t *testing.T) {
	if _, err := ResolveRemoteHead(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing repository")
	}
}

func TestResolveRemoteHead_rejectsNonHTTPSRemote(t *testing.T) {
	if _, err := ResolveRemoteHead(context.Background(), "http://example.com/repo.git"); err == nil {
		t.Fatal("expected error for http:// URL")
	}
}

func TestSyncUpstream(t *testing.T) {
	upstream := t.TempDir()
	initTestRepo(t, upstream)

	staging := filepath.Join(t.TempDir(), "staging.git")
	testGit(t, "", "clone", "-q", "--bare", upstream, staging)

	testGit(t, upstream, "commit", "-q", "--allow-empty", "-m", "new work")
	want := testGit(t, upstream, "rev-parse", "HEAD")

	w := &Worker{DataDir: t.TempDir()}
	if err := w.SyncUpstream(context.Background(), staging, upstream); err != nil {
		t.Fatalf("SyncUpstream: %v", err)
	}
	if got := testGit(t, staging, "rev-parse", "HEAD"); got != want {
		t.Fatalf("staging HEAD = %q, want upstream HEAD %q", got, want)
	}
}

func TestSyncUpstream_reusesMirrorAcrossSyncs(t *testing.T) {
	upstream := t.TempDir()
	initTestRepo(t, upstream)

	staging := filepath.Join(t.TempDir(), "staging.git")
	testGit(t, "", "clone", "-q", "--bare", upstream, staging)

	w := &Worker{DataDir: t.TempDir()}
	for i, msg := range []string{"first upstream move", "second upstream move"} {
		testGit(t, upstream, "commit", "-q", "--allow-empty", "-m", msg)
		want := testGit(t, upstream, "rev-parse", "HEAD")
		if err := w.SyncUpstream(context.Background(), staging, upstream); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
		if got := testGit(t, staging, "rev-parse", "HEAD"); got != want {
			t.Fatalf("sync %d: staging HEAD = %q, want %q", i, got, want)
		}
	}
	mirror := filepath.Join(RepoCacheRoot(w.DataDir, staging), "upstream-sync.git")
	if _, err := os.Stat(mirror); err != nil {
		t.Fatalf("mirror should persist for reuse: %v", err)
	}
}

func TestSyncUpstream_noopWhenAlreadyInSync(t *testing.T) {
	upstream := t.TempDir()
	want := initTestRepo(t, upstream)

	staging := filepath.Join(t.TempDir(), "staging.git")
	testGit(t, "", "clone", "-q", "--bare", upstream, staging)

	w := &Worker{DataDir: t.TempDir()}
	if err := w.SyncUpstream(context.Background(), staging, upstream); err != nil {
		t.Fatalf("SyncUpstream: %v", err)
	}
	if got := testGit(t, staging, "rev-parse", "HEAD"); got != want {
		t.Fatalf("staging HEAD = %q, want %q", got, want)
	}
}

func TestSyncUpstream_overwritesRewrittenHistory(t *testing.T) {
	upstream := t.TempDir()
	initTestRepo(t, upstream)

	staging := filepath.Join(t.TempDir(), "staging.git")
	testGit(t, "", "clone", "-q", "--bare", upstream, staging)

	// Rewrite upstream history so a plain push would be non-fast-forward.
	testGit(t, upstream, "commit", "-q", "--amend", "--allow-empty", "-m", "rewritten")
	want := testGit(t, upstream, "rev-parse", "HEAD")

	w := &Worker{DataDir: t.TempDir()}
	if err := w.SyncUpstream(context.Background(), staging, upstream); err != nil {
		t.Fatalf("SyncUpstream: %v", err)
	}
	if got := testGit(t, staging, "rev-parse", "HEAD"); got != want {
		t.Fatalf("staging HEAD = %q, want rewritten upstream HEAD %q", got, want)
	}
}

func TestSyncUpstream_missingUpstream(t *testing.T) {
	staging := t.TempDir()
	initTestRepo(t, staging)

	w := &Worker{DataDir: t.TempDir()}
	if err := w.SyncUpstream(context.Background(), staging, filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing upstream")
	}
}
