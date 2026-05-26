package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

// RepoCacheRoot returns the persistent per-URL clone directory under
// dataDir. The cache survives scan cleanup so subsequent scans only
// fetch the delta; EnsureCommit deepens it on demand when the code
// browser asks for a commit that the shallow clone doesn't have.
func RepoCacheRoot(dataDir, url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(dataDir, "repo-cache", hex.EncodeToString(sum[:]))
}

// prepareRepoSrc updates the per-URL cache under a lock, copies the
// tree into workRoot/src, and returns the cache HEAD commit. Shallow
// by default; the code browser unshallows on demand when a historical
// commit is requested.
func (w *Worker) prepareRepoSrc(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error) {
	mu := w.cacheMutex(url)
	mu.Lock()
	defer mu.Unlock()

	cacheRoot := RepoCacheRoot(w.DataDir, url)
	if err := os.MkdirAll(cacheRoot, dirPerm); err != nil {
		return "", err
	}
	cacheSrc, err := ensureClone(ctx, db.Repository{URL: url}, cacheRoot, false, ref, emit)
	if err != nil {
		return "", err
	}
	commit := gitHead(cacheSrc)
	dst := filepath.Join(workRoot, "src")
	if err := os.RemoveAll(dst); err != nil {
		return "", err
	}
	if err := copyTree(cacheSrc, dst); err != nil {
		return "", fmt.Errorf("copy repo cache: %w", err)
	}
	return commit, nil
}

// EnsureCommit deepens the per-URL cache so commit becomes reachable.
// No-op when the commit is already present (the common case after the
// scan that recorded it) or the cache is missing. Acquires the per-URL
// lock so a concurrent scan does not race the fetch.
func (w *Worker) EnsureCommit(ctx context.Context, url, commit string) error {
	mu := w.cacheMutex(url)
	mu.Lock()
	defer mu.Unlock()

	cacheSrc := filepath.Join(RepoCacheRoot(w.DataDir, url), "src")
	if _, err := os.Stat(filepath.Join(cacheSrc, ".git")); err != nil {
		return nil
	}
	if commitReachable(ctx, cacheSrc, commit) {
		return nil
	}
	out, _ := git(ctx, "", "-C", cacheSrc, "rev-parse", "--is-shallow-repository")
	if strings.TrimSpace(out) != "true" {
		return nil
	}
	if out, err := git(ctx, "", "-C", cacheSrc, "fetch", "--unshallow", "--quiet", "origin"); err != nil {
		return fmt.Errorf("unshallow %s: %s: %w", url, strings.TrimSpace(out), err)
	}
	return nil
}

func commitReachable(ctx context.Context, dir, commit string) bool {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "cat-file", "-e", commit+"^{commit}")
	return cmd.Run() == nil
}
