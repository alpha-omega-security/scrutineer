package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"scrutineer/internal/db"
)

// RepoCacheRoot returns the persistent per-URL clone directory under
// dataDir. The cache survives scan cleanup so subsequent scans only
// fetch the delta, and full history lets the code browser resolve
// historical commits via `git show <commit>:<path>`.
func RepoCacheRoot(dataDir, url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(dataDir, "repo-cache", hex.EncodeToString(sum[:]))
}

// prepareRepoSrc updates the per-URL cache under a lock, copies the
// tree into workRoot/src, and returns the cache HEAD commit. Full clone
// so `git show <commit>:<path>` keeps working for past HEADs.
func (w *Worker) prepareRepoSrc(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error) {
	mu := w.cacheMutex(url)
	mu.Lock()
	defer mu.Unlock()

	cacheRoot := RepoCacheRoot(w.DataDir, url)
	if err := os.MkdirAll(cacheRoot, dirPerm); err != nil {
		return "", err
	}
	cacheSrc, err := ensureClone(ctx, db.Repository{URL: url}, cacheRoot, true, ref, emit)
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
