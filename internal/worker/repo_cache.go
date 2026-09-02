package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/clone"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func repoCache(dataDir string) *clone.Cache {
	// One attempt via gitWithEnv, matching the pre-delegation git() call.
	// The default clone.Retry policy is 3 attempts with backoff, which would
	// hold w.cacheMutex(url) inside the code-browser HTTP handler for the
	// whole retry budget while a scan on the same repo waits.
	return &clone.Cache{
		Root:  filepath.Join(dataDir, "repo-cache"),
		Retry: gitRetry{attempts: 1}.toCloneWithNotify(nil),
	}
}

// RepoCacheRoot returns the persistent per-URL clone directory under
// dataDir. The cache survives scan cleanup so subsequent scans only
// fetch the delta; EnsureCommit deepens it on demand when the code
// browser asks for a commit that the shallow clone doesn't have.
func RepoCacheRoot(dataDir, url string) string {
	return repoCache(dataDir).Dir(url)
}

// RepoDiskUsage returns the on-disk size in bytes of the persistent
// clone cache for repo. Local repositories keep no managed copy (their
// source stays at LocalPath), and a repo that has never been scanned has
// no cache directory yet — both cases report 0.
func RepoDiskUsage(dataDir string, repo db.Repository) int64 {
	if repo.IsLocal() {
		return 0
	}
	return repoCache(dataDir).DiskBytes(repo.URL)
}

// refreshRepoDiskUsage recomputes the clone-cache size for one repository
// and stores it on the row, so the repo list can read the badge from a
// column instead of walking the filesystem per row (#126). Best-effort:
// called after a scan finishes, when the cache has just changed; a load or
// walk failure is logged and the stored value is left as-is.
func (w *Worker) refreshRepoDiskUsage(repoID uint) {
	var repo db.Repository
	if err := w.DB.First(&repo, repoID).Error; err != nil {
		w.Log.Warn("disk usage refresh: load repo", "repo", repoID, "err", err)
		return
	}
	usage := RepoDiskUsage(w.DataDir, repo)
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", repoID).
		Update("disk_bytes", usage).Error; err != nil {
		w.Log.Warn("disk usage refresh: store", "repo", repoID, "err", err)
	}
}

// BackfillRepoDiskUsage fills Repository.DiskBytes for remote repos that
// have no cached value yet, so the disk-usage badge shows immediately on
// upgrade instead of waiting for each repo's next scan. Runs once at
// startup. Only repos with disk_bytes = 0 are walked, so a second boot
// re-walks just the genuinely-empty ones (a single failed stat each);
// local repos are skipped entirely.
func BackfillRepoDiskUsage(gdb *gorm.DB, dataDir string) {
	var repos []db.Repository
	gdb.Where("disk_bytes = 0").Find(&repos)
	for _, repo := range repos {
		if repo.IsLocal() {
			continue
		}
		usage := RepoDiskUsage(dataDir, repo)
		if usage == 0 {
			continue
		}
		gdb.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("disk_bytes", usage)
	}
}

// PrepareSrc populates workRoot/src from the shared per-URL clone cache and
// returns the cache HEAD commit. It is the exported entry point for callers
// outside the scan pipeline (the chat runner), and honours the PrepareRepoSrc
// test override so they stay hermetic too.
func (w *Worker) PrepareSrc(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error) {
	if w.PrepareRepoSrc != nil {
		return w.PrepareRepoSrc(ctx, url, ref, workRoot, emit)
	}
	return w.prepareRepoSrc(ctx, url, ref, workRoot, emit)
}

// prepareRepoSrc updates the per-URL cache under a lock, copies the
// tree into workRoot/src, and returns the cache HEAD commit. Shallow
// by default; the code browser unshallows on demand when a historical
// commit is requested.
func (w *Worker) prepareRepoSrc(ctx context.Context, url, ref, workRoot string, emit func(Event)) (string, error) {
	return w.prepareRepoSrcWithOptions(ctx, url, ref, workRoot, false, emit)
}

func (w *Worker) prepareRepoSrcWithOptions(
	ctx context.Context,
	url, ref, workRoot string,
	recurseSubmodules bool,
	emit func(Event),
) (string, error) {
	mu := w.cacheMutex(url)
	mu.Lock()
	defer mu.Unlock()

	cacheRoot := RepoCacheRoot(w.DataDir, url)
	if recurseSubmodules {
		cacheRoot = filepath.Join(cacheRoot, "with-submodules")
	}
	if err := os.MkdirAll(cacheRoot, dirPerm); err != nil {
		return "", err
	}
	cacheSrc, err := ensureCloneWithOptions(
		ctx, db.Repository{URL: url}, cacheRoot, false, ref, recurseSubmodules, emit,
	)
	if err != nil {
		return "", err
	}
	commit := gitHead(cacheSrc)
	dst := filepath.Join(workRoot, "src")
	if err := os.RemoveAll(dst); err != nil {
		return "", err
	}
	if err := CopyTree(cacheSrc, dst); err != nil {
		return "", fmt.Errorf("copy repo cache: %w", err)
	}
	return commit, nil
}

func (w *Worker) prepareSkillRepoSrc(
	ctx context.Context,
	url, ref, workRoot string,
	recurseSubmodules bool,
	emit func(Event),
) (string, error) {
	if w.PrepareRepoSrcWithOptions != nil {
		return w.PrepareRepoSrcWithOptions(ctx, url, ref, workRoot, recurseSubmodules, emit)
	}
	if w.PrepareRepoSrc != nil {
		return w.PrepareRepoSrc(ctx, url, ref, workRoot, emit)
	}
	return w.prepareRepoSrcWithOptions(ctx, url, ref, workRoot, recurseSubmodules, emit)
}

// EnsureCommit deepens the per-URL cache so commit becomes reachable.
// No-op when the commit is already present (the common case after the
// scan that recorded it) or the cache is missing. Acquires the per-URL
// lock so a concurrent scan does not race the fetch.
func (w *Worker) EnsureCommit(ctx context.Context, url, commit string) error {
	mu := w.cacheMutex(url)
	mu.Lock()
	defer mu.Unlock()
	return repoCache(w.DataDir).EnsureCommit(ctx, url, strings.ToLower(commit))
}

func commitReachable(ctx context.Context, dir, commit string) bool {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "cat-file", "-e", commit+"^{commit}")
	return cmd.Run() == nil
}
