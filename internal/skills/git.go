package skills

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const dirPerm = 0o755

// CloneOrPull prepares a local copy of a git repo at dst. On first call it
// clones; on subsequent calls it fetches and resets to origin/HEAD so skill
// updates propagate without needing to wipe the cache. https-only, same
// rationale as internal/worker/clone.go (T2/T4).
func CloneOrPull(ctx context.Context, url, dst string) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("skills repo must be https://, got %q", url)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
		if out, err := git(ctx, dst, "fetch", "--quiet", "origin"); err != nil {
			return fmt.Errorf("fetch %s: %s: %w", url, out, err)
		}
		if out, err := git(ctx, dst, "reset", "--quiet", "--hard", "origin/HEAD"); err != nil {
			return fmt.Errorf("reset %s: %s: %w", url, out, err)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--quiet", "--", url, dst)
	cmd.Env = append(os.Environ(), "GIT_PROTOCOL_FROM_USER=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("clone %s: %s: %w", url, string(out), err)
	}
	return nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
