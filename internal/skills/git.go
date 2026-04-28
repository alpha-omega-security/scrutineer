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
// updates propagate without needing to wipe the cache. fullClone toggles
// between --depth 1 and full history, and unshallows an existing shallow
// clone when flipped to true. https-only, same rationale as
// internal/worker/clone.go (T2/T4).
func CloneOrPull(ctx context.Context, url, dst string, fullClone bool) error {
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("skills repo must be https://, got %q", url)
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
		fetchArgs := []string{"fetch", "--quiet", "origin"}
		if fullClone {
			out, _ := git(ctx, dst, "rev-parse", "--is-shallow-repository")
			if strings.TrimSpace(out) == "true" {
				fetchArgs = []string{"fetch", "--unshallow", "--quiet", "origin"}
			}
		}
		if out, err := git(ctx, dst, fetchArgs...); err != nil {
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
	args := []string{"clone", "--quiet"}
	if !fullClone {
		args = []string{"clone", "--depth", "1", "--quiet"}
	}
	args = append(args, "--", url, dst)
	cmd := exec.CommandContext(ctx, "git", args...)
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
