package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

const dirPerm = 0o755

// ensureClone returns the path to an up-to-date clone of repo.URL under
// the given work root. fullClone selects between --depth 1 (false, the
// default) and full history (true). Clones on first call; fetches +
// resets on subsequent ones. Each scan supplies its own work root
// (scan-{id}) so concurrent scans do not share src or report.json,
// removing a class of races where skill A's output gets clobbered by
// skill B removing report.json before A finishes reading it.
func ensureClone(ctx context.Context, repo db.Repository, work string, fullClone bool, emit func(Event)) (string, error) {
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(work, dirPerm); err != nil {
		return "", err
	}
	if err := cloneOrFetch(ctx, repo.URL, src, fullClone, emit); err != nil {
		return "", fmt.Errorf("clone: %w", err)
	}
	return src, nil
}

// validateGitURL rejects anything that isn't https:// to prevent SSRF,
// local file reads, and git option injection (T2, T4).
func validateGitURL(u string) error {
	if !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("only https:// URLs are allowed, got %q", u)
	}
	return nil
}

func cloneOrFetch(ctx context.Context, url, dst string, fullClone bool, emit func(Event)) error {
	if err := validateGitURL(url); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
		fetchArgs := []string{"-C", dst, "fetch", "--quiet", "origin"}
		fetchMsg := "$ git fetch && reset"
		if fullClone {
			out, _ := git(ctx, "", "-C", dst, "rev-parse", "--is-shallow-repository")
			if strings.TrimSpace(out) == "true" {
				fetchArgs = []string{"-C", dst, "fetch", "--unshallow", "--quiet", "origin"}
				fetchMsg = "$ git fetch --unshallow && reset"
			}
		}
		emit(Event{Kind: KindText, Text: fetchMsg})
		if out, err := git(ctx, "", fetchArgs...); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		if out, err := git(ctx, "", "-C", dst, "reset", "--quiet", "--hard", "origin/HEAD"); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		return nil
	}
	// -- stops git option parsing so a URL can't be interpreted as a flag.
	// GIT_PROTOCOL_FROM_USER=0 blocks ext:: and other user-facing protocol handlers.
	args := []string{"clone", "--quiet"}
	msg := "$ git clone " + url
	if !fullClone {
		args = []string{"clone", "--depth", "1", "--quiet"}
		msg = "$ git clone --depth 1 " + url
	}
	args = append(args, "--", url, dst)
	emit(Event{Kind: KindText, Text: msg})
	out, err := gitWithEnv(ctx, "", []string{"GIT_PROTOCOL_FROM_USER=0"}, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	return nil
}

func gitHead(dir string) string {
	out, _ := git(context.Background(), dir, "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	return gitWithEnv(ctx, dir, nil, args...)
}

func gitWithEnv(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
