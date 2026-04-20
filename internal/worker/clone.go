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

// ensureClone returns the path to an up-to-date shallow clone of repo.URL
// under dataDir. Clones on first call; fetches + resets on subsequent ones.
// The workspace layout is dataDir/repo-{id}/src/.
func ensureClone(ctx context.Context, repo db.Repository, dataDir string, emit func(Event)) (string, error) {
	work := filepath.Join(dataDir, fmt.Sprintf("repo-%d", repo.ID))
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(work, dirPerm); err != nil {
		return "", err
	}
	if err := cloneOrFetch(ctx, repo.URL, src, emit); err != nil {
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

func cloneOrFetch(ctx context.Context, url, dst string, emit func(Event)) error {
	if err := validateGitURL(url); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
		emit(Event{Kind: KindText, Text: "$ git fetch && reset"})
		if out, err := git(ctx, "", "-C", dst, "fetch", "--quiet", "origin"); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		if out, err := git(ctx, "", "-C", dst, "reset", "--quiet", "--hard", "origin/HEAD"); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
		return nil
	}
	emit(Event{Kind: KindText, Text: "$ git clone --depth 1 " + url})
	// -- stops git option parsing so a URL can't be interpreted as a flag.
	// GIT_PROTOCOL_FROM_USER=0 blocks ext:: and other user-facing protocol handlers.
	out, err := gitWithEnv(ctx, "", []string{"GIT_PROTOCOL_FROM_USER=0"}, "clone", "--depth", "1", "--quiet", "--", url, dst)
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

