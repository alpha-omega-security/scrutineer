package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validateScheduleURL is the scheduler's counterpart to validateGitURL:
// scheduled checks also run against local repositories (file:// or a bare
// path), which the clone path never sees.
func validateScheduleURL(u string) error {
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "file://") || strings.HasPrefix(u, "/") {
		return nil
	}
	return fmt.Errorf("only https://, file:// or absolute-path URLs are allowed, got %q", u)
}

// ResolveRemoteHead returns the commit SHA the repository's HEAD points at,
// without cloning. Ambient git credentials apply, like the scan clone path
// (and unlike ListRemoteBranches), so a private repo that scans on demand is
// also schedulable; only the terminal prompt is disabled so a missing
// credential fails fast instead of hanging the scheduler.
func ResolveRemoteHead(ctx context.Context, cloneURL string) (string, error) {
	if err := validateScheduleURL(cloneURL); err != nil {
		return "", err
	}
	out, err := gitWithEnv(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"},
		"ls-remote", "--", cloneURL, "HEAD")
	if err != nil {
		return "", fmt.Errorf("%s: %w", strings.TrimSpace(out), err)
	}
	for line := range strings.SplitSeq(out, "\n") {
		sha, ref, ok := strings.Cut(line, "\t")
		if ok && strings.TrimSpace(ref) == "HEAD" {
			return strings.TrimSpace(sha), nil
		}
	}
	return "", fmt.Errorf("no HEAD in ls-remote output for %q", cloneURL)
}

// SyncUpstream fast-forwards a staging repository (a pushed clone with no
// forge fork relationship) from its upstream: fetch the upstream's HEAD into
// a temporary bare clone of the staging repo, then force-push it onto the
// staging repo's default branch. The push is forced because the staging copy
// mirrors the upstream: a rebase there must win. No-op when both HEADs
// already match, so the scheduler doesn't pay a clone per tick. Pushing uses
// the ambient git credentials (credential helper, gh auth); only the
// terminal prompt is disabled so a missing credential fails fast.
func SyncUpstream(ctx context.Context, repoURL, upstreamURL string) error {
	if err := validateScheduleURL(repoURL); err != nil {
		return fmt.Errorf("repo: %w", err)
	}
	if err := validateScheduleURL(upstreamURL); err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	repoHead, err := ResolveRemoteHead(ctx, repoURL)
	if err != nil {
		return fmt.Errorf("resolve repo HEAD: %w", err)
	}
	upstreamHead, err := ResolveRemoteHead(ctx, upstreamURL)
	if err != nil {
		return fmt.Errorf("resolve upstream HEAD: %w", err)
	}
	if repoHead == upstreamHead {
		return nil
	}

	tmp, err := os.MkdirTemp("", "scrutineer-upstream-sync-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	dst := filepath.Join(tmp, "repo.git")

	env := []string{"GIT_TERMINAL_PROMPT=0"}
	if out, err := gitWithEnv(ctx, "", env, "clone", "--quiet", "--bare", "--", repoURL, dst); err != nil {
		return fmt.Errorf("clone staging repo: %s: %w", strings.TrimSpace(out), err)
	}
	branch, err := gitWithEnv(ctx, dst, env, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return fmt.Errorf("resolve default branch: %s: %w", strings.TrimSpace(branch), err)
	}
	branch = strings.TrimSpace(branch)
	if out, err := gitWithEnv(ctx, dst, env, "fetch", "--quiet", "--", upstreamURL, "HEAD"); err != nil {
		return fmt.Errorf("fetch upstream: %s: %w", strings.TrimSpace(out), err)
	}
	if out, err := gitWithEnv(ctx, dst, env, "push", "--quiet", "--force", "origin", "FETCH_HEAD:refs/heads/"+branch); err != nil {
		return fmt.Errorf("push to staging repo: %s: %w", strings.TrimSpace(out), err)
	}
	return nil
}
