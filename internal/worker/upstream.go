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
	return resolveRemoteHead(ctx, branchPickerRetry(gitRetry{}), cloneURL)
}

func resolveRemoteHead(ctx context.Context, retry gitRetry, cloneURL string) (string, error) {
	if err := validateScheduleURL(cloneURL); err != nil {
		return "", err
	}
	out, err := retry.do(ctx, gitCommand{
		label: "ls-remote",
		env:   []string{"GIT_TERMINAL_PROMPT=0"},
		args:  []string{"ls-remote", "--", cloneURL, "HEAD"},
	}, nil)
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

// SyncUpstream force-syncs a staging repository (a pushed clone with no
// forge fork relationship) from its upstream: fetch the upstream's HEAD into
// a persistent bare mirror of the staging repo, then force-push it onto the
// staging repo's default branch. The push is forced because the staging copy
// mirrors the upstream: a rebase there must win. No-op when both HEADs
// already match, so the scheduler doesn't pay a fetch per tick. The mirror
// lives under the per-URL clone cache and is reused across syncs, so a moved
// upstream costs a delta fetch rather than a full re-clone of large repos;
// the per-URL lock serialises it against the scan cache's clone/fetch on the
// same repository. Pushing uses the ambient git credentials (credential
// helper, gh auth); only the terminal prompt is disabled so a missing
// credential fails fast.
func (w *Worker) SyncUpstream(ctx context.Context, repoURL, upstreamURL string) error {
	return w.syncUpstream(ctx, gitRetry{}, repoURL, upstreamURL)
}

func (w *Worker) syncUpstream(ctx context.Context, retry gitRetry, repoURL, upstreamURL string) error {
	if err := validateScheduleURL(repoURL); err != nil {
		return fmt.Errorf("repo: %w", err)
	}
	if err := validateScheduleURL(upstreamURL); err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	policy := retry.resolved()
	repoHead, err := resolveRemoteHead(ctx, branchPickerRetry(policy), repoURL)
	if err != nil {
		return fmt.Errorf("resolve repo HEAD: %w", err)
	}
	upstreamHead, err := resolveRemoteHead(ctx, branchPickerRetry(policy), upstreamURL)
	if err != nil {
		return fmt.Errorf("resolve upstream HEAD: %w", err)
	}
	if repoHead == upstreamHead {
		return nil
	}

	mu := w.cacheMutex(repoURL)
	mu.Lock()
	defer mu.Unlock()

	mirror := filepath.Join(RepoCacheRoot(w.DataDir, repoURL), "upstream-sync.git")
	env := []string{"GIT_TERMINAL_PROMPT=0"}
	if _, err := os.Stat(mirror); err != nil {
		if err := os.MkdirAll(filepath.Dir(mirror), dirPerm); err != nil {
			return err
		}
		if out, err := policy.do(ctx, gitCommand{
			label: "clone",
			env:   env,
			args:  []string{"clone", "--quiet", "--bare", "--", repoURL, mirror},
			reset: cloneDestReset(mirror),
		}, nil); err != nil {
			return fmt.Errorf("clone staging repo: %s: %w", strings.TrimSpace(out), err)
		}
	}
	branch, err := policy.run(ctx, mirror, env, "symbolic-ref", "--short", "HEAD")
	if err != nil {
		return fmt.Errorf("resolve default branch: %s: %w", strings.TrimSpace(branch), err)
	}
	branch = strings.TrimSpace(branch)
	if out, err := policy.do(ctx, gitCommand{
		label: "fetch",
		dir:   mirror,
		env:   env,
		args:  []string{"fetch", "--quiet", "--", upstreamURL, "HEAD"},
	}, nil); err != nil {
		return fmt.Errorf("fetch upstream: %s: %w", strings.TrimSpace(out), err)
	}
	desiredHead, err := policy.run(ctx, mirror, env, "rev-parse", "FETCH_HEAD")
	if err != nil {
		return fmt.Errorf("resolve fetched HEAD: %s: %w", strings.TrimSpace(desiredHead), err)
	}
	desiredHead = strings.TrimSpace(desiredHead)
	if out, err := policy.do(ctx, gitCommand{
		label: "push",
		dir:   mirror,
		env:   env,
		args:  []string{"push", "--quiet", "--force", "origin", "FETCH_HEAD:refs/heads/" + branch},
		confirm: func(ctx context.Context) (bool, error) {
			return remoteRefMatches(ctx, policy.run, env, repoURL, "refs/heads/"+branch, desiredHead)
		},
	}, nil); err != nil {
		return fmt.Errorf("push to staging repo: %s: %w", strings.TrimSpace(out), err)
	}
	return nil
}

// remoteRefMatches checks whether an ambiguous push already installed the
// desired object. It intentionally makes one direct attempt: failure to
// confirm falls back to the push's own bounded retry budget.
func remoteRefMatches(ctx context.Context, run gitRunner, env []string, repoURL, ref, wantSHA string) (bool, error) {
	out, err := run(ctx, "", env, "ls-remote", "--refs", "--", repoURL, ref)
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(out, "\n") {
		sha, gotRef, ok := strings.Cut(line, "\t")
		if ok && strings.TrimSpace(gotRef) == ref {
			return strings.TrimSpace(sha) == wantSHA, nil
		}
	}
	return false, nil
}
