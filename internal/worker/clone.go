package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/git-pkgs/clone"

	"scrutineer/internal/db"
)

const dirPerm = 0o755

// The add-repo branch picker's share of the remote-git retry policy. It is
// smaller than a scan's because it sits in front of a person: worst case one
// extra ls-remote and a fifth of a second, well inside the caller's request
// deadline.
const (
	branchPickerAttempts = 2
	branchPickerDelay    = 200 * time.Millisecond
)

// gitWaitDelay bounds how long a git invocation may sit in Wait after the
// process has exited or been cancelled while a transport grandchild still
// holds its output pipe. A package var so a test can shrink it; large enough
// in production never to clip a healthy command's final flush.
var gitWaitDelay = clone.DefaultWaitDelay

// RepoUnreachableError is returned when git clone/fetch fails because the
// remote is unreachable (deleted, private, wrong URL, network error).
type RepoUnreachableError = clone.UnreachableError

// prepareLocalSrc populates workRoot/src by copying the user's local
// directory. Mirrors prepareDependentSrc's "copy into per-scan src"
// pattern so the container mount can write into /work without touching the
// user's source tree. Validates that the path exists and is a directory
// before touching anything.
func prepareLocalSrc(localPath, workRoot string, emit func(Event)) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", localPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", localPath)
	}
	// filepath.Walk lstats the root, so a symlink-to-dir would be recreated
	// as a single dangling link inside ./src instead of its contents.
	resolved, err := filepath.EvalSymlinks(localPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", localPath, err)
	}
	dst := filepath.Join(workRoot, "src")
	if err := os.MkdirAll(workRoot, dirPerm); err != nil {
		return err
	}
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	emit(Event{Kind: KindText, Text: "$ cp -r " + localPath + " ./src"})
	return CopyTree(resolved, dst)
}

// ensureClone returns the path to an up-to-date clone of repo.URL under
// the given work root. fullClone selects between --depth 1 (false, the
// default) and full history (true). Clones on first call; fetches +
// resets on subsequent ones. Each scan supplies its own work root
// (scan-{id}) so concurrent scans do not share src or report.json,
// removing a class of races where skill A's output gets clobbered by
// skill B removing report.json before A finishes reading it.
func ensureClone(ctx context.Context, repo db.Repository, work string, fullClone bool, ref string, emit func(Event)) (string, error) {
	return ensureCloneWithOptions(ctx, repo, work, fullClone, ref, false, emit)
}

func ensureCloneWithOptions(
	ctx context.Context,
	repo db.Repository,
	work string,
	fullClone bool,
	ref string,
	recurseSubmodules bool,
	emit func(Event),
) (string, error) {
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(work, dirPerm); err != nil {
		return "", err
	}
	if err := cloneOrFetch(
		ctx, gitRetry{}, repo.URL, src, fullClone, ref, recurseSubmodules, emit,
	); err != nil {
		// A cancelled or timed-out scan is not evidence about the repository:
		// flagging it unreachable would record a spurious clone_error and
		// hand the caller a fake "repository unreachable" report. Propagate
		// the cancellation instead so the worker treats it as one.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", err
		}
		return "", &RepoUnreachableError{URL: repo.URL, Err: err}
	}
	return src, nil
}

// validateGitURL rejects anything that isn't https:// to prevent SSRF,
// local file reads, and git option injection (T2, T4).
func validateGitURL(u string) error { return clone.ValidateURL(u) }

// ValidateGitRef restricts refs to a conservative branch/tag-name charset
// before they flow into the fetchRef path. Exported so the web layer can
// reject bad input at the API boundary rather than letting a scan get
// enqueued and then fail at clone time.
func ValidateGitRef(ref string) error { return clone.ValidateRef(ref) }

func cloneOrFetch(
	ctx context.Context,
	retry gitRetry,
	url, dst string,
	fullClone bool,
	ref string,
	recurseSubmodules bool,
	emit func(Event),
) error {
	// Validate before emitting so a bad URL or ref does not log a
	// "$ git clone" line for a command that will never run.
	if err := validateGitURL(url); err != nil {
		return err
	}
	if err := clone.ValidateRef(ref); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
		emit(Event{Kind: KindText, Text: "$ git fetch origin " + fetchTarget(ref) + " && reset"})
	} else {
		msg := "$ git clone " + url
		if !fullClone {
			msg += " (shallow)"
		}
		emit(Event{Kind: KindText, Text: msg})
	}
	if recurseSubmodules {
		emit(Event{Kind: KindText, Text: "$ git submodule update --init --recursive --depth 1 (best effort)"})
	}
	r := retry.resolved().toClone()
	r.Notify = func(n clone.Notice) {
		emit(Event{Kind: KindText, Text: fmt.Sprintf(
			"git %s failed with a transient error (attempt %d/%d), retrying in %s",
			n.Label, n.Attempt, n.Attempts, n.Delay.Round(time.Millisecond))})
	}
	options := clone.EnsureOptions{Full: fullClone, RecurseSubmodules: recurseSubmodules}
	if err := clone.EnsureWithOptions(ctx, r, url, dst, ref, options); err != nil {
		// Unwrap so ensureClone's own UnreachableError wrap does not
		// double-prefix; the scan log records the git output verbatim.
		var ue *clone.UnreachableError
		if errors.As(err, &ue) {
			return ue.Err
		}
		return err
	}
	return nil
}

func fetchTarget(ref string) string {
	if ref == "" {
		return "HEAD"
	}
	return ref
}

// ListRemoteBranches returns the branch names a remote advertises, for the
// add-repo form's branch picker. https-only (validated like clone) and
// best-effort: callers treat any error as "no suggestions" and fall back to
// free-text entry. GIT_TERMINAL_PROMPT=0 and an empty credential helper make
// a private repo fail fast instead of blocking on a credential prompt.
//
// A transient failure is retried, but on a deliberately tighter budget than
// a scan's: this runs inside a short request deadline, and the failure a
// user actually hits here is a mistyped host, which resolves to a transient
// marker. One extra attempt after ~200ms absorbs a genuine blip while
// keeping a typo's feedback prompt. An auth or not-found answer stays
// permanent and is never retried at all.
func ListRemoteBranches(ctx context.Context, cloneURL string) ([]string, error) {
	return clone.RemoteBranches(ctx, branchPickerRetry(gitRetry{}).resolved().toClone(), cloneURL)
}

// gitHead returns HEAD in dir, or "" when dir is not a git repository (e.g.
// a local-directory scan with no .git). Scan.Commit stays empty so
// downstream consumers know we have no reproducible pin, rather than
// receiving stderr as a fake SHA.
func gitHead(dir string) string { return clone.Head(context.Background(), dir) }

func git(ctx context.Context, args ...string) (string, error) {
	return gitWithEnv(ctx, "", nil, args...)
}

func gitWithEnv(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	return clone.RunnerWithWaitDelay(gitWaitDelay)(ctx, dir, env, args...)
}
