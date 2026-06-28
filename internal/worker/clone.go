package worker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"scrutineer/internal/db"
)

const dirPerm = 0o755

// RepoUnreachableError is returned when git clone/fetch fails because the
// remote is unreachable (deleted, private, wrong URL, network error).
type RepoUnreachableError struct {
	URL string
	Err error
}

func (e *RepoUnreachableError) Error() string {
	return fmt.Sprintf("repository unreachable %s: %s", e.URL, e.Err)
}

func (e *RepoUnreachableError) Unwrap() error { return e.Err }

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
	return copyTree(resolved, dst)
}

// ensureClone returns the path to an up-to-date clone of repo.URL under
// the given work root. fullClone selects between --depth 1 (false, the
// default) and full history (true). Clones on first call; fetches +
// resets on subsequent ones. Each scan supplies its own work root
// (scan-{id}) so concurrent scans do not share src or report.json,
// removing a class of races where skill A's output gets clobbered by
// skill B removing report.json before A finishes reading it.
func ensureClone(ctx context.Context, repo db.Repository, work string, fullClone bool, ref string, emit func(Event)) (string, error) {
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(work, dirPerm); err != nil {
		return "", err
	}
	if err := cloneOrFetch(ctx, repo.URL, src, fullClone, ref, emit); err != nil {
		return "", &RepoUnreachableError{URL: repo.URL, Err: err}
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

// ValidateGitRef restricts refs to a conservative branch/tag-name charset
// before they flow into the fetchRef path. The clone code already passes
// ref after a `--` argv stopper, which blocks `-`-prefixed option-shaped
// values; this validator adds the rest: `..` rejected so git's refspec
// resolver cannot treat the value as a range, plus a strict allow-list
// for the body so spaces, control characters, and shell metacharacters
// cannot reach git as an "exotic but legal" ref. Exported so the web
// layer can reject bad input at the API boundary rather than letting a
// scan get enqueued and then fail at clone time.
func ValidateGitRef(ref string) error {
	if ref == "" {
		return nil
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("invalid ref %q: must not start with -", ref)
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf(`invalid ref %q: must not contain ".."`, ref)
	}
	for _, r := range ref {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '/', r == '-':
		default:
			return fmt.Errorf("invalid ref %q: contains disallowed character %q", ref, r)
		}
	}
	return nil
}

func cloneOrFetch(ctx context.Context, url, dst string, fullClone bool, ref string, emit func(Event)) error {
	if err := validateGitURL(url); err != nil {
		return err
	}
	if err := ValidateGitRef(ref); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
		return fetchRef(ctx, dst, ref, fullClone, emit)
	}
	args := []string{"clone", "--quiet"}
	msg := "$ git clone " + url
	if !fullClone {
		args = append(args, "--depth", "1")
		msg += " (shallow)"
	}
	args = append(args, "--", url, dst)
	emit(Event{Kind: KindText, Text: msg})
	out, err := gitWithEnv(ctx, "", []string{"GIT_PROTOCOL_FROM_USER=0"}, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	// Resolve ref through the same fetchRef the cache-reuse path uses, rather
	// than `git clone --branch <ref>`: --branch rejects a commit SHA, so a SHA
	// in the branch field would fail the first scan yet work on every later
	// one. Going through fetchRef makes both paths pin a ref identically.
	if ref != "" {
		return fetchRef(ctx, dst, ref, fullClone, emit)
	}
	return nil
}

// fetchRef updates an existing cache checkout to ref, or to the remote's
// default branch when ref is empty. It fetches the ref by name and resets
// to FETCH_HEAD rather than to origin/<ref>: the cache is a single-branch
// shallow clone, so origin/<ref> only resolves for the one branch it was
// first cloned at. A different ref — another maintained release branch, a
// tag, or a commit — is in no remote-tracking ref, but fetching it by name
// always lands it in FETCH_HEAD.
func fetchRef(ctx context.Context, dst, ref string, fullClone bool, emit func(Event)) error {
	target := ref
	if target == "" {
		target = "HEAD"
	}
	fetchArgs := []string{"-C", dst, "fetch", "--quiet"}
	fetchMsg := "$ git fetch origin " + target + " && reset"
	if fullClone {
		out, _ := git(ctx, "", "-C", dst, "rev-parse", "--is-shallow-repository")
		if strings.TrimSpace(out) == "true" {
			fetchArgs = append(fetchArgs, "--unshallow")
			fetchMsg = "$ git fetch --unshallow origin " + target + " && reset"
		}
	}
	// "--" stops a ref like "--upload-pack=..." (from the branch field or a
	// /tree/<branch> URL) being parsed as a git option, matching the clone
	// and ls-remote paths. Valid refs never start with "-" so this is safe.
	fetchArgs = append(fetchArgs, "--", "origin", target)
	emit(Event{Kind: KindText, Text: fetchMsg})
	if out, err := git(ctx, "", fetchArgs...); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	if out, err := git(ctx, "", "-C", dst, "reset", "--quiet", "--hard", "FETCH_HEAD"); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	return nil
}

// ListRemoteBranches returns the branch names a remote advertises, for the
// add-repo form's branch picker. https-only (validated like clone) and
// best-effort: callers treat any error as "no suggestions" and fall back to
// free-text entry. GIT_TERMINAL_PROMPT=0 and an empty credential helper make
// a private repo fail fast instead of blocking on a credential prompt.
func ListRemoteBranches(ctx context.Context, cloneURL string) ([]string, error) {
	if err := validateGitURL(cloneURL); err != nil {
		return nil, err
	}
	out, err := gitWithEnv(ctx, "", []string{"GIT_TERMINAL_PROMPT=0"},
		"-c", "credential.helper=", "ls-remote", "--heads", "--", cloneURL)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", strings.TrimSpace(out), err)
	}
	return parseRemoteHeads(out), nil
}

// parseRemoteHeads extracts branch names from `git ls-remote --heads`
// output (lines of "<sha>\trefs/heads/<name>"), sorted and de-duplicated.
func parseRemoteHeads(out string) []string {
	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(out, "\n") {
		_, ref, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		name, ok := strings.CutPrefix(strings.TrimSpace(ref), "refs/heads/")
		if !ok || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func gitHead(dir string) string {
	out, err := git(context.Background(), dir, "rev-parse", "HEAD")
	if err != nil {
		// Not a git repository (e.g. a local-directory scan with no .git).
		// Scan.Commit stays empty so downstream consumers know we have no
		// reproducible pin, rather than receiving stderr as a fake SHA.
		return ""
	}
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
