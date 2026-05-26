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

// ParseRepoSpec splits a skills_repo spec into a clone URL and an optional
// git ref. Two forms are accepted:
//
//	owner/repo[@ref]                — shorthand expanded to https://github.com/owner/repo
//	https://host/path/to/repo[@ref] — full URL with an optional trailing ref
//
// ref is empty when none is given, meaning "use the repo's default branch".
// In the URL form, only an `@` that appears after the last `/` is treated as
// a ref separator, so token-in-URL credentials (https://<token>@host/...)
// pass through untouched. As a consequence, slash-bearing refs after `@` are
// not supported; use the short form (`main` instead of `refs/heads/main`).
func ParseRepoSpec(raw string) (url, ref string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("empty skills_repo spec")
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme := raw[:i+3]
		rest := raw[len(scheme):]
		if at := strings.LastIndex(rest, "@"); at > strings.LastIndex(rest, "/") {
			ref = rest[at+1:]
			rest = rest[:at]
		}
		url = scheme + rest
	} else {
		if at := strings.Index(raw, "@"); at >= 0 {
			ref = raw[at+1:]
			raw = raw[:at]
		}
		parts := strings.Split(raw, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("expected owner/repo or https URL, got %q", raw)
		}
		url = "https://github.com/" + raw
	}
	if !strings.HasPrefix(url, "https://") {
		return "", "", fmt.Errorf("skills repo must use https://, got %q", url)
	}
	return url, ref, nil
}

// CloneOrPull prepares a local copy of a git repo at dst. On first call it
// clones; on subsequent calls it fetches and resets to the requested ref so
// skill updates propagate without needing to wipe the cache. When ref is
// empty the default branch (origin/HEAD) is used. fullClone toggles between
// --depth 1 and full history, and unshallows an existing shallow clone when
// flipped to true. Returns the resolved commit SHA so callers can record
// exactly which version of the skills produced each scan. https-only, same
// rationale as internal/worker/clone.go (T2/T4).
func CloneOrPull(ctx context.Context, url, ref, dst string, fullClone bool) (string, error) {
	if !strings.HasPrefix(url, "https://") {
		return "", fmt.Errorf("skills repo must be https://, got %q", url)
	}
	return cloneOrPull(ctx, url, ref, dst, fullClone)
}

func cloneOrPull(ctx context.Context, url, ref, dst string, fullClone bool) (string, error) {
	if _, err := os.Stat(filepath.Join(dst, ".git")); err == nil {
		fetchArgs := []string{"fetch", "--quiet", "origin"}
		if fullClone {
			out, _ := git(ctx, dst, "rev-parse", "--is-shallow-repository")
			if strings.TrimSpace(out) == "true" {
				fetchArgs = []string{"fetch", "--unshallow", "--quiet", "origin"}
			}
		}
		if out, err := git(ctx, dst, fetchArgs...); err != nil {
			return "", fmt.Errorf("fetch %s: %s: %w", url, out, err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(dst), dirPerm); err != nil {
			return "", err
		}
		args := []string{"clone", "--quiet"}
		if !fullClone {
			args = []string{"clone", "--depth", "1", "--quiet"}
		}
		args = append(args, "--", url, dst)
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Env = append(os.Environ(), "GIT_PROTOCOL_FROM_USER=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("clone %s: %s: %w", url, string(out), err)
		}
	}
	target := "origin/HEAD"
	if ref != "" {
		if out, err := git(ctx, dst, "fetch", "--quiet", "origin", "--end-of-options", ref); err != nil {
			return "", fmt.Errorf("fetch ref %s: %s: %w", ref, out, err)
		}
		target = "FETCH_HEAD"
	}
	if out, err := git(ctx, dst, "reset", "--quiet", "--hard", target); err != nil {
		return "", fmt.Errorf("reset to %s: %s: %w", target, out, err)
	}
	out, err := git(ctx, dst, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("rev-parse: %s: %w", out, err)
	}
	return strings.TrimSpace(out), nil
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
