package skills

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/git-pkgs/clone"
)

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
// empty the default branch is used. fullClone toggles between --depth 1 and
// full history, and unshallows an existing shallow clone when flipped to
// true. Returns the resolved commit SHA so callers can record exactly which
// version of the skills produced each scan. https-only, same rationale as
// internal/worker/clone.go (T2/T4).
func CloneOrPull(ctx context.Context, url, ref, dst string, fullClone bool) (string, error) {
	return cloneOrPullWithRetry(ctx, clone.Retry{}, url, ref, dst, fullClone)
}

func cloneOrPullWithRetry(ctx context.Context, retry clone.Retry, url, ref, dst string, fullClone bool) (string, error) {
	if err := clone.Ensure(ctx, retry, url, dst, ref, fullClone); err != nil {
		var ue *clone.UnreachableError
		if errors.As(err, &ue) {
			return "", fmt.Errorf("skills repo %s: %w", url, ue.Err)
		}
		return "", err
	}
	sha := clone.Head(ctx, dst)
	if sha == "" {
		return "", fmt.Errorf("skills repo %s: rev-parse HEAD failed", url)
	}
	return sha, nil
}
