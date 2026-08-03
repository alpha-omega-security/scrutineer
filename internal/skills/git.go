package skills

import (
	"context"
	"errors"
	"fmt"

	harnessskills "github.com/alpha-omega-security/harness/skills"
	"github.com/git-pkgs/clone"
)

// ParseRepoSpec splits a skills_repo spec (owner/repo[@ref] or a full https
// URL) into a clone URL and optional ref. See harness/skills.ParseRepoSpec.
var ParseRepoSpec = harnessskills.ParseRepoSpec

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
