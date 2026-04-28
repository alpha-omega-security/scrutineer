package web

import (
	"fmt"
	"net/url"
	"strings"
)

// RepoInput is the parsed form of a user-supplied repository reference.
// CloneURL is what scrutineer passes to `git clone`; SubPath is the
// sub-folder within the checkout that scans should scope to (empty means
// the repo root). Branch is extracted from /tree/<branch>/<path> URLs so
// the operator knows it was present, but is not honoured for clone (see
// #19 discussion) — scrutineer still clones the default branch.
type RepoInput struct {
	CloneURL string
	SubPath  string
	Branch   string
}

// ParseRepoInput accepts the three user-facing shapes:
//
//	https://github.com/owner/repo[.git]
//	https://github.com/owner/repo/tree/<branch>/<path...>
//	https://forge/owner/repo#<path>
//
// The fragment form is the forge-agnostic way to scope to a sub-path for
// non-GitHub hosts. /tree/ parsing is GitHub-specific but matches the URL
// users paste from the web UI.
//
// CloneURL is normalised so the same repository pasted in different forms
// dedupes to one row: the host is lowercased, the query string is dropped,
// trailing slashes are stripped, `.git` is appended once, and for forges
// known to treat owner/repo case-insensitively the path is lowercased.
// Branch names and sub-paths keep their case.
func ParseRepoInput(raw string) (RepoInput, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RepoInput{}, fmt.Errorf("url required")
	}
	if !strings.HasPrefix(raw, "https://") {
		return RepoInput{}, fmt.Errorf("only https:// URLs are allowed, got %q", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return RepoInput{}, fmt.Errorf("parse url: %w", err)
	}
	u.Host = strings.ToLower(u.Host)
	u.RawQuery = ""

	// Fragment form: url#sub/path. Always wins if present, since the user
	// typed it explicitly.
	if u.Fragment != "" {
		sub := strings.Trim(u.Fragment, "/")
		u.Fragment = ""
		return RepoInput{
			CloneURL: cloneURL(u, u.Path),
			SubPath:  sub,
		}, nil
	}

	// /tree/<branch>/<path> shape (GitHub, Gitea, Forgejo).
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	treeIdx := -1
	for i, p := range parts {
		if p == "tree" {
			treeIdx = i
			break
		}
	}
	if treeIdx >= 2 && treeIdx+1 < len(parts) {
		// owner/repo[/...]/tree/<branch>/<path...>
		repoPath := "/" + strings.Join(parts[:treeIdx], "/")
		branch := parts[treeIdx+1]
		subPath := ""
		if treeIdx+2 < len(parts) {
			subPath = strings.Join(parts[treeIdx+2:], "/")
		}
		return RepoInput{
			CloneURL: cloneURL(u, repoPath),
			SubPath:  subPath,
			Branch:   branch,
		}, nil
	}

	// Plain clone URL.
	return RepoInput{CloneURL: cloneURL(u, u.Path)}, nil
}

// caseInsensitiveForges treat owner/repo path segments as
// case-insensitive, so lowercasing them is safe and lets bulk import
// dedupe `Foo/Bar` against `foo/bar`. Unknown hosts keep their path case.
var caseInsensitiveForges = map[string]bool{
	"github.com":    true,
	"gitlab.com":    true,
	"bitbucket.org": true,
	"codeberg.org":  true,
}

func cloneURL(u *url.URL, path string) string {
	c := *u
	c.Path = path
	if caseInsensitiveForges[c.Host] {
		c.Path = strings.ToLower(c.Path)
	}
	return ensureGitSuffix(c.String())
}

// ensureGitSuffix returns u with a single trailing ".git". Idempotent.
func ensureGitSuffix(u string) string {
	u = strings.TrimRight(u, "/")
	if strings.HasSuffix(u, ".git") {
		return u
	}
	return u + ".git"
}
