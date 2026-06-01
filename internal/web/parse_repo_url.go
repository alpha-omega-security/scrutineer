package web

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// LocalScheme is the URL prefix used to mark a Repository.URL as a path
// on disk rather than a remote git URL.
const LocalScheme = "file://"

// RepoInput is the parsed form of a user-supplied repository reference.
// CloneURL is what scrutineer passes to `git clone`; SubPath is the
// sub-folder within the checkout that scans should scope to (empty means
// the repo root). Branch is extracted from /tree/<branch>/<path> URLs (or
// supplied explicitly via the add-repo form's branch field) and is honoured
// for checkout: createOrTriageRepo passes it to Scan.Ref. Empty means the
// repository's default branch.
//
// For local directory inputs (file:// or absolute path), CloneURL is
// file://<abs-path>, Name is the directory basename, Owner is empty, and
// Branch/SubPath stay empty. Local is true so callers can branch on the
// kind without re-parsing.
//
// Owner and Name are derived from the URL path (last two segments) and
// seed the Repository row at import time so listings and the orgs view
// work before the metadata job has run; the metadata job overwrites them
// with the canonical forge values when it lands. Owner is empty when the
// URL has fewer than two path segments (cgit-style host/<repo>).
type RepoInput struct {
	CloneURL string
	Owner    string
	Name     string
	SubPath  string
	Branch   string
	Local    bool
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
// trailing slashes and a `.git` suffix are stripped, and for forges known
// to treat owner/repo case-insensitively the path is lowercased. Branch
// names and sub-paths keep their case.
func ParseRepoInput(raw string) (RepoInput, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return RepoInput{}, fmt.Errorf("url required")
	}
	if strings.HasPrefix(raw, LocalScheme) || strings.HasPrefix(raw, "/") {
		return parseLocalInput(raw)
	}
	if !strings.HasPrefix(raw, "https://") {
		return RepoInput{}, fmt.Errorf("only https:// URLs and local absolute paths are allowed, got %q", raw)
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
		return newRepoInput(cloneURL(u, u.Path), sub, ""), nil
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
		return newRepoInput(cloneURL(u, repoPath), subPath, branch), nil
	}

	// Plain clone URL.
	return newRepoInput(cloneURL(u, u.Path), "", ""), nil
}

// newRepoInput builds a RepoInput and derives Owner/Name from the
// already-normalised clone URL so every parse path agrees on what those
// values are.
func newRepoInput(clone, sub, branch string) RepoInput {
	r := RepoInput{CloneURL: clone, SubPath: sub, Branch: branch, Name: "repo"}
	u, err := url.Parse(clone)
	if err != nil {
		return r
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if last := len(parts) - 1; last >= 0 && parts[last] != "" {
		r.Name = parts[last]
		if last >= 1 {
			r.Owner = parts[last-1]
		}
	}
	return r
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
	return stripGitSuffix(c.String())
}

// stripGitSuffix returns u with any trailing slash and ".git" removed.
// All major forges clone fine without it and ecosyste.ms / web UIs emit
// the bare form, so stripping is the canonical shape. Idempotent.
func stripGitSuffix(u string) string {
	u = strings.TrimRight(u, "/")
	return strings.TrimSuffix(u, ".git")
}

// DefaultHTMLURL seeds Repository.HTMLURL at row-create time for the
// common case where the clone URL is also the web-UI URL — every major
// public forge. The repo_metadata skill still overwrites this with the
// canonical value when it runs; this just makes the HTML URL available
// in the gap before that skill lands, and on instances where it never
// runs. Returns "" for hosts we don't recognise so authority for those
// stays with the metadata skill.
//
// The returned URL has any trailing slash and ".git" suffix stripped so
// it's a valid web-UI URL even when callers pass a raw clone URL.
//
// Recognised: github.com, codeberg.org, bitbucket.org, and any gitlab.*
// host. The locationURL link builder resolves GitHub/Codeberg/GitLab,
// but not Bitbucket; we still seed bitbucket because the field is
// consumed by other surfaces (repo pages, API output) that just want
// any sensible HTML URL.
func DefaultHTMLURL(cloneURL string) string {
	if cloneURL == "" {
		return ""
	}
	u, err := url.Parse(cloneURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Host)
	switch {
	case host == "github.com",
		host == "codeberg.org",
		host == "bitbucket.org",
		strings.HasPrefix(host, "gitlab."):
		return stripGitSuffix(cloneURL)
	}
	return ""
}

// parseLocalInput accepts either file:///abs/path or /abs/path and
// returns a RepoInput whose CloneURL is file://<cleaned-abs-path>. The
// path is required to be absolute and free of `..` segments after
// cleaning so a caller cannot escape past the supplied root by feeding
// in `/srv/../etc`. Existence is not checked here — handlers stat the
// path before persisting so a typo surfaces at submission time rather
// than as a ghost Repository row.
func parseLocalInput(raw string) (RepoInput, error) {
	path := strings.TrimPrefix(raw, LocalScheme)
	if !filepath.IsAbs(path) {
		return RepoInput{}, fmt.Errorf("local path must be absolute, got %q", raw)
	}
	// Check `..` against the pre-Clean path so `/srv/../etc` is rejected
	// rather than silently collapsed to `/etc`.
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return RepoInput{}, fmt.Errorf("local path must not contain .. segments, got %q", raw)
		}
	}
	clean := filepath.Clean(path)
	name := filepath.Base(clean)
	if name == "/" || name == "." {
		return RepoInput{}, fmt.Errorf("local path %q has no basename", raw)
	}
	return RepoInput{CloneURL: LocalScheme + clean, Name: name, Local: true}, nil
}
