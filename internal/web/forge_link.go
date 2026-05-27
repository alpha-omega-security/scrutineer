package web

import (
	"fmt"
	"net/url"
	"strings"
)

// forgeKind identifies the URL shape a forge uses for blob, commit, and
// line links. It is inferred from a Repository.HTMLURL host: scrutineer
// only commits a URL shape for the four hosts DefaultHTMLURL recognises,
// so anything else maps to forgeUnknown and the link builders below
// return "".
type forgeKind int

const (
	forgeUnknown   forgeKind = iota
	forgeGitHub              // github.com
	forgeGitLab              // gitlab.*
	forgeGitea               // codeberg.org / Gitea / Forgejo
	forgeBitbucket           // bitbucket.org
)

func detectForge(htmlURL string) forgeKind {
	if htmlURL == "" {
		return forgeUnknown
	}
	u, err := url.Parse(htmlURL)
	if err != nil {
		return forgeUnknown
	}
	host := strings.ToLower(u.Host)
	switch {
	case host == "github.com":
		return forgeGitHub
	case host == "codeberg.org":
		return forgeGitea
	case host == "bitbucket.org":
		return forgeBitbucket
	case strings.HasPrefix(host, "gitlab."):
		return forgeGitLab
	}
	return forgeUnknown
}

// forgeBlobURL builds a link to one file at a specific commit on the
// forge web UI. Returns "" when the host is not one of the four
// recognised forges, when htmlURL/commit/path is empty, or when path
// fails the same traversal/NUL checks as the in-app browser. Paths are
// segment-escaped because forge URLs may include unicode or spaces.
func forgeBlobURL(htmlURL, commit, blobPath string, line int) string {
	if htmlURL == "" || commit == "" || blobPath == "" {
		return ""
	}
	clean, ok := sanitizeBlobPath(blobPath)
	if !ok {
		return ""
	}
	base := strings.TrimRight(htmlURL, "/")
	escaped := escapeBlobPath(clean)
	switch detectForge(htmlURL) {
	case forgeGitHub:
		u := fmt.Sprintf("%s/blob/%s/%s", base, commit, escaped)
		if line > 0 {
			u += fmt.Sprintf("#L%d", line)
		}
		return u
	case forgeGitLab:
		u := fmt.Sprintf("%s/-/blob/%s/%s", base, commit, escaped)
		if line > 0 {
			u += fmt.Sprintf("#L%d", line)
		}
		return u
	case forgeGitea:
		u := fmt.Sprintf("%s/src/commit/%s/%s", base, commit, escaped)
		if line > 0 {
			u += fmt.Sprintf("#L%d", line)
		}
		return u
	case forgeBitbucket:
		u := fmt.Sprintf("%s/src/%s/%s", base, commit, escaped)
		if line > 0 {
			u += fmt.Sprintf("#lines-%d", line)
		}
		return u
	}
	return ""
}

// forgeCommitURL builds a link to one commit on the forge web UI. The
// path segment differs by host: Bitbucket uses /commits/<sha> (plural),
// the others use /commit/<sha>; GitLab namespaces it under /-/. Returns
// "" for unknown hosts so callers can fall back to plain text.
func forgeCommitURL(htmlURL, commit string) string {
	if htmlURL == "" || commit == "" {
		return ""
	}
	base := strings.TrimRight(htmlURL, "/")
	switch detectForge(htmlURL) {
	case forgeGitHub, forgeGitea:
		return fmt.Sprintf("%s/commit/%s", base, commit)
	case forgeGitLab:
		return fmt.Sprintf("%s/-/commit/%s", base, commit)
	case forgeBitbucket:
		return fmt.Sprintf("%s/commits/%s", base, commit)
	}
	return ""
}
