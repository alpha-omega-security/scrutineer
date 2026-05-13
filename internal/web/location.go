package web

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// locationURL turns a finding location ("path/to/file.rb:12-34") into a
// link to the in-app code browser pinned to the recorded scan commit.
// Returns "" when commit or location are missing; the template then
// renders the location as plain text.
func locationURL(repoID uint, commit, location string) string {
	if repoID == 0 || commit == "" || location == "" {
		return ""
	}
	path, frag := splitLocation(location)
	if path == "" {
		return ""
	}
	u := fmt.Sprintf("/repositories/%d/blob/%s/%s", repoID, commit, escapeBlobPath(path))
	if frag != "" {
		u += "?line=" + frag + "#L" + firstLine(frag)
	}
	return u
}

// locRE splits a finding location into its file path and line spec. The
// trailing column group is optional so importer-supplied locations that carry
// a column ("file.js:42:7", as emitted by the SARIF parser) resolve to the
// same blob link as native "file.rb:12-34" locations.
var locRE = regexp.MustCompile(`^(.*?):(\d+(?:-\d+)?)(?::\d+(?:-\d+)?)?$`)

func splitLocation(loc string) (path, lines string) {
	loc = strings.TrimPrefix(strings.TrimSpace(loc), "./")
	if m := locRE.FindStringSubmatch(loc); m != nil {
		return m[1], m[2]
	}
	return loc, ""
}

func escapeBlobPath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func firstLine(lines string) string {
	if a, _, ok := strings.Cut(lines, "-"); ok {
		return a
	}
	return lines
}
