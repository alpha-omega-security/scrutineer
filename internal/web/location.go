package web

import (
	"fmt"
	"regexp"
	"strings"
)

// locationURL turns a finding location ("path/to/file.rb:12-34") into a blob
// link on the upstream forge, anchored to the line range. Returns "" when we
// don't have enough to build one (no html_url, no commit, unrecognised host).
func locationURL(htmlURL, commit, location string) string {
	if htmlURL == "" || commit == "" || location == "" {
		return ""
	}
	path, frag := splitLocation(location)
	if path == "" {
		return ""
	}
	base := strings.TrimSuffix(htmlURL, "/")
	switch {
	case strings.Contains(base, "github.com"), strings.Contains(base, "codeberg.org"):
		u := fmt.Sprintf("%s/blob/%s/%s", base, commit, path)
		if frag != "" {
			u += "#" + githubFragment(frag)
		}
		return u
	case strings.Contains(base, "gitlab."):
		u := fmt.Sprintf("%s/-/blob/%s/%s", base, commit, path)
		if frag != "" {
			u += "#" + gitlabFragment(frag)
		}
		return u
	}
	return ""
}

var locRE = regexp.MustCompile(`^(.*?):(\d+(?:-\d+)?)$`)

func splitLocation(loc string) (path, lines string) {
	loc = strings.TrimPrefix(strings.TrimSpace(loc), "./")
	if m := locRE.FindStringSubmatch(loc); m != nil {
		return m[1], m[2]
	}
	return loc, ""
}

func githubFragment(lines string) string {
	if a, b, ok := strings.Cut(lines, "-"); ok {
		return "L" + a + "-L" + b
	}
	return "L" + lines
}

func gitlabFragment(lines string) string {
	if a, b, ok := strings.Cut(lines, "-"); ok {
		return "L" + a + "-" + b
	}
	return "L" + lines
}
