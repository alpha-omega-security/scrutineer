package findingnorm

import (
	"path"
	"strings"
)

func CWE(cwe string) string {
	return strings.ToUpper(strings.TrimSpace(cwe))
}

func LocationFile(loc string) string {
	loc = strings.TrimSpace(strings.Split(strings.TrimSpace(loc), "\n")[0])
	for {
		i := strings.LastIndexByte(loc, ':')
		if i < 0 || !allDigits(loc[i+1:]) {
			break
		}
		loc = loc[:i]
	}
	return RepoPath(loc)
}

func RepoPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	for strings.HasPrefix(p, "./") {
		p = strings.TrimPrefix(p, "./")
	}
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

func HasParentPathSegment(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// FindingPath rebases a finding's reported location into the repository-root
// namespace that repository-wide documents — control globs, git pathspecs —
// are authored in.
//
// A finding from a subpath-scoped scan reports its location relative to the
// sub-folder, because the skill treats that folder as the project root. The
// sub-folder is denormalised onto the finding row, so the two are joined
// here rather than at each call site.
//
// An absolute path or a parent-segment escape yields "" rather than being
// cleaned: a malformed location must produce no match instead of a match
// against the wrong file.
func FindingPath(subPath, location string) string {
	file := LocationFile(location)
	subPath = RepoPath(subPath)
	if !validFindingPath(file) || (subPath != "" && !validFindingPath(subPath)) {
		return ""
	}
	return path.Join(subPath, file)
}

func validFindingPath(p string) bool {
	return p != "" && p != "." && !strings.HasPrefix(p, "/") && !HasParentPathSegment(p)
}
