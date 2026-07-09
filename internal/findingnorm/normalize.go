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
