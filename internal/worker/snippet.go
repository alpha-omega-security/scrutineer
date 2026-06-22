package worker

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// snippetContextLines is how many lines of context are captured on either
// side of a finding's primary location.
const snippetContextLines = 5

// readSnippet returns the source lines around the finding's primary
// location (file:line) read from srcDir, with snippetContextLines of
// context on either side. It applies the same untrusted-path discipline as
// vidSinks: the location must parse to a path with a line number, stay
// inside the checkout after symlink resolution, and point at a regular
// file. Returns "" when any of that fails or the line is past EOF, so
// callers treat a missing snippet as not-captured rather than an error.
func readSnippet(srcDir, location string) string {
	loc := strings.TrimPrefix(strings.TrimSpace(location), "./")
	m := vidLocRE.FindStringSubmatch(loc)
	if m == nil {
		return ""
	}
	path := m[1]
	line, err := strconv.Atoi(m[2])
	if err != nil || path == "" || line < 1 || !filepath.IsLocal(path) {
		return ""
	}
	root, err := filepath.EvalSymlinks(srcDir)
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(srcDir, path))
	if err != nil || !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
		return ""
	}
	if fi, err := os.Stat(resolved); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if line > len(lines) {
		return ""
	}
	start := max(line-1-snippetContextLines, 0)
	end := min(line+snippetContextLines, len(lines))
	return strings.Join(lines[start:end], "\n")
}
