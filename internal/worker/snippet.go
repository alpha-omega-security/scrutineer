package worker

import (
	"io"
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
// inside the descriptor-rooted checkout, and point at a regular file. Returns
// "" when any of that fails or the line is past EOF, so callers treat a
// missing snippet as not-captured rather than an error.
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
	root := openSourceRoot(srcDir)
	if root == nil {
		return ""
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	data, err := io.ReadAll(f)
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

// openSourceRoot rejects a symlink at srcDir itself and verifies that the
// descriptor still names the directory inspected before opening it. All child
// operations through the returned Root are then confined beneath that inode,
// including when a runner changes symlinks concurrently.
func openSourceRoot(srcDir string) *os.Root {
	entryInfo, err := os.Lstat(srcDir)
	if err != nil || !entryInfo.IsDir() {
		return nil
	}
	root, err := os.OpenRoot(srcDir)
	if err != nil {
		return nil
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !rootInfo.IsDir() || !os.SameFile(entryInfo, rootInfo) {
		_ = root.Close()
		return nil
	}
	return root
}
