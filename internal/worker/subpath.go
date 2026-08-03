package worker

import (
	"fmt"
	"path"
	"strings"
)

// CleanSubPath normalises a monorepo sub-path and rejects directory
// traversal. It trims surrounding slashes and whitespace and collapses the
// result with path.Clean. An empty result (repo root) is valid and returned
// as "". It errors on any ".." segment so the sub-path can never escape the
// clone when joined onto it — enforced at the URL parse, the run API, and
// again at workspace staging (defence in depth).
func CleanSubPath(s string) (string, error) {
	s = strings.Trim(s, "/ \t\r\n")
	if s == "" {
		return "", nil
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == ".." {
			return "", fmt.Errorf("sub_path must not contain .. segments, got %q", s)
		}
	}
	if cleaned := path.Clean(s); cleaned != "." {
		return cleaned, nil
	}
	return "", nil
}
