package worker

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoCacheRoot(t *testing.T) {
	a := RepoCacheRoot("/data", "https://github.com/a/b")
	b := RepoCacheRoot("/data", "https://github.com/a/b")
	c := RepoCacheRoot("/data", "https://github.com/c/d")
	if a != b {
		t.Errorf("same URL should produce same path: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different URLs should produce different paths, both %q", a)
	}
	if !strings.HasPrefix(a, filepath.Join("/data", "repo-cache")+string(filepath.Separator)) {
		t.Errorf("path %q not under /data/repo-cache/", a)
	}
}
