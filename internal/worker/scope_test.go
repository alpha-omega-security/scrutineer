package worker

import (
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

func writeScopeFile(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s pruned, stat err = %v", path, err)
	}
}

func present(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected %s kept, stat err = %v", path, err)
	}
}

func TestPruneToSubPath_topLevel(t *testing.T) {
	src := t.TempDir()
	writeScopeFile(t, src, ".git/HEAD")
	writeScopeFile(t, src, "activesupport/lib/foo.rb")
	writeScopeFile(t, src, "actionpack/lib/bar.rb")
	writeScopeFile(t, src, "README.md")

	if err := pruneToSubPath(src, "activesupport"); err != nil {
		t.Fatal(err)
	}
	present(t, filepath.Join(src, "activesupport/lib/foo.rb"))
	present(t, filepath.Join(src, ".git/HEAD")) // git preserved for git-based skills
	gone(t, filepath.Join(src, "actionpack"))
	gone(t, filepath.Join(src, "README.md"))
}

func TestPruneToSubPath_nested(t *testing.T) {
	src := t.TempDir()
	writeScopeFile(t, src, ".git/HEAD")
	writeScopeFile(t, src, "packages/core/index.js")
	writeScopeFile(t, src, "packages/other/index.js")
	writeScopeFile(t, src, "apps/web/index.js")

	if err := pruneToSubPath(src, "packages/core"); err != nil {
		t.Fatal(err)
	}
	present(t, filepath.Join(src, "packages/core/index.js"))
	present(t, filepath.Join(src, ".git/HEAD"))
	gone(t, filepath.Join(src, "packages/other"))
	gone(t, filepath.Join(src, "apps"))
}

func TestPruneToSubPath_missing(t *testing.T) {
	src := t.TempDir()
	writeScopeFile(t, src, "README.md")
	if err := pruneToSubPath(src, "nope"); err == nil {
		t.Error("expected error for a sub_path that does not exist")
	}
}

func TestScanScopeHard(t *testing.T) {
	hard := &Worker{SubprojectScope: "hard"}
	soft := &Worker{SubprojectScope: "soft"}
	unset := &Worker{}
	fid := uint(5)
	cases := []struct {
		name string
		w    *Worker
		scan db.Scan
		want bool
	}{
		{"root scan never hard", hard, db.Scan{SubPath: ""}, false},
		{"subpath + hard default", hard, db.Scan{SubPath: "as"}, true},
		{"subpath + soft default", soft, db.Scan{SubPath: "as"}, false},
		{"subpath + unset default is soft", unset, db.Scan{SubPath: "as"}, false},
		{"override soft beats hard default", hard, db.Scan{SubPath: "as", ScopeMode: "soft"}, false},
		{"override hard beats soft default", soft, db.Scan{SubPath: "as", ScopeMode: "hard"}, true},
		{"finding-scoped stays soft", hard, db.Scan{SubPath: "as", FindingID: &fid}, false},
	}
	for _, tc := range cases {
		if got := tc.w.scanScopeHard(&tc.scan); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsDependencyResolutionFailure(t *testing.T) {
	pos := []string{
		`Bundler could not find compatible versions for gem "activesupport"`,
		"npm ERR! code ERESOLVE\nnpm ERR! unable to resolve dependency tree",
		"ERROR: Could not find a version that satisfies the requirement foo",
		"error: failed to select a version for `foo`",
		"go: no required module provides package example.com/x",
		"Your requirements could not be resolved to an installable set of packages.",
	}
	neg := []string{
		"",
		"SyntaxError: unexpected token",
		"undefined method `foo' for nil:NilClass",
		"2 failing tests",
		"segmentation fault",
	}
	for _, s := range pos {
		if !isDependencyResolutionFailure(s) {
			t.Errorf("want dependency-resolution failure for %q", s)
		}
	}
	for _, s := range neg {
		if isDependencyResolutionFailure(s) {
			t.Errorf("false positive for %q", s)
		}
	}
}
