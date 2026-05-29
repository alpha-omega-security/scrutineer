package skills

import (
	"slices"
	"testing"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*.js", "foo.js", true},
		{"*.js", "dir/foo.js", false},
		{"**/*.js", "foo.js", true},
		{"**/*.js", "a/b/c.js", true},
		{"lib/**", "lib/foo.go", true},
		{"lib/**", "lib/a/b.go", true},
		{"lib/**", "notlib/foo.go", false},
		{"lib/**", "lib", true},
		{"**", "anything/at/all.txt", true},
		{"**/node_modules/**", "node_modules/foo.js", true},
		{"**/node_modules/**", "a/b/node_modules/x/y.js", true},
		{"**/node_modules/**", "not_node_modules/foo.js", false},
		{"?.go", "a.go", true},
		{"?.go", "ab.go", false},
		{"?.go", "a/b.go", false},
		{"**/*.test.*", "foo.test.js", true},
		{"**/*.test.*", "a/b/foo.test.tsx", true},
		{"**/*.test.*", "foo.go", false},
		{"src/**/*.go", "src/a.go", true},
		{"src/**/*.go", "src/a/b.go", true},
		{"src/**/*.go", "lib/a.go", false},
		{"foo.json", "foo.json", true},
		{"foo.json", "bar.json", false},
		{"", "", true},
		{"", "a", false},
		{"a", "", false},
	}
	for _, tc := range cases {
		got := Match(tc.pattern, tc.name)
		if got != tc.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestPathIncluded_defaultAppliesBuiltinSkip(t *testing.T) {
	cases := map[string]bool{
		"src/main.go":               true,
		"node_modules/foo/index.js": false,
		"a/node_modules/x.js":       false,
		"dist/bundle.js":            false,
		"app.min.js":                false,
		"vendor/some.lib":           true,
		"build/main.go":             true,
		"generated/types.go":        false,
		"package-lock.json":         false,
		"sub/pnpm-lock.yaml":        false,
		"src/foo/package-lock.json": false,
		"src/foo/lib.min.css":       false,
		"src/components/Button.tsx": true,
	}
	for rel, want := range cases {
		if got := PathIncluded(rel, nil, nil); got != want {
			t.Errorf("PathIncluded(%q, nil, nil) = %v, want %v", rel, got, want)
		}
	}
}

func TestPathIncluded_pathsOverrideBuiltinSkip(t *testing.T) {
	paths := []string{"node_modules/**"}
	if !PathIncluded("node_modules/foo.js", paths, nil) {
		t.Error("declared paths must override the builtin skip list (node_modules/foo.js should match)")
	}
	if PathIncluded("src/main.go", paths, nil) {
		t.Error("file outside declared paths must be excluded")
	}
}

func TestPathIncluded_ignorePathsCumulative(t *testing.T) {
	if !PathIncluded("src/main.go", nil, nil) {
		t.Fatal("baseline broken")
	}
	if PathIncluded("src/main.go", nil, []string{"src/**"}) {
		t.Error("ignore_paths should filter out src/**")
	}
	if PathIncluded("src/foo_test.go", []string{"src/**"}, []string{"**/*_test.go"}) {
		t.Error("ignore_paths should compose on top of declared paths")
	}
}

func TestPathIncluded_gitAlwaysPreserved(t *testing.T) {
	if !PathIncluded(".git", nil, nil) {
		t.Error(".git must always be preserved (baseline)")
	}
	if !PathIncluded(".git/HEAD", []string{"src/**"}, nil) {
		t.Error(".git/HEAD must survive even when paths excludes everything else")
	}
	if !PathIncluded(".git/objects/aa/bb", nil, []string{"**"}) {
		t.Error(".git contents must survive even when ignore_paths matches everything")
	}
}

func TestDirAllExcluded(t *testing.T) {
	cases := []struct {
		name        string
		rel         string
		paths       []string
		ignorePaths []string
		want        bool
	}{
		{"builtin blankets node_modules at root", "node_modules", nil, nil, true},
		{"builtin blankets nested node_modules", "src/foo/node_modules", nil, nil, true},
		{"builtin does not blanket a random dir", "src", nil, nil, false},
		{"file-level builtin pattern does not blanket dir", "anything", nil, nil, false},
		{"paths bypasses builtin", "node_modules", []string{"**"}, nil, false},
		{"ignorePaths blankets even with paths set", "node_modules", []string{"**"}, []string{"**/node_modules/**"}, true},
		{"ignorePaths blankets even with restrictive paths", "node_modules", []string{"**/*.json"}, []string{"**/node_modules/**"}, true},
		{"ignorePaths file-level does not blanket", "src", nil, []string{"**/*_test.go"}, false},
		{"ignorePaths root-anchored blankets root only", "dist", []string{"**"}, []string{"dist/**"}, true},
		{"ignorePaths root-anchored does not blanket nested same name", "pkg/dist", []string{"**"}, []string{"dist/**"}, false},
		{".git is never excluded", ".git", nil, []string{"**/**"}, false},
		{".git subdir is never excluded", ".git/objects", nil, []string{"**"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DirAllExcluded(tc.rel, tc.paths, tc.ignorePaths); got != tc.want {
				t.Errorf("DirAllExcluded(%q, %v, %v) = %v, want %v", tc.rel, tc.paths, tc.ignorePaths, got, tc.want)
			}
		})
	}
}

func TestValidateGlob(t *testing.T) {
	ok := []string{"src/**", "**/*.go", "?.js", "foo.json", "**", "", "src/[a-z]*.go"}
	for _, p := range ok {
		if err := ValidateGlob(p); err != nil {
			t.Errorf("ValidateGlob(%q) = %v, want nil", p, err)
		}
	}
	bad := []string{"[unclosed", "src/[bad", "[]"}
	for _, p := range bad {
		if err := ValidateGlob(p); err == nil {
			t.Errorf("ValidateGlob(%q) returned nil, want ErrBadPattern", p)
		}
	}
}

func TestSplitPatterns_roundTrip(t *testing.T) {
	in := []string{"src/**", "lib/**"}
	got := SplitPatterns(JoinPatterns(in))
	if !slices.Equal(got, in) {
		t.Errorf("round-trip: got %v, want %v", got, in)
	}
	if SplitPatterns("") != nil {
		t.Error("empty input should yield nil slice")
	}
	if got := SplitPatterns("\n  src/**  \n\n  lib/** \n"); !slices.Equal(got, []string{"src/**", "lib/**"}) {
		t.Errorf("SplitPatterns trim/skip-empty broken: %v", got)
	}
}
