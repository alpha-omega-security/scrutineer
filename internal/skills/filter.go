package skills

import (
	"slices"
	"strings"

	harnessskills "github.com/alpha-omega-security/harness/skills"
)

// BuiltinSkipPaths is the default skip list applied when a skill does not
// declare scrutineer.paths. Patterns use forward-slash paths relative to
// the workspace src/ root with shell-glob semantics (*, ?, **). Skills
// can bypass this list wholesale by declaring scrutineer.paths.
var BuiltinSkipPaths = []string{
	"**/pnpm-lock.yaml",
	"**/package-lock.json",
	"**/yarn.lock",
	"**/Cargo.lock",
	"**/go.sum",
	"**/Gemfile.lock",
	"**/poetry.lock",
	"**/composer.lock",
	"**/Package.resolved",
	"**/*.opam.locked",
	"**/_build/**",
	"**/_opam/**",
	"**/*.min.js",
	"**/*.min.css",
	"**/dist/**",
	"**/node_modules/**",
	"**/generated/**",
	"**/__generated__/**",
}

// The glob matcher and pattern round-tripping live in
// github.com/alpha-omega-security/harness/skills.
var (
	Match         = harnessskills.Match
	ValidateGlob  = harnessskills.ValidateGlob
	SplitPatterns = harnessskills.SplitPatterns
	JoinPatterns  = harnessskills.JoinPatterns
)

// DirAllExcluded reports whether every file under directory rel is
// excluded by the configured filters — i.e. the workspace pruner can
// safely RemoveAll/SkipDir the subtree without visiting its files. A
// deny pattern of shape `<X>/**` is the only thing that can guarantee
// a blanket exclusion; file-level patterns like `**/*.min.js` cannot.
// When paths is non-empty, only ignorePaths can blanket a subtree
// (paths may still selectively include files inside).
func DirAllExcluded(rel string, paths, ignorePaths []string) bool {
	if rel == ".git" || strings.HasPrefix(rel, ".git/") {
		return false
	}
	if dirBlanketed(rel, ignorePaths) {
		return true
	}
	if len(paths) == 0 && dirBlanketed(rel, BuiltinSkipPaths) {
		return true
	}
	return false
}

func dirBlanketed(rel string, patterns []string) bool {
	for _, p := range patterns {
		prefix, ok := strings.CutSuffix(p, "/**")
		if !ok {
			continue
		}
		if Match(prefix, rel) {
			return true
		}
	}
	return false
}

// PathIncluded reports whether a file at rel (forward-slash, relative to
// workRoot/src) is visible to a skill with the given filters. When paths
// is non-empty the file must match one of its patterns and the builtin
// skip list is bypassed; ignorePaths is always applied on top. The .git
// directory is always preserved so git-aware skills can read history.
func PathIncluded(rel string, paths, ignorePaths []string) bool {
	if rel == ".git" || strings.HasPrefix(rel, ".git/") {
		return true
	}
	if len(paths) > 0 {
		if !matchAny(paths, rel) {
			return false
		}
	} else if matchAny(BuiltinSkipPaths, rel) {
		return false
	}
	if matchAny(ignorePaths, rel) {
		return false
	}
	return true
}

func matchAny(patterns []string, name string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return Match(p, name) })
}
