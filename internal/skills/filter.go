package skills

import (
	"path"
	"slices"
	"strings"
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
	"**/*.min.js",
	"**/*.min.css",
	"**/dist/**",
	"**/node_modules/**",
	"**/generated/**",
	"**/__generated__/**",
}

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

// ValidateGlob returns path.ErrBadPattern when pattern contains a
// segment that path.Match cannot parse (e.g. `[unclosed`). matchSegments
// silently treats such patterns as "never matches" at runtime; calling
// this at parse time turns a skill author's typo into a hard error
// rather than a silent empty workspace.
func ValidateGlob(pattern string) error {
	for seg := range strings.SplitSeq(pattern, "/") {
		if _, err := path.Match(seg, "x"); err != nil {
			return err
		}
	}
	return nil
}

// Match reports whether name matches the shell glob pattern. Supports
// `*` (any chars except `/`), `?` (one char except `/`) and the
// doublestar `**` (any chars including `/`). Both pattern and name are
// forward-slash separated.
func Match(pattern, name string) bool {
	if pattern == "" || name == "" {
		return pattern == name
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			if len(rest) == 0 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(rest, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, _ := path.Match(pat[0], name[0])
		if !ok {
			return false
		}
		pat = pat[1:]
		name = name[1:]
	}
	return len(name) == 0
}

// SplitPatterns parses the newline-separated form stored in
// db.Skill.Paths / db.Skill.IgnorePaths into a clean slice, trimming
// whitespace and dropping empty lines.
func SplitPatterns(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// JoinPatterns serialises a slice of patterns into the newline form
// stored on db.Skill.
func JoinPatterns(p []string) string {
	return strings.Join(p, "\n")
}
