package worker

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// agentDirectiveDirs are directory basenames that AI coding CLIs auto-load
// configuration, hooks, or skills from. A hostile repository can plant one
// of these to inject instructions into the auditing agent (T5 in
// threatmodel.md), so they are removed from every clone before the first
// Read/Grep touches ./src, unconditionally — a skill's scrutineer.paths
// cannot opt back in. Matched case-insensitively against the basename;
// entries may use shell-glob metacharacters.
var agentDirectiveDirs = []string{
	".claude",
	".anthropic",
	".cursor",
	".windsurf",
	".continue",
	".cline",
	".roo",
	".goose",
	".aider",
	".aider.*",
	".gemini",
	".codex",
	".copilot",
	".devin",
	// .ai and .llm are deliberately excluded: no known agent CLI auto-loads
	// from those exact basenames, and both are plausible non-agent config
	// directories (ML project scaffolding, Adobe Illustrator asset dirs).
}

// agentDirectiveFiles are file basenames that AI coding CLIs auto-load as
// project memory or standing instructions. See agentDirectiveDirs. Matched
// case-insensitively against the basename with shell-glob semantics.
var agentDirectiveFiles = []string{
	"claude.md",
	"claude.*.md",
	"agents.md",
	"agent.md",
	"gemini.md",
	"codex.md",
	".cursorrules",
	".cursorignore",
	".windsurfrules",
	".clinerules",
	".roorules",
	".rooignore",
	".aider.conf.yml",
	".aider.conf.yaml",
	".aiderrules",
	"copilot-instructions.md",
	"*.instructions.md",
	"*.prompt.md",
	".rules",
	"llms.txt",
	"llms-full.txt",
}

// stripAgentDirectives walks root and deletes every directory whose
// basename matches agentDirectiveDirs (recursively) and every file whose
// basename matches agentDirectiveFiles. Returns the number of items
// removed (a directory counts as one regardless of its contents). The
// .git subtree is skipped so refs named after any pattern above survive.
// Idempotent: a second call over the same tree returns 0, nil.
func stripAgentDirectives(root string) (int, error) {
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		base := strings.ToLower(d.Name())
		if d.IsDir() {
			if base == ".git" {
				return filepath.SkipDir
			}
			if matchAnyBasename(agentDirectiveDirs, base) {
				if rmErr := os.RemoveAll(p); rmErr != nil {
					return rmErr
				}
				n++
				return filepath.SkipDir
			}
			return nil
		}
		if matchAnyBasename(agentDirectiveFiles, base) {
			if rmErr := os.Remove(p); rmErr != nil {
				return rmErr
			}
			n++
		}
		return nil
	})
	return n, err
}

// matchAnyBasename reports whether base matches any of patterns under
// path.Match semantics. Callers pass base already lowercased and patterns
// are stored lowercase, so matching is case-insensitive without a per-call
// allocation.
func matchAnyBasename(patterns []string, base string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, base); ok {
			return true
		}
	}
	return false
}
