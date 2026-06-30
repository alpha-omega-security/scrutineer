package worker

// A Harness is the agent CLI the container runner execs to drive a skill.
// It owns everything that varies between claude-code and an alternative
// agent (codex, opencode): the binary name, the argv it takes, and the
// project-memory filename it auto-loads. The container, egress proxy and
// workspace layout stay the same regardless of harness; only what runs
// inside the container changes.
//
// The interface is grown one chunk at a time as call sites are wired to it
// (#211). Today it covers exec argv and the profile-guide filename; later
// chunks add stream parsing, skill staging, credentials, egress hosts and
// exit classification.
type Harness interface {
	// Binary is the executable on the runner image's PATH.
	Binary() string
	// Args is the argv (without the binary) for one skill run. effort is
	// the runner's configured default; globalMaxTurns is the runner's
	// -max-turns flag. Per-scan overrides on sj win over both.
	Args(sj SkillJob, effort string, globalMaxTurns int) []string
	// GuideFilename is the workspace-relative path the harness auto-loads
	// as project memory, where injectProfileGuide writes the profile's
	// PROFILE.md. claude-code reads CLAUDE.md; codex and opencode read
	// AGENTS.md.
	GuideFilename() string
}

// claudeHarness is the default and (for now) only harness: it wraps the
// existing buildClaudeArgs so behaviour is byte-for-byte unchanged. New
// harnesses sit alongside it; LocalClaude keeps calling buildClaudeArgs
// directly because the no-container fallback is claude-only by design.
type claudeHarness struct{}

func (claudeHarness) Binary() string { return "claude" }

func (claudeHarness) Args(sj SkillJob, effort string, globalMaxTurns int) []string {
	return buildClaudeArgs(sj, effort, globalMaxTurns)
}

func (claudeHarness) GuideFilename() string { return "CLAUDE.md" }
