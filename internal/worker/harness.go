package worker

import "io"

// A Harness is the agent CLI the container runner execs to drive a skill.
// It owns everything that varies between claude-code and an alternative
// agent (codex, opencode, ...): the binary name, the argv it takes, the
// output format it streams, the project-memory filename it auto-loads,
// and the model-API hosts it must reach. The container, egress proxy and
// workspace layout stay the same regardless of harness; only what runs
// inside the container changes.
//
// The interface is grown incrementally as call sites are wired to it
// (#211). Skill staging, credentials and exit classification follow.
type Harness interface {
	// Binary is the executable on the runner image's PATH.
	Binary() string
	// Args is the argv (without the binary) for one skill run. effort is
	// the runner's configured default; globalMaxTurns is the runner's
	// -max-turns flag. Per-scan overrides on sj win over both.
	Args(sj SkillJob, effort string, globalMaxTurns int) []string
	// ParseStream reads the harness's combined stdout/stderr and emits one
	// Event per logical line. The Event vocabulary (KindText, KindTool,
	// KindSession, KindError, ...) is harness-neutral; this method maps
	// the harness's own output format onto it so the scan log, session
	// capture and max-turns detection work the same regardless of agent.
	ParseStream(r io.Reader, emit func(Event))
	// GuideFilename is the workspace-relative path the harness auto-loads
	// as project memory, where injectProfileGuide writes the profile's
	// PROFILE.md. claude-code reads CLAUDE.md; codex and opencode read
	// AGENTS.md.
	GuideFilename() string
	// EgressHosts is the model-API hostnames the harness must reach, in
	// the same wildcard form as DefaultEgressAllow. They are appended to
	// the egress proxy's allowlist at startup so the agent inside the
	// container can talk to its provider; the static allowlists are
	// harness-neutral and contain none of these.
	EgressHosts() []string
}

// ClaudeHarness is the default and (for now) only harness: it wraps the
// existing buildClaudeArgs and ParseStream so behaviour is byte-for-byte
// unchanged. Other harnesses (codex, opencode, ...) sit alongside it;
// LocalClaude keeps calling those functions directly because the
// no-container fallback is claude-only by design.
type ClaudeHarness struct{}

func (ClaudeHarness) Binary() string { return "claude" }

func (ClaudeHarness) Args(sj SkillJob, effort string, globalMaxTurns int) []string {
	return buildClaudeArgs(sj, effort, globalMaxTurns)
}

func (ClaudeHarness) ParseStream(r io.Reader, emit func(Event)) {
	ParseStream(r, emit)
}

func (ClaudeHarness) GuideFilename() string { return "CLAUDE.md" }

func (ClaudeHarness) EgressHosts() []string { return []string{"*.anthropic.com"} }
