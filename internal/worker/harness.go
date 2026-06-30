package worker

import (
	"io"
	"os"
	"path/filepath"
)

// A Harness is the agent CLI the container runner execs to drive a skill.
// It owns everything that varies between claude-code and an alternative
// agent (codex, opencode, ...): the binary name, the argv it takes, the
// output format it streams, the project-memory filename it auto-loads,
// and the model-API hosts it must reach. The container, egress proxy and
// workspace layout stay the same regardless of harness; only what runs
// inside the container changes.
//
// The interface is grown incrementally as call sites are wired to it
// (#211). Exit classification follows.
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
	// SkillDir is the directory under workRoot where stageSkill writes
	// SKILL.md, schema.json, and the skill's auxiliary files so this
	// harness's own discovery picks them up. All three current harnesses
	// look for a file literally named SKILL.md and follow symlinks, so
	// only the directory differs: claude reads .claude/skills/{name},
	// codex reads skills/{name}, opencode reads .opencode/skill/{name}.
	// The activation prompt that points the agent at the skill is the
	// harness's own concern, inside Args.
	SkillDir(workRoot, name string) string
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
	// Env returns the harness-specific environment for the container, in
	// docker -e form: a bare "KEY" passes the host value through, and
	// "KEY=VALUE" sets it explicitly. Covers the model-API credential and
	// the harness's own telemetry / autoupdate suppressors. baseURL is the
	// operator's model-API base-URL override (-anthropic-base-url today);
	// "" means none. Harness-neutral env (HOME, the proxy vars, semgrep)
	// stays in buildRunArgs.
	Env(baseURL string) []string
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

func (ClaudeHarness) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, ".claude", "skills", name)
}

func (ClaudeHarness) GuideFilename() string { return "CLAUDE.md" }

func (ClaudeHarness) EgressHosts() []string { return []string{"*.anthropic.com"} }

func (ClaudeHarness) Env(baseURL string) []string {
	env := []string{
		// claude-code's own opt-outs: telemetry, autoupdate, bug command,
		// and the non-essential model calls (haiku title generation etc.)
		// that a headless run does not need. Denied by the egress proxy
		// anyway, but suppressing them keeps the scan log quiet.
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"OTEL_SDK_DISABLED=true",
		"DISABLE_TELEMETRY=1",
		"DISABLE_ERROR_REPORTING=1",
		"DISABLE_BUG_COMMAND=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_NON_ESSENTIAL_MODEL_CALLS=1",
	}
	// Forwarding the host credential into the container is a known
	// residual: in-container code (T1) can read it. Closing it needs
	// proxy-side credential injection -- see threatmodel.md T1/T13.
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		env = append(env, "ANTHROPIC_API_KEY")
	}
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" {
		env = append(env, "CLAUDE_CODE_OAUTH_TOKEN")
	}
	if baseURL != "" {
		env = append(env, "ANTHROPIC_BASE_URL="+baseURL)
	}
	return env
}
