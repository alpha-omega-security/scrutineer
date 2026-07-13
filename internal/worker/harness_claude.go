package worker

import (
	"io"
	"path/filepath"
)

// ClaudeHarness is the default harness: it wraps the existing
// buildClaudeArgs and ParseStream so behaviour under -backend claude is
// byte-for-byte what it was before the interface. Other harnesses
// (CodexHarness, ...) sit alongside it; LocalClaude keeps calling those
// functions directly because the no-container fallback is claude-only
// by design.
type ClaudeHarness struct{}

func (ClaudeHarness) Binary() string { return "claude" }

func (ClaudeHarness) Args(sj SkillJob, effort string, globalMaxTurns int, _ string) []string {
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
	// Closing the T1/T13 residual (in-container code can read the
	// forwarded credential) needs proxy-side credential injection —
	// see threatmodel.md.
	env = append(env, passthroughEnv("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")...)
	if baseURL != "" {
		env = append(env, "ANTHROPIC_BASE_URL="+baseURL)
	}
	return env
}

func (ClaudeHarness) StateEnv(containerPath string) []string {
	return []string{"CLAUDE_CONFIG_DIR=" + containerPath}
}

func (ClaudeHarness) AccountErrorText(s string) string {
	return claudeAccountErrorText(s)
}

func (ClaudeHarness) DefaultModels() []ModelDefault {
	// Tier tags mirror what the substring heuristic in web/models.go
	// produced against this list: mid=first sonnet, high=first entry,
	// max=last opus. Tagging them explicitly means the heuristic is
	// never consulted for the built-in list.
	return []ModelDefault{
		{Name: "Opus 4.6", ID: "claude-opus-4-6", Tier: "high"},
		{Name: "Opus 4.7", ID: "claude-opus-4-7"},
		{Name: "Opus 4.8", ID: "claude-opus-4-8", Tier: "max"},
		{Name: "Sonnet 4.6", ID: "claude-sonnet-4-6", Tier: "mid"},
		{Name: "Sonnet 5.0", ID: "claude-sonnet-5"},
		{Name: "Fable 5", ID: "claude-fable-5[1m]"},
	}
}
