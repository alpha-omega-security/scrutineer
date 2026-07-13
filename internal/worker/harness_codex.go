package worker

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

// CodexHarness drives OpenAI's codex CLI in headless `codex exec` mode.
// It maps the Harness interface onto codex's conventions: SKILL.md
// discovery at ./skills/{name}, AGENTS.md for project memory, CODEX_HOME
// for the persistent thread store, and CODEX_API_KEY for non-interactive
// API-key auth. The container, egress proxy and workspace stay the same
// as for claude; only what runs inside changes.
type CodexHarness struct{}

func (CodexHarness) Binary() string { return "codex" }

// Args builds the `codex exec` argv. codex has no slash-style skill
// invocation in headless mode -- the skill is discovered at
// ./skills/{name}/SKILL.md -- so the prompt names it explicitly. Resume
// uses `exec resume <session>` with the session id codex reported in a
// prior run's stream. There is no per-turn cap in codex exec, so the
// max-turns inputs are accepted and ignored.
func (CodexHarness) Args(sj SkillJob, _ string, _ int, baseURL string) []string {
	var args []string
	if baseURL != "" {
		args = append(args, "-c", "openai_base_url="+strconv.Quote(baseURL))
	}
	args = append(args,
		"exec",
		"--json",
		// codex's Linux sandbox is bubblewrap, which is not in the runner
		// image and would not work under its --cap-drop ALL / default
		// seccomp anyway (bwrap needs unprivileged userns). Scrutineer's
		// container already drops all caps, runs non-root, mounts /work,
		// and gates egress through the proxy -- that IS the sandbox --
		// so disable codex's own layer rather than fight it.
		"--sandbox", "danger-full-access",
		"--skip-git-repo-check",
	)
	if sj.Model != "" {
		args = append(args, "--model", sj.Model)
	}
	if sj.ResumeSessionID != "" {
		args = append(args, "resume", sj.ResumeSessionID)
	}
	return append(args, explicitSkillPrompt(sj, "./skills/"+sj.Name))
}

// ParseStream reads `codex exec --json` JSONL output. The event shapes
// codex emits are mapped onto the harness-neutral Event vocabulary:
// thread/session announcements become KindSession (so resume works),
// agent text becomes KindText, tool calls become KindTool, and anything
// else -- including non-JSON lines codex writes to stderr -- passes
// through as KindText so nothing is silently dropped. codex has no
// max-turns cap, so no "hit max turns" event is emitted.
func (CodexHarness) ParseStream(r io.Reader, emit func(Event)) {
	scanJSONL(r, emit, parseCodexLine)
}

// codexLine is the subset of `codex exec --json` event fields the
// harness reads. Shapes here were verified against a live codex 0.142.5
// run; unknown types still fall through to KindText so the scan log
// shows them rather than dropping them.
type codexLine struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id"`
	ThreadID  string          `json:"thread_id"`
	Text      string          `json:"text"`
	Message   string          `json:"message"`
	Tool      string          `json:"tool"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	Error     string          `json:"error"`
	Item      *codexItem      `json:"item"`
	Usage     *codexUsage     `json:"usage"`
}

type codexItem struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Message string          `json:"message"`
	Command string          `json:"command"`
	Tool    string          `json:"tool"`
	Name    string          `json:"name"`
	Input   json.RawMessage `json:"input"`
}

// codexUsage is the turn.completed token breakdown. Mapped onto the
// harness-neutral Usage struct so codex runs report tokens like claude runs.
type codexUsage struct {
	InputTokens       int `json:"input_tokens"`
	CachedInputTokens int `json:"cached_input_tokens"`
	OutputTokens      int `json:"output_tokens"`
}

func parseCodexLine(raw []byte, emit func(Event)) {
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return
	}
	var ev codexLine
	if err := json.Unmarshal(raw, &ev); err != nil {
		// codex writes this to stderr on every headless run even with
		// stdin at /dev/null; container.go merges stderr into the stream,
		// so drop it here rather than show it in every scan log.
		if strings.HasPrefix(line, "Reading additional input from stdin") {
			return
		}
		emit(Event{Kind: KindText, Text: line})
		return
	}
	switch {
	case isCodexSessionEvent(ev) && (ev.SessionID != "" || ev.ThreadID != ""):
		id := ev.SessionID
		if id == "" {
			id = ev.ThreadID
		}
		emit(Event{Kind: KindSession, SessionID: id})
	case ev.Type == "turn.started":
		// Pure marker, no payload; item.completed events carry the content.
		return
	case ev.Type == "turn.completed":
		var u Usage
		if ev.Usage != nil {
			u = Usage{
				InputTokens:     ev.Usage.InputTokens,
				OutputTokens:    ev.Usage.OutputTokens,
				CacheReadTokens: ev.Usage.CachedInputTokens,
			}
		}
		// One turn.completed per turn; the accumulator sums Turns
		// across events so the scan row records the count.
		emit(Event{Kind: KindResult, Usage: u, Turns: 1})
	case ev.Type == "item.started":
		// item.completed for the same id carries the same fields plus the
		// result; emitting both would show every command twice in the log.
		return
	case ev.Item != nil && ev.Item.Type == "error":
		emit(Event{Kind: KindError, Text: ev.Item.Message})
	case ev.Item != nil && ev.Item.Text != "":
		emit(Event{Kind: KindText, Text: ev.Item.Text})
	case ev.Item != nil && isCodexToolItem(ev.Item.Type):
		name := codexToolName(ev.Item)
		emit(Event{Kind: KindTool, Tool: name, Text: codexToolText(ev.Item)})
	case ev.Type == "tool" || ev.Tool != "":
		name := ev.Tool
		if name == "" {
			name = ev.Name
		}
		emit(Event{Kind: KindTool, Tool: name, Text: summariseInput(name, ev.Input)})
	case ev.Error != "":
		emit(Event{Kind: KindError, Text: ev.Error})
	case ev.Text != "":
		emit(Event{Kind: KindText, Text: ev.Text})
	case ev.Message != "":
		emit(Event{Kind: KindText, Text: ev.Message})
	default:
		emit(Event{Kind: KindText, Text: line})
	}
}

func isCodexSessionEvent(ev codexLine) bool {
	switch ev.Type {
	case "thread.started", "session.created", "init":
		return true
	default:
		return false
	}
}

func isCodexToolItem(t string) bool {
	return strings.Contains(t, "command") || strings.Contains(t, "tool")
}

func codexToolName(item *codexItem) string {
	for _, name := range []string{item.Tool, item.Name} {
		if name != "" {
			return name
		}
	}
	if strings.Contains(item.Type, "command") {
		return "command"
	}
	return item.Type
}

func codexToolText(item *codexItem) string {
	if item.Command != "" {
		return item.Command
	}
	return summariseInput(codexToolName(item), item.Input)
}

func (CodexHarness) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, "skills", name)
}

func (CodexHarness) GuideFilename() string { return "AGENTS.md" }

func (CodexHarness) EgressHosts() []string {
	// api.openai.com for the model API; auth0.openai.com and
	// chatgpt.com for the ChatGPT-login auth flow when an operator
	// uses Codex Pro instead of an API key.
	return []string{"api.openai.com", "auth0.openai.com", "chatgpt.com"}
}

func (CodexHarness) Env(_ string) []string {
	env := []string{
		// Suppress codex's own OpenTelemetry exporter; the egress
		// proxy denies it anyway, this just keeps the log quiet.
		"RUST_LOG=error,opentelemetry_sdk=off,opentelemetry_otlp=off",
		// codex 0.142.5 also dials ab.chatgpt.com for A/B telemetry
		// on every run; the egress proxy denies it and logs a WARN
		// per scan. Disable it at source instead.
		"OMO_CODEX_SEND_ANONYMOUS_TELEMETRY=0",
		"OMO_CODEX_DISABLE_POSTHOG=1",
	}
	return append(env, passthroughEnv("CODEX_API_KEY")...)
}

func (CodexHarness) StateEnv(containerPath string) []string {
	return []string{"CODEX_HOME=" + containerPath}
}

func (CodexHarness) DefaultModels() []ModelDefault {
	// The ids are the public entries in codex's built-in catalog at the
	// version pinned in Dockerfile.runner (codex-rs/models-manager/models.json).
	// gpt-5.3-codex is first so it becomes the default; it is the
	// codex-tuned model and what `codex exec` picks when no --model is
	// given.
	return []ModelDefault{
		{Name: "GPT-5.3 Codex", ID: "gpt-5.3-codex", Tier: "high"},
		{Name: "GPT-5.4 mini", ID: "gpt-5.4-mini", Tier: "mid"},
		{Name: "GPT-5.4", ID: "gpt-5.4"},
		{Name: "GPT-5.5", ID: "gpt-5.5", Tier: "max"},
		{Name: "GPT-5.2", ID: "gpt-5.2"},
	}
}

// codexAccountPhrases are the OpenAI API account-level failures that retrying
// cannot fix until the account recovers.
var codexAccountPhrases = []string{
	"rate_limit",
	"rate limit",
	"too many requests",
	"429",
	"insufficient_quota",
	"quota exceeded",
	"invalid_api_key",
	"incorrect api key",
	"account is not active",
}

func (CodexHarness) AccountErrorText(s string) string {
	return matchAccountPhrase(s, codexAccountPhrases)
}
