package worker

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CodexHarness drives OpenAI's codex CLI in headless `codex exec` mode.
// It maps the nine Harness seams onto codex's conventions: SKILL.md
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
		// scrutineer's container already drops caps, runs non-root,
		// mounts the workspace, and gates egress through the proxy;
		// codex's own sandbox would only fight that. workspace-write
		// is the lightest mode that still lets codex edit /work.
		"--sandbox", "workspace-write",
		"--skip-git-repo-check",
	)
	if sj.Model != "" {
		args = append(args, "--model", sj.Model)
	}
	if sj.ResumeSessionID != "" {
		args = append(args, "resume", sj.ResumeSessionID)
	}
	if sj.ResumeSessionID != "" && sj.ResumePrompt != "" {
		return append(args, sj.ResumePrompt)
	}
	return append(args, codexSkillPrompt(sj.Name, sj.OutputFile, sj.ResumeSessionID != ""))
}

// codexSkillPrompt is the activation prompt for a codex run. codex
// discovers ./skills/{name}/SKILL.md but does not auto-invoke it, so
// the prompt points at it explicitly and restates the deliverable.
func codexSkillPrompt(name, outputFile string, resume bool) string {
	verb := "Follow"
	if resume {
		verb = "Continue following"
	}
	p := verb + " the instructions in ./skills/" + name +
		"/SKILL.md against the repository cloned at ./src."
	if outputFile != "" {
		p += " Write your structured output to ./" + outputFile + " as the skill specifies."
		p += schemaValidationHint(outputFile)
	}
	return p
}

// ParseStream reads `codex exec --json` JSONL output. The event shapes
// codex emits are mapped onto the harness-neutral Event vocabulary:
// thread/session announcements become KindSession (so resume works),
// agent text becomes KindText, tool calls become KindTool, and anything
// else -- including non-JSON lines codex writes to stderr -- passes
// through as KindText so nothing is silently dropped. codex has no
// max-turns cap, so no "hit max turns" event is emitted.
func (CodexHarness) ParseStream(r io.Reader, emit func(Event)) {
	br := bufio.NewReader(r)
	for {
		raw, readErr := br.ReadBytes('\n')
		if len(raw) > 0 {
			parseCodexLine(raw, emit)
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil {
			emit(Event{Kind: KindError, Text: "stream read: " + readErr.Error()})
			return
		}
	}
}

// codexLine is the subset of `codex exec --json` event fields the
// harness needs. Unknown types fall through to KindText so the scan
// log still shows them; refine as the format is exercised against a
// real codex run.
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
}

type codexItem struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Command string          `json:"command"`
	Tool    string          `json:"tool"`
	Name    string          `json:"name"`
	Input   json.RawMessage `json:"input"`
}

func parseCodexLine(raw []byte, emit func(Event)) {
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return
	}
	var ev codexLine
	if err := json.Unmarshal(raw, &ev); err != nil {
		emit(Event{Kind: KindText, Text: line})
		return
	}
	switch {
	case ev.SessionID != "" || ev.ThreadID != "":
		id := ev.SessionID
		if id == "" {
			id = ev.ThreadID
		}
		emit(Event{Kind: KindSession, SessionID: id})
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
	}
	// Same T1/T13 residual as claude: forwarding the host credential
	// into the container exposes it to in-container code.
	if os.Getenv("CODEX_API_KEY") != "" {
		env = append(env, "CODEX_API_KEY")
	}
	return env
}

func (CodexHarness) StateEnv(containerPath string) []string {
	return []string{"CODEX_HOME=" + containerPath}
}

func (CodexHarness) AccountErrorText(s string) string {
	text := strings.TrimSpace(s)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, phrase := range []string{
		// OpenAI API account-level failures that retrying cannot fix
		// until the account recovers.
		"rate_limit",
		"rate limit",
		"too many requests",
		"429",
		"insufficient_quota",
		"quota exceeded",
		"invalid_api_key",
		"incorrect api key",
		"account is not active",
		"billing",
	} {
		if strings.Contains(lower, phrase) {
			return text
		}
	}
	return ""
}
