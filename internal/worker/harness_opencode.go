package worker

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// OpencodeHarness drives the sst/opencode CLI in headless `opencode run`
// mode. opencode is provider-agnostic -- the model's provider determines
// which API host it dials -- so EgressHosts and Env cover the two common
// providers (Anthropic and OpenAI) plus opencode's own model registry;
// operators using another provider add its host via egress_allow.
type OpencodeHarness struct{}

func (OpencodeHarness) Binary() string { return "opencode" }

// Args builds the `opencode run` argv. Like codex, opencode discovers
// SKILL.md but does not auto-invoke it, so the prompt points at it
// explicitly. --auto suppresses interactive permission prompts (the
// container is the sandbox); --format json yields a JSONL event stream.
func (OpencodeHarness) Args(sj SkillJob, _ string, _ int, _ string) []string {
	args := []string{
		"run",
		"--format", "json",
		"--auto",
	}
	if sj.Model != "" {
		args = append(args, "--model", sj.Model)
	}
	if sj.ResumeSessionID != "" {
		args = append(args, "--session", sj.ResumeSessionID, "--replay=false")
	}
	if sj.ResumeSessionID != "" && sj.ResumePrompt != "" {
		return append(args, sj.ResumePrompt)
	}
	return append(args, opencodeSkillPrompt(sj.Name, sj.OutputFile, sj.ResumeSessionID != ""))
}

func opencodeSkillPrompt(name, outputFile string, resume bool) string {
	verb := "Follow"
	if resume {
		verb = "Continue following"
	}
	p := verb + " the instructions in ./.opencode/skill/" + name +
		"/SKILL.md against the repository cloned at ./src."
	if outputFile != "" {
		p += " Write your structured output to ./" + outputFile + " as the skill specifies."
		p += schemaValidationHint(outputFile)
	}
	return p
}

func (OpencodeHarness) ParseStream(r io.Reader, emit func(Event)) {
	br := bufio.NewReader(r)
	for {
		raw, readErr := br.ReadBytes('\n')
		if len(raw) > 0 {
			parseOpencodeLine(raw, emit)
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

// opencodeLine is the subset of `opencode run --format json` event
// fields the harness needs. The shape is {type, sessionID, ...} per
// packages/opencode/src/cli/cmd/run.ts.
type opencodeLine struct {
	Type      string          `json:"type"`
	SessionID string          `json:"sessionID"`
	Part      *opencodePart   `json:"part"`
	Error     json.RawMessage `json:"error"`
}

type opencodePart struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	Tool  string          `json:"tool"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

func parseOpencodeLine(raw []byte, emit func(Event)) {
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return
	}
	var ev opencodeLine
	if err := json.Unmarshal(raw, &ev); err != nil {
		emit(Event{Kind: KindText, Text: line})
		return
	}
	switch {
	case ev.Type == "step_start" && ev.SessionID != "":
		emit(Event{Kind: KindSession, SessionID: ev.SessionID})
	case isOpencodeToolEvent(ev):
		name := ev.Part.Tool
		if name == "" {
			name = ev.Part.Name
		}
		emit(Event{Kind: KindTool, Tool: name, Text: summariseInput(name, ev.Part.Input)})
	case ev.Type == "error" || len(ev.Error) > 0:
		emit(Event{Kind: KindError, Text: opencodeErrorText(ev.Error, line)})
	case isOpencodeTextEvent(ev):
		emit(Event{Kind: KindText, Text: ev.Part.Text})
	case ev.Type == "step_finish":
		// noise; the scan log doesn't need step boundaries
	default:
		emit(Event{Kind: KindText, Text: line})
	}
}

func isOpencodeToolEvent(ev opencodeLine) bool {
	if ev.Part == nil {
		return false
	}
	return ev.Type == "tool_use" || ev.Part.Type == "tool_use" || ev.Part.Tool != "" || ev.Part.Name != ""
}

func isOpencodeTextEvent(ev opencodeLine) bool {
	if ev.Part == nil || ev.Part.Text == "" {
		return false
	}
	return ev.Type == "text" || ev.Type == "reasoning" || ev.Part.Type == "text" || ev.Part.Type == "reasoning"
}

func opencodeErrorText(raw json.RawMessage, fallback string) string {
	if len(raw) == 0 {
		return fallback
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var e struct {
		Message string `json:"message"`
		Name    string `json:"name"`
		Code    string `json:"code"`
	}
	if err := json.Unmarshal(raw, &e); err == nil {
		for _, text := range []string{e.Message, e.Code, e.Name} {
			if text != "" {
				return text
			}
		}
	}
	return strings.TrimSpace(string(raw))
}

func (OpencodeHarness) SkillDir(workRoot, name string) string {
	return filepath.Join(workRoot, ".opencode", "skill", name)
}

func (OpencodeHarness) GuideFilename() string { return "AGENTS.md" }

func (OpencodeHarness) EgressHosts() []string {
	// opencode is provider-agnostic; cover its own model-definition
	// registry plus the two providers operators are most likely to use.
	// Anything else (Bedrock, Azure, Cloudflare, ...) goes in
	// egress_allow.
	return []string{"models.dev", "api.openai.com", "*.anthropic.com"}
}

func (OpencodeHarness) Env(baseURL string) []string {
	env := []string{
		"OPENCODE_DISABLE_AUTOUPDATE=1",
		"OPENCODE_DISABLE_MODELS_FETCH=1",
		// The container is the sandbox; opencode's own permission
		// gate would just block headless runs.
		"OPENCODE_PERMISSION=allow",
	}
	// opencode reads provider credentials from its auth config or from
	// the provider's own env var; pass through whichever the operator
	// has set so the common providers work without extra config. Same
	// T1/T13 residual as the other harnesses.
	for _, k := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OPENCODE_CONFIG_CONTENT", "OPENCODE_AUTH_CONTENT"} {
		if os.Getenv(k) != "" {
			env = append(env, k)
		}
	}
	if baseURL != "" {
		// opencode has no single base-url override; the operator sets
		// it per-provider via OPENCODE_CONFIG_CONTENT. baseURL is
		// accepted for interface symmetry and ignored.
		_ = baseURL
	}
	return env
}

func (OpencodeHarness) StateEnv(containerPath string) []string {
	return []string{
		"OPENCODE_CONFIG_DIR=" + containerPath,
		"OPENCODE_DB=" + containerPath + "/opencode.db",
	}
}

func (OpencodeHarness) AccountErrorText(s string) string {
	text := strings.TrimSpace(s)
	if text == "" {
		return ""
	}
	lower := strings.ToLower(text)
	for _, phrase := range []string{
		// opencode surfaces the underlying provider's message, so
		// match the union of the common providers' account-level
		// failure phrases.
		"rate limit", "rate_limit", "too many requests", "429",
		"usage limit", "quota", "insufficient_quota",
		"invalid_api_key", "incorrect api key",
		"credit balance", "billing",
	} {
		if strings.Contains(lower, phrase) {
			return text
		}
	}
	return ""
}
