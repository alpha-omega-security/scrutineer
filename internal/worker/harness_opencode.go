package worker

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
)

// OpencodeHarness drives the anomalyco/opencode CLI in headless `opencode run`
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
		args = append(args, "--session", sj.ResumeSessionID)
	}
	return append(args, explicitSkillPrompt(sj, "./.opencode/skill/"+sj.Name))
}

func (OpencodeHarness) ParseStream(r io.Reader, emit func(Event)) {
	scanJSONL(r, emit, parseOpencodeLine)
}

// opencodeLine is the subset of `opencode run --format json` event
// fields the harness needs. The shape is {type, sessionID, part} per
// packages/opencode/src/cli/cmd/run.ts; every payload nests under part.
type opencodeLine struct {
	Type      string          `json:"type"`
	SessionID string          `json:"sessionID"`
	Part      *opencodePart   `json:"part"`
	Error     json.RawMessage `json:"error"`
}

type opencodePart struct {
	Type  string            `json:"type"`
	Text  string            `json:"text"`
	Tool  string            `json:"tool"`
	Name  string            `json:"name"`
	State opencodeToolState `json:"state"`
	// step_finish (part.type "step-finish") carries per-step cost and
	// token counts here, not at the event top level.
	Cost   float64         `json:"cost"`
	Tokens *opencodeTokens `json:"tokens"`
}

type opencodeToolState struct {
	Input json.RawMessage `json:"input"`
}

type opencodeTokens struct {
	Input     int `json:"input"`
	Output    int `json:"output"`
	Reasoning int `json:"reasoning"`
	Cache     struct {
		Read  int `json:"read"`
		Write int `json:"write"`
	} `json:"cache"`
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
		emit(Event{Kind: KindTool, Tool: name, Text: summariseInput(name, ev.Part.State.Input)})
	case ev.Type == "error" || len(ev.Error) > 0:
		emit(Event{Kind: KindError, Text: opencodeErrorText(ev.Error, line)})
	case isOpencodeTextEvent(ev):
		emit(Event{Kind: KindText, Text: ev.Part.Text})
	case ev.Type == "step_finish" && ev.Part != nil:
		emit(Event{Kind: KindResult, CostUSD: ev.Part.Cost, Turns: 1, Usage: opencodeUsage(ev.Part.Tokens)})
	case ev.Type == "step_finish":
		// no part: nothing to record, but drop it rather than dump raw JSON
	default:
		emit(Event{Kind: KindText, Text: line})
	}
}

func opencodeUsage(t *opencodeTokens) Usage {
	if t == nil {
		return Usage{}
	}
	// opencode reports reasoning tokens separately; the scan row only
	// tracks input/output/cache, so fold reasoning into output for the
	// per-scan total.
	return Usage{
		InputTokens:      t.Input,
		OutputTokens:     t.Output + t.Reasoning,
		CacheReadTokens:  t.Cache.Read,
		CacheWriteTokens: t.Cache.Write,
	}
}

func isOpencodeToolEvent(ev opencodeLine) bool {
	if ev.Part == nil {
		return false
	}
	return ev.Type == "tool" || ev.Part.Type == "tool" || ev.Part.Tool != "" || ev.Part.Name != ""
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
		// opencode's typed provider errors nest the provider's own
		// message under data (ProviderAuthError, APIError, ...); that is
		// where "rate limit"/"quota" phrases live, so prefer it.
		Data struct {
			Message string `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &e); err == nil {
		for _, text := range []string{e.Data.Message, e.Message, e.Code, e.Name} {
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

// Env returns opencode's container environment. baseURL is accepted for
// interface symmetry and ignored: opencode has no single base-url
// override; the operator sets it per-provider via OPENCODE_CONFIG_CONTENT.
func (OpencodeHarness) Env(_ string) []string {
	// --auto (see Args) grants tool permissions in headless mode; the
	// container is the sandbox. OPENCODE_PERMISSION is not set because
	// opencode JSON-parses it and there is no scalar "allow all" value.
	env := []string{
		"OPENCODE_DISABLE_AUTOUPDATE=true",
		"OPENCODE_DISABLE_MODELS_FETCH=true",
		"OPENCODE_DISABLE_SHARE=true",
	}
	// opencode reads provider credentials from its auth config or from
	// the provider's own env var; pass through whichever the operator
	// has set so the common providers work without extra config.
	return append(env, passthroughEnv(
		"OPENAI_API_KEY", "ANTHROPIC_API_KEY",
		"OPENCODE_CONFIG_CONTENT", "OPENCODE_AUTH_CONTENT",
	)...)
}

func (OpencodeHarness) StateEnv(containerPath string) []string {
	return []string{
		"OPENCODE_CONFIG_DIR=" + containerPath,
		"OPENCODE_DB=" + containerPath + "/opencode.db",
	}
}

func (OpencodeHarness) DefaultModels() []ModelDefault {
	// opencode is provider-agnostic; it drives whichever provider the
	// operator's OPENCODE_CONFIG_CONTENT / auth config points at. The
	// default matches the credentials Env passes through with no extra
	// config: with ANTHROPIC_API_KEY set, opencode drives Anthropic. IDs
	// are in opencode's provider/model form; --model without the prefix
	// fails resolution. normalizeModelID strips the prefix for the
	// pricing lookup so the table needs no per-provider copies.
	defs := ClaudeHarness{}.DefaultModels()
	out := make([]ModelDefault, len(defs))
	for i, d := range defs {
		out[i] = ModelDefault{Name: d.Name, ID: "anthropic/" + d.ID, Tier: d.Tier}
	}
	return out
}

// opencodeAccountPhrases: opencode surfaces the underlying provider's own
// error message, so this covers the union of the common providers'
// account-level failure phrases.
var opencodeAccountPhrases = []string{
	"rate limit", "rate_limit", "too many requests", "429",
	"usage limit", "quota", "insufficient_quota",
	"invalid_api_key", "incorrect api key", "invalid x-api-key",
	"credit balance", "billing",
}

func (OpencodeHarness) AccountErrorText(s string) string {
	return matchAccountPhrase(s, opencodeAccountPhrases)
}
