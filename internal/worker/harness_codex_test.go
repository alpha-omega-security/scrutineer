package worker

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestHarnessByName(t *testing.T) {
	for _, name := range []string{"", "claude", "Claude"} {
		h, err := HarnessByName(name)
		if err != nil {
			t.Fatalf("HarnessByName(%q): %v", name, err)
		}
		if _, ok := h.(ClaudeHarness); !ok {
			t.Errorf("HarnessByName(%q) = %T, want ClaudeHarness", name, h)
		}
	}
	h, err := HarnessByName("codex")
	if err != nil {
		t.Fatalf("HarnessByName(codex): %v", err)
	}
	if _, ok := h.(CodexHarness); !ok {
		t.Errorf("HarnessByName(codex) = %T, want CodexHarness", h)
	}
	if _, err := HarnessByName("nope"); err == nil {
		t.Error("HarnessByName(nope) returned no error")
	} else if !strings.Contains(err.Error(), "claude") || !strings.Contains(err.Error(), "codex") {
		t.Errorf("unknown-backend error %q does not list valid names", err)
	}
}

func TestHarnessName(t *testing.T) {
	if got := HarnessName(ClaudeHarness{}); got != "claude" {
		t.Errorf("HarnessName(ClaudeHarness) = %q, want claude", got)
	}
	if got := HarnessName(CodexHarness{}); got != "codex" {
		t.Errorf("HarnessName(CodexHarness) = %q, want codex", got)
	}
}

func TestHarnessNames(t *testing.T) {
	got := HarnessNames()
	if !strings.Contains(got, "claude") || !strings.Contains(got, "codex") {
		t.Errorf("HarnessNames() = %q, want both claude and codex listed", got)
	}
	if strings.HasPrefix(got, ",") || strings.Contains(got, ", ,") {
		t.Errorf("HarnessNames() = %q, empty default alias should not appear", got)
	}
}

func TestCodexHarness_seamConstants(t *testing.T) {
	h := CodexHarness{}
	if h.Binary() != "codex" {
		t.Errorf("Binary() = %q, want codex", h.Binary())
	}
	if h.GuideFilename() != "AGENTS.md" {
		t.Errorf("GuideFilename() = %q, want AGENTS.md", h.GuideFilename())
	}
	wantDir := filepath.Join("/work/scan-7", "skills", "deep-dive")
	if got := h.SkillDir("/work/scan-7", "deep-dive"); got != wantDir {
		t.Errorf("SkillDir = %q, want %q", got, wantDir)
	}
	if got := h.StateEnv("/harness-state"); !reflect.DeepEqual(got, []string{"CODEX_HOME=/harness-state"}) {
		t.Errorf("StateEnv = %v, want CODEX_HOME=/harness-state", got)
	}
	if !slices.Contains(h.EgressHosts(), "api.openai.com") {
		t.Errorf("EgressHosts() = %v, want api.openai.com included", h.EgressHosts())
	}
}

func TestCodexHarness_Args(t *testing.T) {
	h := CodexHarness{}
	got := h.Args(SkillJob{Name: "deep-dive", Model: "gpt-5", OutputFile: "report.json"}, "high", 30, "https://proxy.corp.com/v1")

	for _, want := range []string{"exec", "-c", `openai_base_url="https://proxy.corp.com/v1"`, "--json", "--sandbox", "danger-full-access", "--skip-git-repo-check"} {
		if !slices.Contains(got, want) {
			t.Errorf("Args missing %q: %v", want, got)
		}
	}
	if i := slices.Index(got, "--model"); i < 0 || got[i+1] != "gpt-5" {
		t.Errorf("Args missing --model gpt-5: %v", got)
	}
	prompt := got[len(got)-1]
	if !strings.Contains(prompt, "./skills/deep-dive/SKILL.md") || !strings.Contains(prompt, "./src") {
		t.Errorf("activation prompt does not point at the staged skill: %q", prompt)
	}
	if !strings.Contains(prompt, "./report.json") {
		t.Errorf("activation prompt does not name the output file: %q", prompt)
	}
	if slices.Contains(got, "resume") {
		t.Errorf("non-resume run included resume subcommand: %v", got)
	}
}

func TestCodexHarness_ArgsResume(t *testing.T) {
	h := CodexHarness{}
	got := h.Args(SkillJob{Name: "deep-dive", ResumeSessionID: "thr-7"}, "", 0, "")
	if i := slices.Index(got, "resume"); i < 0 || got[i+1] != "thr-7" {
		t.Errorf("resume args missing 'resume thr-7': %v", got)
	}
	if !strings.Contains(got[len(got)-1], "Continue") {
		t.Errorf("resume prompt does not say continue: %q", got[len(got)-1])
	}

	// An explicit ResumePrompt (e.g. the schema-repair nudge) replaces
	// the default continue prompt.
	got = h.Args(SkillJob{Name: "deep-dive", ResumeSessionID: "thr-7", ResumePrompt: "fix the report"}, "", 0, "")
	if got[len(got)-1] != "fix the report" {
		t.Errorf("explicit ResumePrompt not used: %q", got[len(got)-1])
	}
}

func TestCodexHarness_Env(t *testing.T) {
	t.Setenv("CODEX_API_KEY", "sk-test")
	got := CodexHarness{}.Env("https://proxy.corp.com/v1")
	for _, want := range []string{"CODEX_API_KEY", "OMO_CODEX_SEND_ANONYMOUS_TELEMETRY=0", "OMO_CODEX_DISABLE_POSTHOG=1"} {
		if !slices.Contains(got, want) {
			t.Errorf("Env() missing %q: %v", want, got)
		}
	}
	for _, leaked := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"} {
		if slices.Contains(got, leaked) {
			t.Errorf("codex Env() leaked claude credential %q: %v", leaked, got)
		}
	}

	t.Setenv("CODEX_API_KEY", "")
	got = CodexHarness{}.Env("")
	if slices.Contains(got, "CODEX_API_KEY") {
		t.Errorf("Env() included unset CODEX_API_KEY: %v", got)
	}
	for _, e := range got {
		if strings.HasPrefix(e, "OPENAI_BASE_URL=") || strings.HasPrefix(e, "openai_base_url=") {
			t.Errorf("Env() set base URL with none configured: %v", got)
		}
	}
}

func TestCodexHarness_AccountErrorText(t *testing.T) {
	h := CodexHarness{}
	for in, want := range map[string]bool{
		"Error: rate_limit_exceeded":          true,
		"429 Too Many Requests":               true,
		"insufficient_quota for this account": true,
		"invalid_api_key provided":            true,
		"repo mentions billing integrations":  false,
		"compiling skill":                     false,
		"":                                    false,
	} {
		got := h.AccountErrorText(in)
		if want && got == "" {
			t.Errorf("AccountErrorText(%q) = empty, want non-empty (account-level)", in)
		}
		if !want && got != "" {
			t.Errorf("AccountErrorText(%q) = %q, want empty", in, got)
		}
	}
}

// TestCodexHarness_ParseStream_live locks the parser against a fixture
// captured from a real `codex exec --json` run at codex-cli 0.142.5, plus
// the error item shape codex emits for an unknown model id. The mapping
// verified here — one KindTool per command (item.started dropped),
// item.type=="error" as KindError, turn.started dropped, turn.completed as
// KindResult with usage — is what the PR body flagged for live verification.
func TestCodexHarness_ParseStream_live(t *testing.T) {
	in := `{"type":"thread.started","thread_id":"019f239d-99d0-7fa2-a42a-f4fac6a06a96"}
{"type":"item.completed","item":{"id":"item_0","type":"error","message":"Model metadata for x not found."}}
{"type":"turn.started"}
{"type":"item.completed","item":{"id":"item_1","type":"agent_message","text":"listing"}}
{"type":"item.started","item":{"id":"item_2","type":"command_execution","command":"/bin/bash -lc 'ls ./src'","aggregated_output":"","exit_code":null,"status":"in_progress"}}
{"type":"item.completed","item":{"id":"item_2","type":"command_execution","command":"/bin/bash -lc 'ls ./src'","aggregated_output":"README.md\n","exit_code":0,"status":"completed"}}
{"type":"item.completed","item":{"id":"item_3","type":"agent_message","text":"done"}}
{"type":"turn.completed","usage":{"input_tokens":17339,"cached_input_tokens":11008,"output_tokens":92,"reasoning_output_tokens":23}}
`
	want := []Event{
		{Kind: KindSession, SessionID: "019f239d-99d0-7fa2-a42a-f4fac6a06a96"},
		{Kind: KindError, Text: "Model metadata for x not found."},
		// turn.started dropped
		{Kind: KindText, Text: "listing"},
		// item.started dropped: item.completed for the same command follows
		{Kind: KindTool, Tool: "command", Text: "/bin/bash -lc 'ls ./src'"},
		{Kind: KindText, Text: "done"},
		{Kind: KindResult, Turns: 1, Usage: Usage{InputTokens: 17339, OutputTokens: 92, CacheReadTokens: 11008}},
	}
	var got []Event
	CodexHarness{}.ParseStream(strings.NewReader(in), func(e Event) { got = append(got, e) })
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseStream mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

// TestCodexHarness_ParseStream_fallthrough covers shapes not seen in the
// live capture but that the parser is permissive about: a session_id key,
// top-level text/message/tool/error, and a non-JSON line. These keep the
// scan log readable if codex's format shifts.
func TestCodexHarness_ParseStream_fallthrough(t *testing.T) {
	in := `Reading additional input from stdin...
{"type":"init","session_id":"sess-1"}
{"type":"text","text":"hello"}
{"message":"working"}
{"type":"tool","tool":"bash","input":{"command":"ls"}}
{"error":"rate_limit_exceeded"}
not json
`
	var got []Event
	CodexHarness{}.ParseStream(strings.NewReader(in), func(e Event) { got = append(got, e) })

	kinds := make([]string, len(got))
	for i, e := range got {
		kinds[i] = e.Kind
	}
	wantKinds := []string{KindSession, KindText, KindText, KindTool, KindError, KindText}
	if !reflect.DeepEqual(kinds, wantKinds) {
		t.Errorf("kinds = %v, want %v: %+v", kinds, wantKinds, got)
	}
	if got[0].SessionID != "sess-1" {
		t.Errorf("session_id not extracted: %+v", got[0])
	}
	if got[3].Tool != "bash" {
		t.Errorf("top-level tool not mapped: %+v", got[3])
	}
	if got[4].Text != "rate_limit_exceeded" {
		t.Errorf("top-level error not mapped: %+v", got[4])
	}
	if got[5].Text != "not json" {
		t.Errorf("non-JSON line not passed through: %+v", got[5])
	}
}
