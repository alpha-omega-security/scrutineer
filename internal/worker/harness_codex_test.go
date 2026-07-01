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
	if got := h.StateEnv("/claude-config"); !reflect.DeepEqual(got, []string{"CODEX_HOME=/claude-config"}) {
		t.Errorf("StateEnv = %v, want CODEX_HOME=/claude-config", got)
	}
	if !slices.Contains(h.EgressHosts(), "api.openai.com") {
		t.Errorf("EgressHosts() = %v, want api.openai.com included", h.EgressHosts())
	}
}

func TestCodexHarness_Args(t *testing.T) {
	h := CodexHarness{}
	got := h.Args(SkillJob{Name: "deep-dive", Model: "gpt-5", OutputFile: "report.json"}, "high", 30, "https://proxy.corp.com/v1")

	for _, want := range []string{"exec", "-c", `openai_base_url="https://proxy.corp.com/v1"`, "--json", "--sandbox", "workspace-write", "--skip-git-repo-check"} {
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
	for _, want := range []string{"CODEX_API_KEY"} {
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

func TestCodexHarness_ParseStream(t *testing.T) {
	in := `{"type":"init","session_id":"sess-1"}
	{"thread_id":"thr-2"}
	{"type":"text","text":"hello"}
	{"message":"working"}
	{"type":"tool","tool":"bash","input":{"command":"ls"}}
	{"type":"item.started","item":{"id":"item_1","type":"command_execution","command":"bash -lc ls","status":"in_progress"}}
	{"type":"item.completed","item":{"id":"item_2","type":"agent_message","text":"done"}}
	{"error":"rate_limit_exceeded"}
	not json
	`
	var got []Event
	CodexHarness{}.ParseStream(strings.NewReader(in), func(e Event) { got = append(got, e) })

	var sessions, texts, tools, errs int
	for _, e := range got {
		switch e.Kind {
		case KindSession:
			sessions++
		case KindText:
			texts++
		case KindTool:
			tools++
		case KindError:
			errs++
		}
	}
	if sessions != 2 {
		t.Errorf("session events = %d, want 2 (session_id and thread_id both map): %v", sessions, got)
	}
	if got[0].SessionID != "sess-1" || got[1].SessionID != "thr-2" {
		t.Errorf("session ids not extracted: %v", got)
	}
	if tools != 2 || got[4].Tool != "bash" || got[5].Tool != "command" || got[5].Text != "bash -lc ls" {
		t.Errorf("tool event not mapped: %v", got)
	}
	if errs != 1 || got[7].Text != "rate_limit_exceeded" {
		t.Errorf("error event not mapped: %v", got)
	}
	// "hello", "working", "done", and the non-JSON line all pass through as text.
	if texts != 4 {
		t.Errorf("text events = %d, want 4: %v", texts, got)
	}
}
