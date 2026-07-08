package worker

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestHarnessByName_opencode(t *testing.T) {
	h, err := HarnessByName("opencode")
	if err != nil {
		t.Fatalf("HarnessByName(opencode): %v", err)
	}
	if _, ok := h.(OpencodeHarness); !ok {
		t.Errorf("HarnessByName(opencode) = %T, want OpencodeHarness", h)
	}
	if !strings.Contains(HarnessNames(), "opencode") {
		t.Errorf("HarnessNames() = %q, want opencode listed", HarnessNames())
	}
}

func TestOpencodeHarness_seamConstants(t *testing.T) {
	h := OpencodeHarness{}
	if h.Binary() != "opencode" {
		t.Errorf("Binary() = %q, want opencode", h.Binary())
	}
	if h.GuideFilename() != "AGENTS.md" {
		t.Errorf("GuideFilename() = %q, want AGENTS.md", h.GuideFilename())
	}
	wantDir := filepath.Join("/work/scan-7", ".opencode", "skill", "deep-dive")
	if got := h.SkillDir("/work/scan-7", "deep-dive"); got != wantDir {
		t.Errorf("SkillDir = %q, want %q", got, wantDir)
	}
	wantState := []string{"OPENCODE_CONFIG_DIR=/claude-config", "OPENCODE_DB=/claude-config/opencode.db"}
	if got := h.StateEnv("/claude-config"); !reflect.DeepEqual(got, wantState) {
		t.Errorf("StateEnv = %v, want %v", got, wantState)
	}
	if !slices.Contains(h.EgressHosts(), "models.dev") {
		t.Errorf("EgressHosts() = %v, want models.dev included", h.EgressHosts())
	}
}

func TestOpencodeHarness_Args(t *testing.T) {
	h := OpencodeHarness{}
	got := h.Args(SkillJob{Name: "deep-dive", Model: "anthropic/claude-sonnet-4-6", OutputFile: "report.json"}, "high", 30, "https://ignored")

	for _, want := range []string{"run", "--auto"} {
		if !slices.Contains(got, want) {
			t.Errorf("Args missing %q: %v", want, got)
		}
	}
	if i := slices.Index(got, "--format"); i < 0 || got[i+1] != "json" {
		t.Errorf("Args missing --format json: %v", got)
	}
	if i := slices.Index(got, "--model"); i < 0 || got[i+1] != "anthropic/claude-sonnet-4-6" {
		t.Errorf("Args missing --model: %v", got)
	}
	prompt := got[len(got)-1]
	if !strings.Contains(prompt, "./.opencode/skill/deep-dive/SKILL.md") || !strings.Contains(prompt, "./src") {
		t.Errorf("activation prompt does not point at the staged skill: %q", prompt)
	}
	if !strings.Contains(prompt, "./report.json") {
		t.Errorf("activation prompt does not name the output file: %q", prompt)
	}
	if slices.Contains(got, "--session") {
		t.Errorf("non-resume run included --session: %v", got)
	}
}

func TestOpencodeHarness_ArgsResume(t *testing.T) {
	h := OpencodeHarness{}
	got := h.Args(SkillJob{Name: "deep-dive", ResumeSessionID: "ses-7"}, "", 0, "")
	if i := slices.Index(got, "--session"); i < 0 || got[i+1] != "ses-7" {
		t.Errorf("resume args missing '--session ses-7': %v", got)
	}
	if !strings.Contains(got[len(got)-1], "Continue") {
		t.Errorf("resume prompt does not say continue: %q", got[len(got)-1])
	}

	got = h.Args(SkillJob{Name: "deep-dive", ResumeSessionID: "ses-7", ResumePrompt: "fix the report"}, "", 0, "")
	if got[len(got)-1] != "fix the report" {
		t.Errorf("explicit ResumePrompt not used: %q", got[len(got)-1])
	}
}

func TestOpencodeHarness_Env(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("OPENCODE_CONFIG_CONTENT", "")
	got := OpencodeHarness{}.Env("https://ignored")
	for _, want := range []string{"OPENCODE_DISABLE_AUTOUPDATE=true", "OPENCODE_DISABLE_MODELS_FETCH=true", "OPENCODE_DISABLE_SHARE=true", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"} {
		if !slices.Contains(got, want) {
			t.Errorf("Env() missing %q: %v", want, got)
		}
	}
	if slices.Contains(got, "OPENCODE_CONFIG_CONTENT") {
		t.Errorf("Env() included unset OPENCODE_CONFIG_CONTENT: %v", got)
	}
	for _, e := range got {
		if strings.Contains(e, "https://ignored") {
			t.Errorf("Env() set a base URL when opencode has none: %v", got)
		}
	}
}

func TestOpencodeHarness_AccountErrorText(t *testing.T) {
	h := OpencodeHarness{}
	for in, want := range map[string]bool{
		"Error: rate_limit_exceeded": true,
		"usage limit reached":        true,
		"insufficient_quota":         true,
		"invalid_api_key":            true,
		"compiling skill":            false,
		"":                           false,
	} {
		got := h.AccountErrorText(in)
		if want && got == "" {
			t.Errorf("AccountErrorText(%q) = empty, want non-empty", in)
		}
		if !want && got != "" {
			t.Errorf("AccountErrorText(%q) = %q, want empty", in, got)
		}
	}
}

func TestOpencodeHarness_ParseStream(t *testing.T) {
	// Fixture matches `opencode run --format json` at v1.17.12 (packages/
	// opencode/src/cli/cmd/run.ts): tool input nests under part.state,
	// part.type is "tool" not "tool_use", provider errors nest the message
	// under error.data.message, and step_finish carries cost + tokens.
	in := `{"type":"step_start","sessionID":"ses-1"}
{"type":"text","part":{"type":"text","text":"hello"}}
{"type":"reasoning","part":{"type":"reasoning","text":"thinking"}}
{"type":"tool","part":{"type":"tool","tool":"bash","state":{"status":"completed","input":{"command":"ls"}}}}
{"type":"error","error":{"name":"ProviderAuthError","data":{"message":"insufficient_quota: exceeded"}}}
{"type":"step_finish","cost":0.0123,"tokens":{"input":100,"output":40,"reasoning":10,"cache":{"read":20,"write":5}}}
not json
`
	var got []Event
	OpencodeHarness{}.ParseStream(strings.NewReader(in), func(e Event) { got = append(got, e) })

	var sessions, texts, tools, errs, results int
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
		case KindResult:
			results++
		}
	}
	if sessions != 1 || got[0].SessionID != "ses-1" {
		t.Errorf("session event not extracted: %v", got)
	}
	if tools != 1 || got[3].Tool != "bash" || !strings.Contains(got[3].Text, "ls") {
		t.Errorf("tool event not mapped from part.state.input: %v", got[3])
	}
	if errs != 1 || got[4].Text != "insufficient_quota: exceeded" {
		t.Errorf("error text not read from error.data.message: %q", got[4].Text)
	}
	if (OpencodeHarness{}).AccountErrorText(got[4].Text) == "" {
		t.Errorf("parsed error text %q not recognised as account error", got[4].Text)
	}
	if results != 1 || got[5].CostUSD != 0.0123 {
		t.Errorf("step_finish not mapped to result: %+v", got[5])
	}
	wantUsage := Usage{InputTokens: 100, OutputTokens: 50, CacheReadTokens: 20, CacheWriteTokens: 5}
	if got[5].Usage != wantUsage {
		t.Errorf("Usage = %+v, want %+v (reasoning folded into output)", got[5].Usage, wantUsage)
	}
	// "hello", "thinking", and the non-JSON line.
	if texts != 3 || got[1].Text != "hello" || got[2].Text != "thinking" {
		t.Errorf("text events = %d, want 3: %v", texts, got)
	}
}

func TestOpencodeHarness_DefaultModelsUseProviderPrefix(t *testing.T) {
	defs := OpencodeHarness{}.DefaultModels()
	if len(defs) == 0 {
		t.Fatal("DefaultModels() is empty")
	}
	for _, d := range defs {
		if !strings.HasPrefix(d.ID, "anthropic/") {
			t.Errorf("model id %q lacks provider/ prefix; opencode --model needs it", d.ID)
		}
		if _, ok := modelPricing[normalizeModelID(d.ID)]; !ok {
			t.Errorf("model id %q not priced after normalizeModelID", d.ID)
		}
	}
}
