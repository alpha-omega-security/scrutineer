package worker

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alpha-omega-security/harness"
)

// TestSkillJobToJob_PromptBytesUnchanged pins the one thing this refactor
// must not change: the prompt each harness hands the CLI is byte-identical to
// what scrutineer produced before the interface moved to the module. If this
// test starts failing after a harness-module bump, the module's default prompt
// has drifted and either scrutineer or the module needs adjusting before
// operators see different agent behaviour.
func TestSkillJobToJob_PromptBytesUnchanged(t *testing.T) {
	sj := SkillJob{Name: "audit", OutputFile: "report.json"}
	j := sj.toJob("", 0, "")
	const hint = ` To check ./report.json against ./schema.json, POST it to {scrutineer.api_base}/scans/{scrutineer.scan_id}/validate-report (header "Authorization: Bearer {scrutineer.token}", values in ./context.json); {"valid":true} means it conforms. Don't install a schema validator.`
	cases := []struct {
		name string
		h    Harness
		want string
	}{
		{"claude", ClaudeHarness{}, `Use the "audit" skill on the repository cloned at ./src. Write your structured output to ./report.json as the skill specifies.` + hint},
		{"codex", CodexHarness{}, `Follow the instructions in ./skills/audit/SKILL.md against the repository cloned at ./src. Write your structured output to ./report.json as the skill specifies.` + hint},
		{"opencode", OpencodeHarness{}, `Follow the instructions in ./.opencode/skill/audit/SKILL.md against the repository cloned at ./src. Write your structured output to ./report.json as the skill specifies.` + hint},
	}
	for _, c := range cases {
		if got := c.h.Prompt(j); got != c.want {
			t.Errorf("%s Prompt() =\n  %q\nwant\n  %q", c.name, got, c.want)
		}
	}

	resume := SkillJob{Name: "audit", OutputFile: "report.json", ResumeSessionID: "s1"}.toJob("", 0, "")
	wantResume := `Continue the "audit" skill on the repository at ./src from where you left off. Write your structured output to ./report.json as the skill specifies.` + hint
	if got := (ClaudeHarness{}).Prompt(resume); got != wantResume {
		t.Errorf("claude resume Prompt() =\n  %q\nwant\n  %q", got, wantResume)
	}
}

// TestSkillJobToJob_resolvesDefaults checks the runner-default resolution
// that used to sit in buildClaudeArgs' effectiveEffort/effectiveMaxTurns.
func TestSkillJobToJob_resolvesDefaults(t *testing.T) {
	j := SkillJob{Name: "s"}.toJob("high", 40, "https://proxy/v1")
	if j.Effort != "high" || j.MaxTurns != 40 || j.BaseURL != "https://proxy/v1" {
		t.Errorf("runner defaults not applied: %+v", j)
	}
	// Per-job values win over runner defaults.
	j = SkillJob{Name: "s", Effort: "low", MaxTurns: 5}.toJob("high", 40, "")
	if j.Effort != "low" || j.MaxTurns != 5 {
		t.Errorf("per-job overrides not applied: %+v", j)
	}
	// Built-in default when neither is set.
	j = SkillJob{Name: "s"}.toJob("", 0, "")
	if j.MaxTurns != DefaultSkillMaxTurns {
		t.Errorf("MaxTurns = %d, want DefaultSkillMaxTurns", j.MaxTurns)
	}
}

func TestClaudeHarness_SkillDir(t *testing.T) {
	got := ClaudeHarness{}.SkillDir("/work/scan-7", "deep-dive")
	want := filepath.Join("/work/scan-7", ".claude", "skills", "deep-dive")
	if got != want {
		t.Errorf("ClaudeHarness.SkillDir = %q, want %q", got, want)
	}
	if lc := (LocalClaude{}).SkillDir("/work/scan-7", "deep-dive"); lc != want {
		t.Errorf("LocalClaude.SkillDir = %q, want %q", lc, want)
	}
}

func TestContainerRunner_SkillDirDelegatesToHarness(t *testing.T) {
	claudePath := ClaudeHarness{}.SkillDir("/w", "s")
	if got := (ContainerRunner{}).SkillDir("/w", "s"); got != claudePath {
		t.Errorf("default ContainerRunner.SkillDir = %q, want claude path %q", got, claudePath)
	}
	d := ContainerRunner{Harness: stubHarness{}}
	want := filepath.Join("/w", "stub-skills", "s")
	if got := d.SkillDir("/w", "s"); got != want {
		t.Errorf("stub-harness ContainerRunner.SkillDir = %q, want %q", got, want)
	}
}

func TestContainerRunner_harnessDefaultsToClaude(t *testing.T) {
	var d ContainerRunner
	if _, ok := d.harness().(ClaudeHarness); !ok {
		t.Errorf("zero ContainerRunner harness = %T, want ClaudeHarness", d.harness())
	}
	stub := stubHarness{bin: "codex", guide: "AGENTS.md"}
	d = ContainerRunner{Harness: stub}
	if got, ok := d.harness().(stubHarness); !ok || !reflect.DeepEqual(got, stub) {
		t.Errorf("explicit harness not returned: got %T", d.harness())
	}
}

// stubHarness is a test-only Harness for exercising the container runner
// without a real backend.
type stubHarness struct {
	bin     string
	guide   string
	egress  []string
	env     []string
	state   []string
	acctErr string
}

func (s stubHarness) Binary() string                     { return s.bin }
func (s stubHarness) Args(j harness.Job) []string        { return []string{s.Prompt(j)} }
func (stubHarness) Prompt(harness.Job) string            { return "--stub" }
func (s stubHarness) ParseStream(io.Reader, func(Event)) {}
func (s stubHarness) SkillDir(wr, n string) string       { return filepath.Join(wr, "stub-skills", n) }
func (s stubHarness) GuideFilename() string              { return s.guide }
func (s stubHarness) SystemPromptViaArgs() bool          { return false }
func (s stubHarness) EgressHosts() []string              { return s.egress }
func (s stubHarness) Env(string) []string                { return s.env }
func (s stubHarness) StateEnv(string) []string           { return s.state }
func (s stubHarness) AccountErrorText(t string) string {
	if s.acctErr != "" && strings.Contains(t, s.acctErr) {
		return t
	}
	return ""
}
func (s stubHarness) DefaultModels() []ModelDefault { return nil }

func TestHarnessDefaultModels_registryEntriesAreComplete(t *testing.T) {
	// Every registered backend must supply a non-empty default model list
	// with all three tiers tagged, so a fresh install of any backend has a
	// working pick list and tier resolution without the operator setting
	// models: in config. This tripwire lives here (not upstream) because
	// scrutineer's UI depends on it; the module has its own priced-models
	// tripwire.
	for _, name := range strings.Split(HarnessNames(), ", ") {
		h, _ := HarnessByName(name)
		defs := h.DefaultModels()
		if len(defs) == 0 {
			t.Errorf("%s: DefaultModels() is empty", name)
			continue
		}
		tiers := map[string]bool{}
		for _, d := range defs {
			if d.ID == "" || d.Name == "" {
				t.Errorf("%s: entry %+v has empty Name or ID", name, d)
			}
			if d.Tier != "" {
				tiers[d.Tier] = true
			}
		}
		for _, want := range []string{"mid", "high", "max"} {
			if !tiers[want] {
				t.Errorf("%s: no DefaultModels() entry tagged Tier=%q", name, want)
			}
		}
	}
}

func TestBuildRunArgs_stateEnvFromHarness(t *testing.T) {
	d := ContainerRunner{Harness: stubHarness{state: []string{"CODEX_HOME=/harness-state", "CODEX_SQLITE_HOME=/harness-state"}}}
	got := d.buildRunArgs("img:latest", hardenedNet{}, "/data/cfg/scan-7")

	if !containsEnvFlag(got, "CODEX_HOME=/harness-state") || !containsEnvFlag(got, "CODEX_SQLITE_HOME=/harness-state") {
		t.Errorf("harness StateEnv not wired: %v", got)
	}
	if containsEnvFlag(got, "CLAUDE_CONFIG_DIR=/harness-state") {
		t.Errorf("non-claude harness leaked CLAUDE_CONFIG_DIR: %v", got)
	}
	mounted := false
	for i := 0; i+1 < len(got); i++ {
		if got[i] == "-v" && strings.HasPrefix(got[i+1], "/data/cfg/scan-7:/harness-state") {
			mounted = true
		}
	}
	if !mounted {
		t.Errorf("state dir bind mount missing: %v", got)
	}

	def := ContainerRunner{}.buildRunArgs("img:latest", hardenedNet{}, "/data/cfg/scan-7")
	if !containsEnvFlag(def, "CLAUDE_CONFIG_DIR=/harness-state") {
		t.Errorf("default harness dropped CLAUDE_CONFIG_DIR: %v", def)
	}
}

func TestBuildRunArgs_includesHarnessEnv(t *testing.T) {
	d := ContainerRunner{Harness: stubHarness{env: []string{"CODEX_API_KEY", "STUB_OPT=1"}}}
	got := d.buildRunArgs("img:latest", hardenedNet{}, "")

	if !containsEnvFlag(got, "CODEX_API_KEY") || !containsEnvFlag(got, "STUB_OPT=1") {
		t.Errorf("harness env not wired into run args: %v", got)
	}
	for _, leaked := range []string{
		"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "DISABLE_AUTOUPDATER=1",
	} {
		if containsEnvFlag(got, leaked) {
			t.Errorf("non-claude harness leaked claude env %q: %v", leaked, got)
		}
	}
	if !containsEnvFlag(got, "HOME=/tmp") || !containsEnvFlag(got, "SEMGREP_SEND_METRICS=off") {
		t.Errorf("harness-neutral env dropped: %v", got)
	}
}

func TestBuildRunArgs_defaultHarnessKeepsClaudeEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	d := ContainerRunner{ModelBaseURL: "https://proxy.corp.com/v1"}
	got := d.buildRunArgs("img:latest", hardenedNet{}, "")
	for _, want := range []string{
		"ANTHROPIC_API_KEY",
		"ANTHROPIC_BASE_URL=https://proxy.corp.com/v1",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"DISABLE_AUTOUPDATER=1",
	} {
		if !containsEnvFlag(got, want) {
			t.Errorf("default harness dropped claude env %q: %v", want, got)
		}
	}
}

func containsEnvFlag(s []string, entry string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == "-e" && s[i+1] == entry {
			return true
		}
	}
	return false
}

func TestInjectProfileGuide_writesHarnessFilename(t *testing.T) {
	profilesDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(profilesDir, "ruby"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("# Ruby scanning container\n")
	if err := os.WriteFile(filepath.Join(profilesDir, "ruby", "PROFILE.md"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	work := t.TempDir()
	d := ContainerRunner{ProfilesDir: profilesDir}
	d.injectProfileGuide("ruby", work, func(Event) {})
	if got, _ := os.ReadFile(filepath.Join(work, "CLAUDE.md")); string(got) != string(body) {
		t.Errorf("default harness wrote %q to CLAUDE.md, want %q", got, body)
	}

	work = t.TempDir()
	d = ContainerRunner{ProfilesDir: profilesDir, Harness: stubHarness{guide: "AGENTS.md"}}
	d.injectProfileGuide("ruby", work, func(Event) {})
	if got, _ := os.ReadFile(filepath.Join(work, "AGENTS.md")); string(got) != string(body) {
		t.Errorf("stub harness wrote %q to AGENTS.md, want %q", got, body)
	}
	if _, err := os.Stat(filepath.Join(work, "CLAUDE.md")); err == nil {
		t.Error("stub harness wrote CLAUDE.md, should only write its own GuideFilename")
	}
}

func TestInjectProfileGuide_noopWithoutProfile(t *testing.T) {
	work := t.TempDir()
	ContainerRunner{ProfilesDir: t.TempDir()}.injectProfileGuide("", work, func(Event) {})
	ContainerRunner{}.injectProfileGuide("ruby", work, func(Event) {})
	entries, _ := os.ReadDir(work)
	if len(entries) != 0 {
		t.Errorf("no-profile / no-profiles-dir wrote %d files, want 0", len(entries))
	}
}

// TestScrutineerValidationHint pins the exact API-endpoint text so a
// wording change is deliberate.
func TestScrutineerValidationHint(t *testing.T) {
	got := scrutineerValidationHint("report.json", "")
	if !strings.Contains(got, "{scrutineer.api_base}/scans/{scrutineer.scan_id}/validate-report") {
		t.Errorf("hint missing endpoint: %q", got)
	}
	if !strings.Contains(got, "Don't install a schema validator") {
		t.Errorf("hint missing no-install instruction: %q", got)
	}
	if scrutineerValidationHint("", "") != "" {
		t.Error("empty output file should give empty hint")
	}
}

// TestScrutineerValidationHintWithoutShell covers #834: recon declares
// allowed-tools without Bash, so the POST route it was being handed is
// unexecutable and it burned its turn budget failing at it. The hint must stay
// NON-EMPTY -- an empty ValidationHint makes the harness module substitute its
// own generic "Validate ./report.json against ./schema.json before finishing"
// for any .json output, which is the same impossible instruction with the
// don't-install guard dropped.
func TestScrutineerValidationHintWithoutShell(t *testing.T) {
	got := scrutineerValidationHint("report.json", "Read,Write,Grep,Glob")
	if got == "" {
		t.Fatal("empty hint lets the harness substitute its generic one")
	}
	if strings.Contains(got, "POST") || strings.Contains(got, "validate-report") {
		t.Errorf("shell-less skill still told to POST: %q", got)
	}
	if !strings.Contains(got, "schema.json") {
		t.Errorf("hint should still name the schema: %q", got)
	}
	if !strings.Contains(got, "don't install a schema validator") {
		t.Errorf("hint missing no-install instruction: %q", got)
	}
}

func TestToolsAllowShell(t *testing.T) {
	cases := []struct {
		tools string
		want  bool
	}{
		{"", true},                          // unrestricted
		{"   ", true},                       // unrestricted
		{"Read,Write,Bash,Grep,Glob", true}, // every bundled skill but recon
		{"Read,Write,Grep,Glob", false},     // recon
		{" read , bash ", true},             // spacing and case
		{"Read,Bash(git:*)", true},          // scoped entry
		{"Read,BashOutput", false},          // prefix must not match
	}
	for _, tc := range cases {
		if got := toolsAllowShell(tc.tools); got != tc.want {
			t.Errorf("toolsAllowShell(%q) = %v, want %v", tc.tools, got, tc.want)
		}
	}
}

// TestSkillJobPromptHonoursToolSet is the wiring half: the two tests above
// exercise the helper directly and so cannot catch a call site that never
// passes AllowedTools through. This one goes SkillJob -> toJob -> the real
// harness prompt, which is the path the agent actually receives.
func TestSkillJobPromptHonoursToolSet(t *testing.T) {
	recon := SkillJob{Name: "recon", OutputFile: "report.json", AllowedTools: "Read,Write,Grep,Glob"}
	prompt := ClaudeHarness{}.Prompt(recon.toJob("", 0, ""))
	if strings.Contains(prompt, "validate-report") {
		t.Errorf("recon prompt still carries the POST route:\n%s", prompt)
	}
	if strings.Contains(prompt, "Validate ./report.json against ./schema.json before finishing") {
		t.Errorf("recon prompt fell back to the harness generic hint:\n%s", prompt)
	}

	audit := SkillJob{Name: "audit-authz", OutputFile: "report.json", AllowedTools: "Read,Write,Bash,Grep,Glob"}
	auditPrompt := ClaudeHarness{}.Prompt(audit.toJob("", 0, ""))
	if !strings.Contains(auditPrompt, "validate-report") {
		t.Errorf("shell-capable skill lost the API route:\n%s", auditPrompt)
	}
}
