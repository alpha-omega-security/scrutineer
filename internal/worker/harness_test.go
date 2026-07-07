package worker

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestClaudeHarness_argsMatchBuildClaudeArgs(t *testing.T) {
	// ClaudeHarness.Args must be byte-for-byte identical to the function
	// it wraps so introducing the seam is a no-behaviour-change refactor.
	// The buildClaudeArgs table tests in claude_test.go cover the argv
	// shape; this just proves the harness delegates to them.
	for _, sj := range []SkillJob{
		{Name: "deep-dive", Model: "m"},
		{Name: "deep-dive", Model: "m", AllowedTools: "Read,Write", Effort: "low", MaxTurns: 7},
		{Name: "deep-dive", Model: "m", ResumeSessionID: "sess-1", OutputFile: "report.json"},
	} {
		got := ClaudeHarness{}.Args(sj, "high", 30, "https://proxy.corp.com/v1")
		want := buildClaudeArgs(sj, "high", 30)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ClaudeHarness.Args(%+v) = %v, want %v", sj, got, want)
		}
	}
}

func TestClaudeHarness_parseStreamMatchesParseStream(t *testing.T) {
	// Same delegation guarantee for the stream parser: the harness
	// method must emit exactly what the package function does, so the
	// scan log, session capture and max-turns signal are unchanged.
	in := `{"type":"system","subtype":"init","session_id":"sess-1"}
{"type":"assistant","message":{"content":[{"type":"text","text":"hello"}]}}
not json
`
	var viaHarness, viaFunc []Event
	ClaudeHarness{}.ParseStream(strings.NewReader(in), func(e Event) { viaHarness = append(viaHarness, e) })
	ParseStream(strings.NewReader(in), func(e Event) { viaFunc = append(viaFunc, e) })
	if !reflect.DeepEqual(viaHarness, viaFunc) {
		t.Errorf("ClaudeHarness.ParseStream emitted %v, want %v", viaHarness, viaFunc)
	}
}

func TestClaudeHarness_SkillDir(t *testing.T) {
	// claude-code discovers skills at ./.claude/skills/{name}; this is
	// the path stageSkill has always written to, so the seam preserves
	// it exactly.
	got := ClaudeHarness{}.SkillDir("/work/scan-7", "deep-dive")
	want := filepath.Join("/work/scan-7", ".claude", "skills", "deep-dive")
	if got != want {
		t.Errorf("ClaudeHarness.SkillDir = %q, want %q", got, want)
	}
	// LocalClaude is claude-only and must agree.
	if lc := (LocalClaude{}).SkillDir("/work/scan-7", "deep-dive"); lc != want {
		t.Errorf("LocalClaude.SkillDir = %q, want %q", lc, want)
	}
}

func TestContainerRunner_SkillDirDelegatesToHarness(t *testing.T) {
	// The runner exposes SkillDir on SkillRunner so the worker can stage
	// SKILL.md before calling RunSkill; it must delegate to whatever
	// harness is configured and default to claude when none is.
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

func TestClaudeHarness_binaryGuideEgress(t *testing.T) {
	h := ClaudeHarness{}
	if h.Binary() != "claude" {
		t.Errorf("Binary() = %q, want claude", h.Binary())
	}
	if h.GuideFilename() != "CLAUDE.md" {
		t.Errorf("GuideFilename() = %q, want CLAUDE.md", h.GuideFilename())
	}
	want := []string{"*.anthropic.com"}
	if got := h.EgressHosts(); !reflect.DeepEqual(got, want) {
		t.Errorf("EgressHosts() = %v, want %v", got, want)
	}
}

func TestContainerRunner_harnessDefaultsToClaude(t *testing.T) {
	// The zero ContainerRunner{} must keep exec'ing claude so no caller
	// needs to set the field until a second harness exists.
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

// stubHarness is a test-only Harness for exercising the seam without a
// real second implementation. The set of harnesses is open-ended; this
// stands in for any of them.
type stubHarness struct {
	bin     string
	guide   string
	egress  []string
	env     []string
	state   []string
	acctErr string
}

func (s stubHarness) Binary() string                              { return s.bin }
func (s stubHarness) Args(SkillJob, string, int, string) []string { return []string{"--stub"} }
func (s stubHarness) ParseStream(io.Reader, func(Event))          {}
func (s stubHarness) SkillDir(wr, n string) string                { return filepath.Join(wr, "stub-skills", n) }
func (s stubHarness) GuideFilename() string                       { return s.guide }
func (s stubHarness) EgressHosts() []string                       { return s.egress }
func (s stubHarness) Env(string) []string                         { return s.env }
func (s stubHarness) StateEnv(string) []string                    { return s.state }
func (s stubHarness) AccountErrorText(t string) string {
	if s.acctErr != "" && strings.Contains(t, s.acctErr) {
		return t
	}
	return ""
}
func (s stubHarness) DefaultModels() []ModelDefault { return nil }

func TestHarnessDefaultModels_registryEntriesAreComplete(t *testing.T) {
	// Every registered harness must supply a non-empty default model
	// list with all three tiers tagged, so a fresh install of any
	// backend has a working pick list and tier resolution without the
	// operator setting models: in config.
	for name, h := range harnesses {
		if name == "" {
			continue
		}
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

func TestClaudeHarness_StateEnv(t *testing.T) {
	got := ClaudeHarness{}.StateEnv("/harness-state")
	want := []string{"CLAUDE_CONFIG_DIR=/harness-state"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("StateEnv(/harness-state) = %v, want %v", got, want)
	}
}

func TestClaudeHarness_AccountErrorTextDelegates(t *testing.T) {
	// The harness method must classify exactly as the package function
	// does so the queue-pause behaviour is unchanged.
	for _, s := range []string{
		"Error: Claude usage limit reached",
		"429 too many requests",
		"this is fine",
		"",
	} {
		if got, want := (ClaudeHarness{}).AccountErrorText(s), claudeAccountErrorText(s); got != want {
			t.Errorf("AccountErrorText(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestBuildRunArgs_stateEnvFromHarness(t *testing.T) {
	// With a config dir, the runner bind-mounts it and asks the harness
	// for the env entries that point at the mount. A non-claude harness
	// must NOT get CLAUDE_CONFIG_DIR; it gets only what its StateEnv
	// returns.
	d := ContainerRunner{Harness: stubHarness{state: []string{"CODEX_HOME=/harness-state", "CODEX_SQLITE_HOME=/harness-state"}}}
	got := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/cfg/scan-7")

	if !containsEnvFlag(got, "CODEX_HOME=/harness-state") || !containsEnvFlag(got, "CODEX_SQLITE_HOME=/harness-state") {
		t.Errorf("harness StateEnv not wired: %v", got)
	}
	if containsEnvFlag(got, "CLAUDE_CONFIG_DIR=/harness-state") {
		t.Errorf("non-claude harness leaked CLAUDE_CONFIG_DIR: %v", got)
	}
	// The bind mount itself is harness-neutral and must still be present.
	mounted := false
	for i := 0; i+1 < len(got); i++ {
		if got[i] == "-v" && strings.HasPrefix(got[i+1], "/data/cfg/scan-7:/harness-state") {
			mounted = true
		}
	}
	if !mounted {
		t.Errorf("state dir bind mount missing: %v", got)
	}

	// Default harness keeps the historical env var.
	def := ContainerRunner{}.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/cfg/scan-7")
	if !containsEnvFlag(def, "CLAUDE_CONFIG_DIR=/harness-state") {
		t.Errorf("default harness dropped CLAUDE_CONFIG_DIR: %v", def)
	}
}

func TestClaudeHarness_Env(t *testing.T) {
	// With both credentials set on the host and a base URL, Env must
	// pass both through (bare KEY) and set the base URL explicitly,
	// alongside the fixed telemetry suppressors.
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "oat-test")
	got := ClaudeHarness{}.Env("https://proxy.corp.com/v1")
	for _, want := range []string{
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"OTEL_SDK_DISABLED=true",
		"DISABLE_TELEMETRY=1",
		"DISABLE_ERROR_REPORTING=1",
		"DISABLE_BUG_COMMAND=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_NON_ESSENTIAL_MODEL_CALLS=1",
		"ANTHROPIC_API_KEY",
		"CLAUDE_CODE_OAUTH_TOKEN",
		"ANTHROPIC_BASE_URL=https://proxy.corp.com/v1",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("Env() missing %q: %v", want, got)
		}
	}
}

func TestClaudeHarness_EnvOmitsUnsetCredentials(t *testing.T) {
	// docker -e KEY (bare) reads the host value at run time; when the
	// host has none, passing the bare key would clear an inherited value
	// and is just noise. Env must omit credentials the host does not set,
	// and omit the base URL when none is configured.
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	got := ClaudeHarness{}.Env("")
	for _, absent := range []string{"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"} {
		if slices.Contains(got, absent) {
			t.Errorf("Env() included unset credential %q: %v", absent, got)
		}
	}
	for _, e := range got {
		if strings.HasPrefix(e, "ANTHROPIC_BASE_URL=") {
			t.Errorf("Env() set base URL with none configured: %v", got)
		}
	}
}

func TestBuildRunArgs_includesHarnessEnv(t *testing.T) {
	// The harness's Env() entries land on the container command line
	// each as its own `-e <entry>` pair, and a non-claude harness
	// contributes only its own keys -- nothing claude-specific leaks
	// from buildRunArgs itself.
	d := ContainerRunner{Harness: stubHarness{env: []string{"CODEX_API_KEY", "STUB_OPT=1"}}}
	got := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")

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
	// Harness-neutral env stays put regardless of harness.
	if !containsEnvFlag(got, "HOME=/tmp") || !containsEnvFlag(got, "SEMGREP_SEND_METRICS=off") {
		t.Errorf("harness-neutral env dropped: %v", got)
	}
}

func TestBuildRunArgs_defaultHarnessKeepsClaudeEnv(t *testing.T) {
	// The zero ContainerRunner{} (no Harness set) must keep producing
	// the claude env it always has, so this refactor is no behaviour
	// change for existing deployments.
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	d := ContainerRunner{ModelBaseURL: "https://proxy.corp.com/v1"}
	got := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")
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

// containsEnvFlag reports whether the docker/podman argv s carries the
// pair `-e entry`. Adjacency matters: `-e A -e B` must not match `-e B A`.
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

	// Default harness: PROFILE.md lands at CLAUDE.md, the historical
	// behaviour this refactor must preserve.
	work := t.TempDir()
	d := ContainerRunner{ProfilesDir: profilesDir}
	d.injectProfileGuide("ruby", work, func(Event) {})
	if got, _ := os.ReadFile(filepath.Join(work, "CLAUDE.md")); string(got) != string(body) {
		t.Errorf("default harness wrote %q to CLAUDE.md, want %q", got, body)
	}

	// Non-claude harness: same PROFILE.md, different target filename, so
	// codex/opencode (which read AGENTS.md) get the same orientation.
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
