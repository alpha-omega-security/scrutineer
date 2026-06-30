package worker

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestClaudeHarness_argsMatchBuildClaudeArgs(t *testing.T) {
	// claudeHarness.Args must be byte-for-byte identical to the function
	// it wraps so introducing the seam is a no-behaviour-change refactor.
	// The buildClaudeArgs table tests in claude_test.go cover the argv
	// shape; this just proves the harness delegates to them.
	for _, sj := range []SkillJob{
		{Name: "deep-dive", Model: "m"},
		{Name: "deep-dive", Model: "m", AllowedTools: "Read,Write", Effort: "low", MaxTurns: 7},
		{Name: "deep-dive", Model: "m", ResumeSessionID: "sess-1", OutputFile: "report.json"},
	} {
		got := claudeHarness{}.Args(sj, "high", 30)
		want := buildClaudeArgs(sj, "high", 30)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("claudeHarness.Args(%+v) = %v, want %v", sj, got, want)
		}
	}
}

func TestClaudeHarness_binaryAndGuide(t *testing.T) {
	h := claudeHarness{}
	if h.Binary() != "claude" {
		t.Errorf("Binary() = %q, want claude", h.Binary())
	}
	if h.GuideFilename() != "CLAUDE.md" {
		t.Errorf("GuideFilename() = %q, want CLAUDE.md", h.GuideFilename())
	}
}

func TestContainerRunner_harnessDefaultsToClaude(t *testing.T) {
	// The zero ContainerRunner{} must keep exec'ing claude so no caller
	// needs to set the field until a second harness exists.
	var d ContainerRunner
	if _, ok := d.harness().(claudeHarness); !ok {
		t.Errorf("zero ContainerRunner harness = %T, want claudeHarness", d.harness())
	}
	stub := stubHarness{bin: "codex", guide: "AGENTS.md"}
	d = ContainerRunner{Harness: stub}
	if d.harness() != stub {
		t.Errorf("explicit harness not returned: got %T", d.harness())
	}
}

// stubHarness is a test-only Harness for exercising the seam without a
// real second implementation. The set of harnesses is open-ended; this
// stands in for any of them.
type stubHarness struct {
	bin   string
	guide string
}

func (s stubHarness) Binary() string                      { return s.bin }
func (s stubHarness) Args(SkillJob, string, int) []string { return []string{"--stub"} }
func (s stubHarness) GuideFilename() string               { return s.guide }

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
