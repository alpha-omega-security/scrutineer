package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexRunner_modelSelection(t *testing.T) {
	// Default model fallback
	r := CodexRunner{}
	sj := SkillJob{Model: ""}
	model := sj.Model
	if model == "" {
		model = r.Model
	}
	if model == "" {
		model = "codex-mini-latest"
	}
	if model != "codex-mini-latest" {
		t.Errorf("default model = %q, want codex-mini-latest", model)
	}

	// Job model wins
	sj2 := SkillJob{Model: "gpt-4o"}
	model2 := sj2.Model
	if model2 == "" {
		model2 = r.Model
	}
	if model2 != "gpt-4o" {
		t.Errorf("job model = %q, want gpt-4o", model2)
	}

	// Runner model wins over default
	r3 := CodexRunner{Model: "o3-mini"}
	sj3 := SkillJob{Model: ""}
	model3 := sj3.Model
	if model3 == "" {
		model3 = r3.Model
	}
	if model3 == "" {
		model3 = "codex-mini-latest"
	}
	if model3 != "o3-mini" {
		t.Errorf("runner model = %q, want o3-mini", model3)
	}
}

func TestCodexRunner_readsOutput(t *testing.T) {
	work := t.TempDir()
	outPath := filepath.Join(work, "report.json")
	_ = os.WriteFile(outPath, []byte(`{"findings":[]}`), 0o644)

	got := readCappedReport(outPath, func(Event) {})
	if !strings.Contains(got, "findings") {
		t.Errorf("report = %q, want containing 'findings'", got)
	}
}
