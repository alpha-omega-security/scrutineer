package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

// twoPhaseRunner fails the first RunSkill and succeeds the second, so a test
// can observe the hard→soft fallback re-run. firstEmit, when set, is streamed as
// a KindText event on the first call to simulate the agent narrating a build
// failure (which is where a real resolver error surfaces — not in the report).
type twoPhaseRunner struct {
	calls     int
	firstEmit string
	first     SkillResult
	second    SkillResult
}

func (r *twoPhaseRunner) RunSkill(_ context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	r.calls++
	if r.calls == 1 {
		if r.firstEmit != "" {
			emit(Event{Kind: KindText, Text: r.firstEmit})
		}
		return r.first, nil
	}
	return r.second, nil
}

func (*twoPhaseRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func stubWholeTreePrep(_ context.Context, _, _, workRoot string, _ func(Event)) (string, error) {
	for _, d := range []string{"activesupport/lib", "actionpack/lib", ".git"} {
		if err := os.MkdirAll(filepath.Join(workRoot, "src", d), 0o755); err != nil {
			return "", err
		}
	}
	return "abc", nil
}

func TestDoSkill_hardScopeSoftFallback(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "subprojects", OutputFile: "report.json", OutputKind: "subprojects", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, Model: "fake", SkillID: &skill.ID, SubPath: "activesupport"}
	gdb.Create(&scan)

	runner := &twoPhaseRunner{
		first:  SkillResult{Commit: "abc", Report: `Bundler could not find compatible versions for gem "activesupport"`},
		second: SkillResult{Commit: "abc", Report: `{"subprojects":[]}`},
	}
	w := &Worker{
		DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(),
		SubprojectScope: "hard", Runner: runner, PrepareRepoSrc: stubWholeTreePrep,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("doSkill: %v", err)
	}
	if runner.calls != 2 {
		t.Errorf("runner called %d times, want 2 (hard attempt + soft retry)", runner.calls)
	}
	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.ScopeMode != "soft" {
		t.Errorf("scope_mode = %q, want soft (fallback recorded)", got.ScopeMode)
	}
}

func TestDoSkill_hardScopeFallbackFromStreamedOutput(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "subprojects", OutputFile: "report.json", OutputKind: "subprojects", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, Model: "fake", SkillID: &skill.ID, SubPath: "actionpack"}
	gdb.Create(&scan)

	// The report is clean; the resolver failure appears only in the streamed
	// narration — the realistic case (an agent describes a failed bundle install
	// in its output, not in report.json).
	runner := &twoPhaseRunner{
		firstEmit: `I ran bundle install and it failed: Bundler could not find compatible versions for gem "activesupport".`,
		first:     SkillResult{Commit: "abc", Report: `{"subprojects":[]}`},
		second:    SkillResult{Commit: "abc", Report: `{"subprojects":[]}`},
	}
	w := &Worker{
		DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(),
		SubprojectScope: "hard", Runner: runner, PrepareRepoSrc: stubWholeTreePrep,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("doSkill: %v", err)
	}
	if runner.calls != 2 {
		t.Errorf("runner called %d times, want 2 (fallback triggered by streamed resolver error)", runner.calls)
	}
	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.ScopeMode != "soft" {
		t.Errorf("scope_mode = %q, want soft", got.ScopeMode)
	}
}

func TestDoSkill_hardScopeNoFallbackOnOrdinaryFailure(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "subprojects", OutputFile: "report.json", OutputKind: "subprojects", Version: 1, Active: true, Source: "ui"}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, Model: "fake", SkillID: &skill.ID, SubPath: "activesupport"}
	gdb.Create(&scan)

	// A clean report with no resolver signature: the hard scan stands, no retry.
	runner := &twoPhaseRunner{
		first:  SkillResult{Commit: "abc", Report: `{"subprojects":[]}`},
		second: SkillResult{Commit: "abc", Report: `{"subprojects":[]}`},
	}
	w := &Worker{
		DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(),
		SubprojectScope: "hard", Runner: runner, PrepareRepoSrc: stubWholeTreePrep,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("doSkill: %v", err)
	}
	if runner.calls != 1 {
		t.Errorf("runner called %d times, want 1 (no fallback without a resolver signature)", runner.calls)
	}
	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.ScopeMode == "soft" {
		t.Errorf("scope_mode = soft, want unchanged (no fallback)")
	}
}
