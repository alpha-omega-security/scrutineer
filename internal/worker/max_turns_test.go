package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

// captureRunner records the SkillJob it was handed so a test can assert how
// the worker resolved per-scan inputs.
type captureRunner struct{ sj SkillJob }

func (c *captureRunner) RunSkill(_ context.Context, sj SkillJob, _ func(Event)) (SkillResult, error) {
	c.sj = sj
	return SkillResult{}, nil
}

func (*captureRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func TestWorker_resolvesDefaultMaxTurns(t *testing.T) {
	tests := []struct {
		name         string
		skillMaxTurn int
		setting      string // "" = leave the DB setting unset
		want         int
	}{
		{"unset falls back to runner default", 0, "", 0},
		{"live default applies when skill sets none", 0, "42", 42},
		{"per-skill cap wins over live default", 7, "42", 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gdb, err := db.Open(filepath.Join(t.TempDir(), "mt.db"))
			if err != nil {
				t.Fatal(err)
			}
			repo := db.Repository{URL: "https://example.com/x", Name: "x"}
			gdb.Create(&repo)
			skill := db.Skill{Name: "s", Description: "d", Body: "b", Active: true, Source: "ui", Version: 1, MaxTurns: tc.skillMaxTurn}
			gdb.Create(&skill)
			scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
			gdb.Create(&scan)
			if tc.setting != "" {
				if err := db.SetSetting(gdb, db.SettingDefaultMaxTurns, tc.setting); err != nil {
					t.Fatal(err)
				}
			}

			runner := &captureRunner{}
			w := &Worker{
				DB:             gdb,
				Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
				DataDir:        t.TempDir(),
				Runner:         runner,
				PrepareRepoSrc: stubPrepareRepoSrc,
			}
			body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
			if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
				t.Fatalf("wrap: %v", err)
			}
			if runner.sj.MaxTurns != tc.want {
				t.Errorf("sj.MaxTurns = %d, want %d", runner.sj.MaxTurns, tc.want)
			}
		})
	}
}
