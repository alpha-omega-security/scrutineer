package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

// stubPrepareRepoSrc pretends a clone happened so doSkill's repo-cache
// step never hits the network. Tests exercising the unreachable path
// replace this with a function returning *RepoUnreachableError.
func stubPrepareRepoSrc(_ context.Context, _, _, workRoot string, _ func(Event)) (string, error) {
	return "abc", os.MkdirAll(filepath.Join(workRoot, "src"), 0o755)
}

// fakeRunner stubs the SkillRunner for unit tests: emits a log line so the
// wrap() path is exercised and returns a pre-set result. Shared by the
// skill and parser test files in this package.
type fakeRunner struct {
	skillRes SkillResult
	skillErr error
}

func (f fakeRunner) RunSkill(_ context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	emit(Event{Kind: "text", Text: "running skill " + sj.Name})
	return f.skillRes, f.skillErr
}

type blockingRunner struct {
	started chan struct{}
}

func (b blockingRunner) RunSkill(ctx context.Context, _ SkillJob, _ func(Event)) (SkillResult, error) {
	close(b.started)
	<-ctx.Done()
	return SkillResult{}, ctx.Err()
}

func TestWorker_CancelStopsRunningScan(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "slow", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)

	runner := blockingRunner{started: make(chan struct{})}
	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         runner,
		PrepareRepoSrc: stubPrepareRepoSrc,
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	done := make(chan error, 1)
	go func() { done <- w.wrap(w.doSkill)(context.Background(), body) }()

	<-runner.started
	if !w.Cancel(scan.ID) {
		t.Fatal("Cancel reported scan not running")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrap returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("job did not stop after cancel")
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %s, want cancelled (err=%q)", got.Status, got.Error)
	}
	if w.Cancel(scan.ID) {
		t.Error("Cancel returned true after job finished")
	}
}

func TestEffectiveMaxTurns(t *testing.T) {
	tests := []struct {
		perSkill, global, want int
	}{
		{50, 200, 50},
		{0, 200, 200},
		{0, 0, DefaultSkillMaxTurns},
		{10, 0, 10},
	}
	for _, tc := range tests {
		got := effectiveMaxTurns(tc.perSkill, tc.global)
		if got != tc.want {
			t.Errorf("effectiveMaxTurns(%d, %d) = %d, want %d", tc.perSkill, tc.global, got, tc.want)
		}
	}
}

func TestWorker_maxTurnsReachedCompletesNotFails(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "mt.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "capped", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1, MaxTurns: 5}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)

	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillRes: SkillResult{Report: `{"partial":true}`}, skillErr: &MaxTurnsReachedError{}},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Errorf("status = %s, want done", got.Status)
	}
	if got.Report != `{"partial":true}` {
		t.Errorf("report = %q, want partial report preserved", got.Report)
	}
}

func TestWorker_workspaceCleanup(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "wc.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "noop", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)

	dataDir := t.TempDir()
	run := func(r SkillRunner) (db.Scan, string) {
		scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
		gdb.Create(&scan)
		w := &Worker{
			DB:             gdb,
			Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
			DataDir:        dataDir,
			Runner:         r,
			PrepareRepoSrc: stubPrepareRepoSrc,
		}
		body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
		if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
			t.Fatalf("wrap: %v", err)
		}
		gdb.First(&scan, scan.ID)
		return scan, w.workRoot(scan.ID)
	}

	// Successful scan: workspace removed.
	ok, okRoot := run(fakeRunner{skillRes: SkillResult{Report: ""}})
	if ok.Status != db.ScanDone {
		t.Fatalf("status = %s, want done (err=%q)", ok.Status, ok.Error)
	}
	if _, err := os.Stat(okRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace %s not removed after successful scan", okRoot)
	}

	// Failed scan: workspace also removed (prevents disk exhaustion).
	fail, failRoot := run(fakeRunner{skillErr: errors.New("boom")})
	if fail.Status != db.ScanFailed {
		t.Fatalf("status = %s, want failed", fail.Status)
	}
	if _, err := os.Stat(failRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace %s not removed after failed scan", failRoot)
	}
}
