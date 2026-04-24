package worker

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

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
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		Runner:  runner,
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
