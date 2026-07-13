package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

// recordingRunner captures the SkillJob it was handed and optionally emits a
// session event so the worker's persist path is exercised.
type recordingRunner struct {
	emitSession string
	res         SkillResult
	err         error
	got         SkillJob
}

func (r *recordingRunner) RunSkill(_ context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	r.got = sj
	if r.emitSession != "" {
		emit(Event{Kind: KindSession, SessionID: r.emitSession})
	}
	return r.res, r.err
}

func (*recordingRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func newResumeTestWorker(t *testing.T, runner SkillRunner) (*Worker, *db.Skill, uint) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "deep", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         runner,
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	return w, &skill, repo.ID
}

func runScan(t *testing.T, w *Worker, scanID uint) db.Scan {
	t.Helper()
	body, _ := json.Marshal(queue.Payload{ScanID: scanID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}
	var got db.Scan
	w.DB.First(&got, scanID)
	return got
}

func TestWorker_SessionClearedOnDone(t *testing.T) {
	runner := &recordingRunner{emitSession: "sess-1", res: SkillResult{Report: "", SessionID: "sess-1"}}
	w, skill, repoID := newResumeTestWorker(t, runner)
	scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	w.DB.Create(&scan)

	// A fresh scan must not ask the runner to resume.
	got := runScan(t, w, scan.ID)
	if runner.got.ResumeSessionID != "" {
		t.Errorf("fresh scan passed ResumeSessionID=%q", runner.got.ResumeSessionID)
	}
	if got.Status != db.ScanDone {
		t.Fatalf("status = %s, want done", got.Status)
	}
	if got.SessionID != "" {
		t.Errorf("session id = %q, want cleared on done", got.SessionID)
	}
}

func TestWorker_SessionKeptOnFailure(t *testing.T) {
	runner := &recordingRunner{emitSession: "sess-1", err: errors.New("boom")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	w.DB.Create(&scan)

	got := runScan(t, w, scan.ID)
	if got.Status != db.ScanFailed {
		t.Fatalf("status = %s, want failed", got.Status)
	}
	// A failed scan keeps the session so a retry can resume it.
	if got.SessionID != "sess-1" {
		t.Errorf("session id = %q, want sess-1 preserved", got.SessionID)
	}
}

func TestWorker_ResumeReusesLineageWorkspace(t *testing.T) {
	const rootID = uint(7)
	runner := &recordingRunner{res: SkillResult{Report: ""}}
	w, skill, repoID := newResumeTestWorker(t, runner)
	resumeOf := rootID
	scan := db.Scan{
		RepositoryID:      repoID,
		Kind:              JobSkill,
		Status:            db.ScanQueued,
		SkillID:           &skill.ID,
		SessionID:         "sess-1",
		ResumedFromScanID: &resumeOf,
	}
	w.DB.Create(&scan)

	runScan(t, w, scan.ID)

	if runner.got.ResumeSessionID != "sess-1" {
		t.Errorf("ResumeSessionID = %q, want sess-1", runner.got.ResumeSessionID)
	}
	// The runner must execute in the lineage root's workspace, not the new
	// scan's, so claude finds the cwd-keyed session it stored originally.
	if want := w.workRoot(rootID); runner.got.WorkRoot != want {
		t.Errorf("WorkRoot = %q, want lineage root %q", runner.got.WorkRoot, want)
	}
	if want := w.harnessStateDirID(7); runner.got.StateDir != want {
		t.Errorf("StateDir = %q, want %q", runner.got.StateDir, want)
	}
}
