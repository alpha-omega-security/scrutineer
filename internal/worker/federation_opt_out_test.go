package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

// mustNotRunRunner fails the test if the skill is dispatched at all, which is
// the whole point of the opt-out gate: the report is not the concern, reading
// the maintainer's code is.
type mustNotRunRunner struct{ t *testing.T }

func (m mustNotRunRunner) RunSkill(context.Context, SkillJob, func(Event)) (SkillResult, error) {
	m.t.Error("the runner must not be reached for an opted-out repository")
	return SkillResult{}, nil
}

func (mustNotRunRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func newOptOutWorker(t *testing.T, optedOut bool) (*Worker, db.Scan) {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	if optedOut {
		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		repo.FederationOptOutAt = &at
	}
	gdb.Create(&repo)
	skill := db.Skill{Name: "metadata", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)
	return &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         mustNotRunRunner{t: t},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}, scan
}

// A scan enqueued before the maintainer opted out is already on the queue when
// the opt-out lands, so the enqueue gate cannot catch it; dispatch must.
func TestWrap_cancelsJobForOptedOutRepository(t *testing.T) {
	w, scan := newOptOutWorker(t, true)
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	w.DB.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %s, want cancelled", got.Status)
	}
	if got.Error != OptOutCancelReason {
		t.Errorf("error = %q, want %q", got.Error, OptOutCancelReason)
	}
	if got.FinishedAt == nil {
		t.Error("a cancelled scan must be terminal, got no finished_at")
	}
	if got.StartedAt != nil {
		t.Error("the gate must refuse before the scan is marked running")
	}
}

// A scan the worker is actually running unwinds through finishScan, which used
// to hardcode the operator's message: an opt-out cancellation then read as
// "cancelled by user" and the maintainer's request left no trace on the row.
func TestCancel_carriesTheReasonOntoARunningScan(t *testing.T) {
	w, scan := newOptOutWorker(t, false)
	runner := blockingRunner{started: make(chan struct{})}
	w.Runner = runner
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	done := make(chan error, 1)
	go func() { done <- w.wrap(w.doSkill)(context.Background(), body) }()

	<-runner.started
	if !w.Cancel(scan.ID, OptOutCancelReason) {
		t.Fatal("Cancel reported the scan not running")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrap: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("job did not stop after cancel")
	}

	var got db.Scan
	w.DB.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %s, want cancelled", got.Status)
	}
	if got.Error != OptOutCancelReason {
		t.Errorf("error = %q, want %q", got.Error, OptOutCancelReason)
	}
}

// The dispatch gate reads the row and the flag, then startScan claims it, and
// nothing serialises the opt-out sweep against that pair: it can cancel the
// queued row in between. Saving the stale row back would write every column and
// resurrect the scan as running, on exactly the repository whose maintainer just
// asked us to stop.
func TestStartScan_doesNotResurrectARowTheOptOutSweepCancelled(t *testing.T) {
	w, scan := newOptOutWorker(t, false)
	now := time.Now()
	if err := w.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Updates(map[string]any{
		"status":      db.ScanCancelled,
		"error":       OptOutCancelReason,
		"finished_at": &now,
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := w.startScan(&scan); !errors.Is(err, errScanClaimLost) {
		t.Fatalf("startScan = %v, want errScanClaimLost", err)
	}
	var got db.Scan
	w.DB.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %q, want the sweep's cancelled to stand", got.Status)
	}
	if got.Error != OptOutCancelReason {
		t.Errorf("error = %q, want %q", got.Error, OptOutCancelReason)
	}
	if got.StartedAt != nil {
		t.Error("a scan that lost its claim must not look started")
	}
	var events int64
	w.DB.Model(&db.AuditEvent{}).Count(&events)
	if events != 0 {
		t.Errorf("event count = %d, want no scan-started event for a lost claim", events)
	}
}

// The other half of the same window: the flag is committed but the sweep has not
// reached this row yet, so the claim itself has to see the opt-out and roll back.
func TestStartScan_rollsBackTheClaimWhenTheOptOutBeatsIt(t *testing.T) {
	w, scan := newOptOutWorker(t, false)
	at := time.Now().UTC()
	if err := w.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).
		Update("federation_opt_out_at", &at).Error; err != nil {
		t.Fatal(err)
	}

	if err := w.startScan(&scan); !errors.Is(err, errRepoOptedOut) {
		t.Fatalf("startScan = %v, want errRepoOptedOut", err)
	}
	var got db.Scan
	w.DB.First(&got, scan.ID)
	if got.Status != db.ScanQueued {
		t.Errorf("status = %q, want the claim rolled back to queued", got.Status)
	}
	if got.StartedAt != nil {
		t.Error("a rolled-back claim must leave no started_at")
	}
	var events int64
	w.DB.Model(&db.AuditEvent{}).Count(&events)
	if events != 0 {
		t.Errorf("event count = %d, want no scan-started event for a rolled-back claim", events)
	}
}

func TestWrap_dispatchesWhenNotOptedOut(t *testing.T) {
	w, scan := newOptOutWorker(t, false)
	w.Runner = fakeRunner{skillRes: SkillResult{Report: `{"ok":true}`}}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	w.DB.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Fatalf("status = %s (%s), want done", got.Status, got.Error)
	}
}
