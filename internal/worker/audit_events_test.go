package worker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"

	"gorm.io/gorm"
)

func TestWorkerRecordsScanLifecycleEvents(t *testing.T) {
	tests := []struct {
		name      string
		runnerErr error
		ctx       context.Context
		wantKind  string
		wantState db.ScanStatus
	}{
		{name: "finished", wantKind: db.AuditEventScanFinished, wantState: db.ScanDone},
		{name: "failed", runnerErr: errors.New("runner failed"), wantKind: db.AuditEventScanFailed, wantState: db.ScanFailed},
		{name: "cancelled", ctx: cancelledContext(), wantKind: db.AuditEventScanCancelled, wantState: db.ScanCancelled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertScanLifecycleEvents(t, tt.runnerErr, tt.ctx, tt.wantKind, tt.wantState)
		})
	}
}

func assertScanLifecycleEvents(t *testing.T, runnerErr error, ctx context.Context, wantKind string, wantState db.ScanStatus) {
	t.Helper()
	runner := &recordingRunner{err: runnerErr}
	w, skill, repoID := newResumeTestWorker(t, runner)
	scan := db.Scan{
		RepositoryID: repoID,
		Kind:         JobSkill,
		Status:       db.ScanQueued,
		SkillID:      &skill.ID,
		SkillName:    skill.Name,
		Model:        "test-model",
	}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := w.wrap(w.doSkill)(ctx, body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	if err := w.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != wantState {
		t.Fatalf("status = %q, want %q", got.Status, wantState)
	}
	var events []db.AuditEvent
	if err := w.DB.Where("subject_type = ? AND subject_id = ?", db.AuditSubjectScan, scan.ID).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("event count = %d, want 2: %#v", len(events), events)
	}
	if events[0].Kind != db.AuditEventScanStarted || events[1].Kind != wantKind {
		t.Fatalf("event kinds = %q, %q; want %q, %q", events[0].Kind, events[1].Kind, db.AuditEventScanStarted, wantKind)
	}
	if events[1].Source != db.SourceSystem || events[1].Actor != skill.Name {
		t.Fatalf("terminal provenance = source %q actor %q", events[1].Source, events[1].Actor)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(events[1].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["status"] != string(wantState) || payload["repository_id"] != float64(repoID) {
		t.Fatalf("terminal payload = %#v", payload)
	}
	if _, ok := payload["duration_ms"]; !ok {
		t.Fatalf("terminal payload missing duration: %#v", payload)
	}
	if runnerErr != nil && payload["error"] != runnerErr.Error() {
		t.Fatalf("failure error = %#v, want %q", payload["error"], runnerErr)
	}
}

func TestWorkerRollsBackRunningStateWhenAuditEventWriteFails(t *testing.T) {
	w, skill, repoID := newResumeTestWorker(t, &recordingRunner{})
	scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID, SkillName: skill.Name}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Callback().Create().Before("gorm:create").Register("test:fail_audit_event", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AuditEvent" {
			if err := tx.AddError(errors.New("audit event write failed")); err == nil {
				panic("AddError returned nil")
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrap(w.doSkill)(context.Background(), body); err == nil {
		t.Fatal("wrap succeeded despite audit event write failure")
	}

	var got db.Scan
	if err := w.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != db.ScanQueued {
		t.Errorf("status = %q, want queued after rollback", got.Status)
	}
	var events int64
	if err := w.DB.Model(&db.AuditEvent{}).Count(&events).Error; err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Errorf("event count = %d, want 0 after rollback", events)
	}
}

func TestWorkerRollsBackTerminalStateWhenAuditEventWriteFails(t *testing.T) {
	w, skill, repoID := newResumeTestWorker(t, &recordingRunner{})
	scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID, SkillName: skill.Name}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.startScan(&scan); err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Callback().Create().Before("gorm:create").Register("test:fail_terminal_audit_event", func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AuditEvent" {
			if err := tx.AddError(errors.New("terminal audit event write failed")); err == nil {
				panic("AddError returned nil")
			}
		}
	}); err != nil {
		t.Fatal(err)
	}

	err := w.finalizeScan(context.Background(), &scan, "", errors.New("runner failed"), time.Minute, func(Event) {}, func() {})
	if err == nil {
		t.Fatal("finalizeScan succeeded despite terminal audit event write failure")
	}

	var got db.Scan
	if err := w.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != db.ScanRunning {
		t.Errorf("status = %q, want running after rollback", got.Status)
	}
	var events []db.AuditEvent
	if err := w.DB.Where("subject_type = ? AND subject_id = ?", db.AuditSubjectScan, scan.ID).Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != db.AuditEventScanStarted {
		t.Errorf("events = %#v, want only scan.started", events)
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
