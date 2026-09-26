package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"

	"gorm.io/gorm"
)

func scanControlEvents(t *testing.T, s *Server) []db.AuditEvent {
	t.Helper()
	var events []db.AuditEvent
	if err := s.DB.Where("subject_type = ?", db.AuditSubjectScan).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func seedControlScan(t *testing.T, s *Server, status db.ScanStatus) db.Scan {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/control", Name: "control"}
	if err := s.DB.Where("url = ?", repo.URL).FirstOrCreate(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: status,
		APIToken: "secret-token", Log: "secret-transcript", SessionID: "secret-session"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return scan
}

func failScanAudit(t *testing.T, s *Server) {
	t.Helper()
	const name = "test:fail-scan-control-audit"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(name, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AuditEvent" {
			_ = tx.AddError(errors.New("audit unavailable"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DB.Callback().Create().Remove(name) })
}

func assertScanStatus(t *testing.T, s *Server, id uint, status db.ScanStatus) {
	t.Helper()
	var scan db.Scan
	if err := s.DB.First(&scan, id).Error; err != nil {
		t.Fatal(err)
	}
	if scan.Status != status {
		t.Fatalf("status = %s, want %s", scan.Status, status)
	}
}

func assertControlEvent(t *testing.T, event db.AuditEvent, scan db.Scan, kind string, oldStatus, newStatus db.ScanStatus, source db.FindingSource) {
	t.Helper()
	if event.Kind != kind || event.SubjectID != scan.ID || event.Source != source || event.Actor != "" {
		t.Fatalf("unexpected event: %+v", event)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["repository_id"] != float64(scan.RepositoryID) || payload["old_status"] != string(oldStatus) || payload["new_status"] != string(newStatus) {
		t.Fatalf("unexpected payload: %s", event.Payload)
	}
	if strings.Contains(event.Payload, "secret-") {
		t.Fatalf("sensitive data in payload: %s", event.Payload)
	}
}

func TestScanControlResumeAudit(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		for _, failure := range []bool{false, true} {
			t.Run(fmt.Sprintf("bulk=%t/enqueue-failure=%t", bulk, failure), func(t *testing.T) {
				testScanControlResumeAudit(t, bulk, failure)
			})
		}
	}
}

func testScanControlResumeAudit(t *testing.T, bulk, failure bool) {
	t.Helper()
	s, done := newTestServer(t)
	defer done()
	scan := seedControlScan(t, s, db.ScanPaused)
	ctx := t.Context()
	if failure {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		cancel()
	}
	var err error
	if bulk {
		var scans []db.Scan
		scans, err = s.bulkResumePaused(s.DB.Where("repository_id = ?", scan.RepositoryID))
		if err == nil && len(scans) == 1 {
			err = s.enqueueResumedScan(ctx, scans[0])
		} else {
			t.Fatalf("claimed = %v, error = %v", scans, err)
		}
	} else {
		err = s.resumeScan(ctx, &scan)
	}
	if (err != nil) != failure {
		t.Fatalf("error = %v, want failure %t", err, failure)
	}
	events := scanControlEvents(t, s)
	want := 1
	if failure {
		want = 2
	}
	if len(events) != want {
		t.Fatalf("events = %d, want %d", len(events), want)
	}
	assertControlEvent(t, events[0], scan, db.AuditEventScanResumeRequested, db.ScanPaused, db.ScanQueued, db.SourceAnalyst)
	if failure {
		assertControlEvent(t, events[1], scan, db.AuditEventScanResumeEnqueueFailed, db.ScanQueued, db.ScanPaused, db.SourceSystem)
		assertScanStatus(t, s, scan.ID, db.ScanPaused)
		assertQueuedJobCount(t, s, 0)
	} else {
		assertScanStatus(t, s, scan.ID, db.ScanQueued)
		if err := s.resumeScan(ctx, &scan); err == nil {
			t.Fatal("duplicate resume succeeded")
		}
		if len(scanControlEvents(t, s)) != 1 {
			t.Fatal("duplicate resume recorded an event")
		}
		assertQueuedJobCount(t, s, 1)
	}
}

func TestScanControlAuditFailureRollsBack(t *testing.T) {
	for _, action := range []string{"resume", "bulk-resume", "pause", "cancel", "bulk-cancel"} {
		t.Run(action, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			status := db.ScanQueued
			if strings.Contains(action, "resume") {
				status = db.ScanPaused
			}
			scan := seedControlScan(t, s, status)
			failScanAudit(t, s)
			r := localReq("POST", fmt.Sprintf("/scans?repository=%d", scan.RepositoryID))
			r.SetPathValue("id", fmt.Sprint(scan.ID))
			w := httptest.NewRecorder()
			switch action {
			case "resume":
				s.scanResume(w, r)
			case "bulk-resume":
				s.scansResumePaused(w, r)
			case "pause":
				s.scansPauseQueued(w, r)
			case "cancel":
				s.scanCancel(w, r)
			case "bulk-cancel":
				s.scansCancelAll(w, r)
			}
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body)
			}
			assertScanStatus(t, s, scan.ID, status)
			if len(scanControlEvents(t, s)) != 0 {
				t.Fatal("failed mutation left audit events")
			}
			assertQueuedJobCount(t, s, 0)
		})
	}
}

func TestScanControlPauseAndCancelAudit(t *testing.T) {
	for _, action := range []string{"pause", "cancel", "bulk-cancel"} {
		t.Run(action, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			scan := seedControlScan(t, s, db.ScanQueued)
			terminal := seedControlScan(t, s, db.ScanDone)
			for range 2 {
				r := localReq("POST", fmt.Sprintf("/scans?repository=%d", scan.RepositoryID))
				r.SetPathValue("id", fmt.Sprint(scan.ID))
				w := httptest.NewRecorder()
				switch action {
				case "pause":
					s.scansPauseQueued(w, r)
				case "cancel":
					s.scanCancel(w, r)
				case "bulk-cancel":
					s.scansCancelAll(w, r)
				}
				if w.Code >= 500 {
					t.Fatalf("HTTP %d: %s", w.Code, w.Body)
				}
			}
			events := scanControlEvents(t, s)
			if len(events) != 1 {
				t.Fatalf("events = %+v", events)
			}
			kind, status := db.AuditEventScanCancelled, db.ScanCancelled
			if action == "pause" {
				kind, status = db.AuditEventScanPaused, db.ScanPaused
			}
			assertControlEvent(t, events[0], scan, kind, db.ScanQueued, status, db.SourceAnalyst)
			assertScanStatus(t, s, terminal.ID, db.ScanDone)
		})
	}
}

func TestScanControlRetryAudit(t *testing.T) {
	for _, mode := range []string{"success", "bulk", "audit-failure", "enqueue-failure", "ordinary-enqueue"} {
		t.Run(mode, func(t *testing.T) {
			testScanControlRetryAudit(t, mode)
		})
	}
}

func TestScanControlBulkScope(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scan := seedControlScan(t, s, db.ScanPaused)
	other := db.Repository{URL: "https://example.com/other-control"}
	if err := s.DB.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	foreign := db.Scan{RepositoryID: other.ID, Kind: worker.JobSkill, Status: db.ScanPaused}
	if err := s.DB.Create(&foreign).Error; err != nil {
		t.Fatal(err)
	}
	scans, err := s.bulkResumePaused(s.DB.Where("repository_id = ?", scan.RepositoryID))
	if err != nil || len(scans) != 1 {
		t.Fatalf("scans=%v error=%v", scans, err)
	}
	events := scanControlEvents(t, s)
	if len(events) != 1 {
		t.Fatalf("events=%v", events)
	}
	assertControlEvent(t, events[0], scan, db.AuditEventScanResumeRequested, db.ScanPaused, db.ScanQueued, db.SourceAnalyst)
	assertScanStatus(t, s, foreign.ID, db.ScanPaused)
}

func TestScanControlBulkAuditRollbackAfterFirstEvent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	a := seedControlScan(t, s, db.ScanQueued)
	b := seedControlScan(t, s, db.ScanQueued)
	writes := 0
	const callback = "test:fail-second-control-event"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AuditEvent" {
			writes++
			if writes == 2 {
				_ = tx.AddError(errors.New("second event failed"))
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.DB.Callback().Create().Remove(callback) }()
	w := httptest.NewRecorder()
	s.scansPauseQueued(w, localReq("POST", "/scans/pause-queued"))
	if w.Code != 500 || writes != 2 {
		t.Fatalf("HTTP=%d writes=%d", w.Code, writes)
	}
	assertScanStatus(t, s, a.ID, db.ScanQueued)
	assertScanStatus(t, s, b.ID, db.ScanQueued)
	if len(scanControlEvents(t, s)) != 0 {
		t.Fatal("first event survived rollback")
	}
}

func TestScanControlRecoveryAuditFailure(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry=%t", retry), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			scan := seedControlScan(t, s, db.ScanQueued)
			failScanAudit(t, s)
			queueErr := errors.New("queue failed")
			var err error
			if retry {
				err = s.scanEnqueueFailure(scan, queueErr, true)
				if !errors.Is(err, queueErr) {
					t.Fatal("lost original enqueue error")
				}
			} else {
				err = s.restorePausedAfterResumeEnqueueFailure(scan, queueErr)
			}
			if err == nil || !strings.Contains(err.Error(), "audit unavailable") {
				t.Fatalf("error=%v", err)
			}
			assertScanStatus(t, s, scan.ID, db.ScanQueued)
			if len(scanControlEvents(t, s)) != 0 {
				t.Fatal("failed recovery left audit event")
			}
		})
	}
}

func TestScanControlRecoveryDoesNotOverwriteNewState(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scan := seedControlScan(t, s, db.ScanRunning)
	queueErr := errors.New("queue failed")
	if err := s.restorePausedAfterResumeEnqueueFailure(scan, queueErr); err != nil {
		t.Fatal(err)
	}
	if err := s.scanEnqueueFailure(scan, queueErr, true); !errors.Is(err, queueErr) {
		t.Fatalf("error=%v", err)
	}
	assertScanStatus(t, s, scan.ID, db.ScanRunning)
	if len(scanControlEvents(t, s)) != 0 {
		t.Fatal("no-op recovery recorded an event")
	}
}

func testScanControlRetryAudit(t *testing.T, mode string) {
	t.Helper()
	s, done := newTestServer(t)
	defer done()
	parent := seedControlScan(t, s, db.ScanFailed)
	skill := db.Skill{Name: "metadata", Active: true}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&parent).Update("skill_id", skill.ID).Error; err != nil {
		t.Fatal(err)
	}
	if mode == "audit-failure" {
		failScanAudit(t, s)
	}
	r := localReq("POST", "/scans/retry-failed")
	r.SetPathValue("id", fmt.Sprint(parent.ID))
	if mode == "enqueue-failure" {
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		r = r.WithContext(ctx)
	}
	w := httptest.NewRecorder()
	switch mode {
	case "bulk":
		s.scansRetryFailed(w, r)
	case "ordinary-enqueue":
		if _, err := s.enqueueSkill(r.Context(), parent.RepositoryID, skill.ID, ""); err != nil {
			t.Fatal(err)
		}
	default:
		s.scanRetry(w, r)
	}
	events := scanControlEvents(t, s)
	if mode == "audit-failure" {
		if w.Code != 500 || len(events) != 0 {
			t.Fatalf("status=%d events=%v", w.Code, events)
		}
		var count int64
		if err := s.DB.Model(&db.Scan{}).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("scan count=%d", count)
		}
		assertQueuedJobCount(t, s, 0)
		return
	}
	if mode == "ordinary-enqueue" {
		if len(events) != 0 {
			t.Fatalf("unexpected events: %v", events)
		}
		return
	}
	want := 1
	if mode == "enqueue-failure" {
		want = 2
	}
	if len(events) != want {
		t.Fatalf("events=%v HTTP=%d %s", events, w.Code, w.Body)
	}
	var child db.Scan
	if err := s.DB.First(&child, events[0].SubjectID).Error; err != nil {
		t.Fatal(err)
	}
	assertControlEvent(t, events[0], child, db.AuditEventScanRetryRequested, "", db.ScanQueued, db.SourceAnalyst)
	var payload map[string]any
	if err := json.Unmarshal([]byte(events[0].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["parent_scan_id"] != float64(parent.ID) || payload["resumed_from_scan_id"] != float64(parent.ID) {
		t.Fatalf("lineage missing: %v", payload)
	}
	if mode == "enqueue-failure" {
		assertControlEvent(t, events[1], child, db.AuditEventScanRetryEnqueueFailed, db.ScanQueued, db.ScanFailed, db.SourceSystem)
		assertScanStatus(t, s, child.ID, db.ScanFailed)
		assertQueuedJobCount(t, s, 0)
	} else {
		assertQueuedJobCount(t, s, 1)
	}
}
