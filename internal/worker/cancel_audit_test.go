package worker

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func TestCancelWithAudit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &Worker{running: map[uint]*runningScan{1: {cancel: cancel}}}
	failure := errors.New("audit failed")
	if found, err := w.CancelWithAudit(1, CancelledByUser, func() error { return failure }); !found || !errors.Is(err, failure) {
		t.Fatalf("found=%t error=%v", found, err)
	}
	if ctx.Err() != nil || w.cancelReason(1) != "" {
		t.Fatal("failed audit cancelled the scan")
	}
	var calls atomic.Int32
	audit := func() error {
		if ctx.Err() != nil {
			return errors.New("runner signalled before audit")
		}
		calls.Add(1)
		return nil
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if found, err := w.CancelWithAudit(1, CancelledByUser, audit); !found || err != nil {
				t.Errorf("found=%t error=%v", found, err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || ctx.Err() == nil || w.cancelReason(1) != CancelledByUser {
		t.Fatal("cancellation was not audited exactly once")
	}
	if found, err := w.CancelWithAudit(2, CancelledByUser, audit); found || err != nil {
		t.Fatalf("missing scan: found=%t error=%v", found, err)
	}
}

func TestCancelAuditPreservesWorkerLifecycle(t *testing.T) {
	w, scan := newOptOutWorker(t, false)
	runner := blockingRunner{started: make(chan struct{})}
	w.Runner = runner
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- w.wrap(w.doSkill)(ctx, body) }()
	select {
	case <-runner.started:
	case <-time.After(10 * time.Second):
		t.Fatal("runner did not start")
	}
	if found, err := w.CancelWithAudit(scan.ID, CancelledByUser, func() error {
		return db.LogEvent(w.DB, db.AuditEventInput{
			Kind: db.AuditEventScanCancelRequested, SubjectType: db.AuditSubjectScan,
			SubjectID: scan.ID, Source: db.SourceAnalyst,
		})
	}); !found || err != nil {
		t.Fatalf("found=%t error=%v", found, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runner did not stop")
	}
	var events []db.AuditEvent
	if err := w.DB.Where("subject_type = ? AND subject_id = ?", db.AuditSubjectScan, scan.ID).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%v", events)
	}
	for i, kind := range []string{db.AuditEventScanStarted, db.AuditEventScanCancelRequested, db.AuditEventScanCancelled} {
		if events[i].Kind != kind {
			t.Fatalf("event %d=%s, want %s", i, events[i].Kind, kind)
		}
	}
	if events[1].Source != db.SourceAnalyst || events[2].Source != db.SourceSystem {
		t.Fatal("lost cancellation attribution")
	}
}

func TestCancelAuditDoesNotHoldWorkerMutex(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w := &Worker{running: map[uint]*runningScan{1: {cancel: cancel}}}
	if _, err := w.CancelWithAudit(1, CancelledByUser, func() error {
		// This read takes the worker-wide mutex; database callbacks and scan
		// finalizers must still be able to make progress during an audit write.
		if w.cancelReason(1) != "" {
			t.Error("reason set before audit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Fatal("scan not cancelled")
	}
}
