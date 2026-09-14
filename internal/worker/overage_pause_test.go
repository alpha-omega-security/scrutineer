package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func TestOveragePauseConcurrentScans(t *testing.T) {
	w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
	w.PauseOnOverage = true
	reset := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	scans := make([]db.Scan, 3)
	for i := range scans {
		scans[i] = db.Scan{RepositoryID: repoID, Kind: JobExposure, Status: db.ScanQueued}
		if err := w.DB.Create(&scans[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	manual := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanPaused, Error: "manually paused"}
	if err := w.DB.Create(&manual).Error; err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	results := make(chan error, 2)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	handler := func(ctx context.Context, scan *db.Scan, emit func(Event)) (string, error) {
		emit(Event{Kind: KindSession, SessionID: "keep-session"})
		if err := os.MkdirAll(w.scanWorkRoot(scan), 0o755); err != nil {
			return "", err
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		if scan.ID == scans[0].ID {
			emit(Event{Kind: KindRateLimit, RateLimit: &RateLimitInfo{Type: "five_hour", Status: "allowed", IsUsingOverage: true, ResetsAt: reset.Unix()}})
		}
		<-ctx.Done()
		return "partial report", ctx.Err()
	}
	for _, scan := range scans[:2] {
		payload, err := json.Marshal(queue.Payload{ScanID: scan.ID})
		if err != nil {
			t.Fatal(err)
		}
		go func() { results <- w.wrap(handler)(ctx, payload) }()
	}
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("scans did not start")
		}
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	for i, scan := range scans {
		assertOveragePausedScan(t, w, scan.ID, reset, i < 2)
	}
	if err := w.DB.First(&manual, manual.ID).Error; err != nil {
		t.Fatal(err)
	}
	if manual.Error != "manually paused" || manual.PausedUntil != nil {
		t.Fatal("manual pause modified")
	}
}

func assertOveragePausedScan(t *testing.T, w *Worker, id uint, reset time.Time, started bool) {
	t.Helper()
	var got db.Scan
	if err := w.DB.First(&got, id).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != db.ScanPaused || !strings.HasPrefix(got.Error, OveragePauseReason) || got.PausedUntil == nil || !got.PausedUntil.Equal(reset) {
		t.Fatalf("scan not policy-paused: %+v", got)
	}
	if started {
		if got.SessionID != "keep-session" || got.Report != "partial report" {
			t.Fatalf("lost resume state: %+v", got)
		}
		if _, err := os.Stat(w.scanWorkRoot(&got)); err != nil {
			t.Fatal("paused workspace removed", err)
		}
	} else if got.StartedAt != nil {
		t.Fatal("queued scan spent work")
	}
}

func TestOverageDispatchGateAndRestart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
		w.PauseOnOverage = true
		w.recordRateLimit(RateLimitInfo{Type: "five_hour", IsUsingOverage: true})
		first := db.Scan{RepositoryID: repoID, Kind: JobExposure, Status: db.ScanQueued}
		if err := w.DB.Create(&first).Error; err != nil {
			t.Fatal(err)
		}
		dispatch := func(scan db.Scan) {
			t.Helper()
			body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
			if err != nil {
				t.Fatal(err)
			}
			if err := w.wrap(func(context.Context, *db.Scan, func(Event)) (string, error) {
				t.Error("handler ran during overage")
				return "", nil
			})(t.Context(), body); err != nil {
				t.Fatal(err)
			}
		}
		dispatch(first)
		if restart {
			w.rlStatus = nil
		}
		next := db.Scan{RepositoryID: repoID, Kind: JobExposure, Status: db.ScanQueued}
		if err := w.DB.Create(&next).Error; err != nil {
			t.Fatal(err)
		}
		dispatch(next)
		if !w.ShouldPauseOnOverage() {
			t.Fatal("policy gate lost")
		}
		if err := w.DB.First(&next, next.ID).Error; err != nil {
			t.Fatal(err)
		}
		if next.Status != db.ScanPaused || next.PausedUntil != nil {
			t.Fatalf("unknown reset: %+v", next)
		}
	}
}

func TestOveragePausesBeforePrerequisiteChecks(t *testing.T) {
	for _, attempt := range []int{0, 3} {
		t.Run(fmt.Sprintf("attempt_%d", attempt), func(t *testing.T) {
			w := newPreflightWorker(t)
			sqlDB, err := w.DB.DB()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := sqlDB.Close(); err != nil {
					t.Error(err)
				}
			})
			w.PauseOnOverage = true
			w.recordRateLimit(RateLimitInfo{Type: "five_hour", IsUsingOverage: true})
			scan := seedPreflightFixtures(t, w, "threat-model")
			prereq := seedPrereqSkill(t, w, "threat-model", true)
			seedPrereqScan(t, w, prereq, scan.RepositoryID, db.ScanPaused)
			body, err := json.Marshal(queue.Payload{ScanID: scan.ID, Attempt: attempt})
			if err != nil {
				t.Fatal(err)
			}
			if err := w.wrap(func(context.Context, *db.Scan, func(Event)) (string, error) {
				t.Error("handler ran during overage")
				return "", nil
			})(t.Context(), body); err != nil {
				t.Fatal(err)
			}
			if err := w.DB.First(scan, scan.ID).Error; err != nil {
				t.Fatal(err)
			}
			if scan.Status != db.ScanPaused || scan.Error != OveragePauseReason || scan.StartedAt != nil {
				t.Fatalf("prerequisite preflight bypassed overage pause: %+v", scan)
			}
		})
	}
}

func TestOverageResetSelection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name   string
		resets []int64
		want   *time.Time
	}{
		{"latest", []int64{now.Add(time.Hour).Unix(), now.Add(24 * time.Hour).Unix()}, new(now.Add(24 * time.Hour))},
		{"unknown", []int64{now.Add(time.Hour).Unix(), 0}, nil},
		{"implausible", []int64{now.Add(time.Hour).Unix(), now.Add(30 * 24 * time.Hour).Unix()}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
			w.Now = func() time.Time { return now }
			w.PauseOnOverage = true
			scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued}
			if err := w.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			for i, reset := range tc.resets {
				w.recordRateLimit(RateLimitInfo{Type: []string{"five_hour", "seven_day"}[i], IsUsingOverage: true, ResetsAt: reset})
			}
			if err := w.DB.First(&scan, scan.ID).Error; err != nil {
				t.Fatal(err)
			}
			if (scan.PausedUntil == nil) != (tc.want == nil) || tc.want != nil && !scan.PausedUntil.Equal(*tc.want) {
				t.Fatalf("reset=%v want=%v", scan.PausedUntil, tc.want)
			}
		})
	}
}

func TestOverageResumeOnlyPolicyPauses(t *testing.T) {
	w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
	now := time.Now().UTC().Truncate(time.Second)
	w.Now = func() time.Time { return now }
	w.PauseOnOverage = true
	reset := now.Add(time.Hour)
	for _, reason := range []string{appendAutoResume(OveragePauseReason, &reset), "manual pause"} {
		scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanPaused, Error: reason, PausedUntil: &reset}
		if err := w.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
	}
	sqlDB, err := w.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	w.Queue, err = queue.New(sqlDB, w.Log, 1)
	if err != nil {
		t.Fatal(err)
	}
	now = reset.Add(time.Second)
	count, err := w.resumeAccountPaused(t.Context())
	if err != nil || count != 1 {
		t.Fatalf("resume count=%d err=%v", count, err)
	}
	var manual db.Scan
	if err := w.DB.Where("error = ?", "manual pause").First(&manual).Error; err != nil {
		t.Fatal(err)
	}
	if manual.Status != db.ScanPaused {
		t.Fatal("manual pause resumed")
	}
}

func TestOveragePolicyPrecedenceAndCancellation(t *testing.T) {
	w := &Worker{PauseOnOverage: true, DowngradeOnOverage: true}
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", IsUsingOverage: true})
	if !w.ShouldPauseOnOverage() || w.ShouldDowngradeModel() {
		t.Fatal("pause must take precedence")
	}
	for _, reason := range []string{CancelledByUser, OptOutCancelReason, OveragePauseReason} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		scan := db.Scan{}
		finishScan(ctx, &scan, "partial", ctx.Err(), time.Hour, reason, func(Event) {})
		want := db.ScanCancelled
		if reason == OveragePauseReason {
			want = db.ScanPaused
		}
		if scan.Status != want {
			t.Fatalf("reason=%s status=%s", reason, scan.Status)
		}
	}
	w.PauseOnOverage = false
	if !w.ShouldDowngradeModel() || w.ShouldPauseOnOverage() {
		t.Fatal("disabled policy changed downgrade")
	}
}

func TestOverageDispatchFailsClosedOnDatabaseError(t *testing.T) {
	w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
	w.PauseOnOverage = true
	sqlDB, err := w.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	err = w.startScanUnlessOverage(&db.Scan{RepositoryID: repoID, Status: db.ScanQueued})
	if err == nil || errors.Is(err, errScanClaimLost) {
		t.Fatal("database failure treated as success")
	}
}

func TestOverageClearedSignalSchedulesOwnPauses(t *testing.T) {
	w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
	w.PauseOnOverage = true
	scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", IsUsingOverage: true})
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", IsUsingOverage: false})
	if err := w.DB.First(&scan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if scan.PausedUntil == nil || scan.PausedUntil.After(time.Now()) {
		t.Fatal("recovery did not release policy hold")
	}
	if w.ShouldPauseOnOverage() {
		t.Fatal("recovery left gate active")
	}
}

func TestOverageWorkspacePreserved(t *testing.T) {
	// The policy reason must use paused, not terminal cancelled, so normal
	// finalization keeps both the workspace and harness session directory.
	w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
	w.PauseOnOverage = true
	scan := db.Scan{RepositoryID: repoID, Kind: JobExposure, Status: db.ScanQueued}
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(w.harnessStateDir(&scan), "session")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(func(ctx context.Context, _ *db.Scan, emit func(Event)) (string, error) {
		emit(Event{Kind: KindRateLimit, RateLimit: &RateLimitInfo{Type: "five_hour", IsUsingOverage: true}})
		return "", ctx.Err()
	})(t.Context(), body); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("session state removed", err)
	}
}
