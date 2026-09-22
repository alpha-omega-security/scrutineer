package worker

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func TestScheduleNextAccountResumeDatabaseError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{"policy disabled", false},
		{"policy enabled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, _ := newResumeTestWorker(t, &recordingRunner{})
			w.PauseOnOverage = tc.enabled
			now := time.Now().UTC()
			w.Now = func() time.Time { return now }
			w.AutoResumeRetryDelay = time.Hour
			var logs bytes.Buffer
			w.Log = slog.New(slog.NewTextHandler(&logs, nil))
			configureOverageTestQueue(t, w)
			sqlDB, err := w.DB.DB()
			if err != nil {
				t.Fatal(err)
			}
			if err := sqlDB.Close(); err != nil {
				t.Fatal(err)
			}

			w.scheduleNextAccountResume()

			w.rlStatusMu.Lock()
			hold, reset := w.persistedOverageHold, w.persistedOverageReset
			w.rlStatusMu.Unlock()
			if hold != tc.enabled || reset != nil {
				t.Fatalf("persisted hold=%v reset=%v, want hold=%v with no reset", hold, reset, tc.enabled)
			}
			if logged := strings.Contains(logs.String(), "persist overage pause"); logged != tc.enabled {
				t.Fatalf("overage log=%v, want %v: %s", logged, tc.enabled, logs.String())
			}
			w.autoResumeMu.Lock()
			scheduled, retryAt := w.autoResumeTimer != nil, w.autoResumeAt
			w.autoResumeMu.Unlock()
			if !scheduled || !retryAt.Equal(now.Add(time.Hour)) {
				t.Fatalf("retry scheduled=%v at=%v, want %v", scheduled, retryAt, now.Add(time.Hour))
			}
		})
	}
}

func configureOverageTestQueue(t *testing.T, w *Worker) {
	t.Helper()
	sqlDB, err := w.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	w.Queue, err = queue.New(sqlDB, w.Log, 1, queue.SQLite)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		w.autoResumeMu.Lock()
		defer w.autoResumeMu.Unlock()
		if w.autoResumeTimer != nil {
			w.autoResumeTimer.Stop()
		}
	})
}

func TestOverageRestartHoldCached(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name   string
		reset  *time.Time
		active bool
	}{
		{"future", new(now.Add(time.Hour)), true},
		{"unknown", nil, true},
		{"implausible", new(now.Add(30 * 24 * time.Hour)), true},
		{"expired", new(now.Add(-time.Hour)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, repoID := newResumeTestWorker(t, &recordingRunner{})
			w.PauseOnOverage = true
			w.Now = func() time.Time { return now }
			// Keep even an expired reset's timer from firing during this test.
			w.AutoResumeBuffer = 2 * time.Hour
			configureOverageTestQueue(t, w)
			scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanPaused, Error: OveragePauseReason, PausedUntil: tc.reset}
			if err := w.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			w.scheduleNextAccountResume()
			active, reset := w.overageState()
			if active != tc.active || tc.name == "future" && (reset == nil || !reset.Equal(*tc.reset)) {
				t.Fatalf("restored hold = %v, %v", active, reset)
			}
			if (tc.name == "unknown" || tc.name == "implausible") && reset != nil {
				t.Fatalf("unreliable reset accepted: %v", reset)
			}
			sqlDB, err := w.DB.DB()
			if err != nil {
				t.Fatal(err)
			}
			if err := sqlDB.Close(); err != nil {
				t.Fatal(err)
			}
			// UI refreshes must use memory even when the database is unavailable.
			for range 3 {
				if got := w.ShouldPauseOnOverage(); got != tc.active {
					t.Fatalf("cached hold = %v, want %v", got, tc.active)
				}
			}
		})
	}
}

func TestOverageRecoveredResetExpiresInMemory(t *testing.T) {
	now := time.Now().UTC()
	w := &Worker{PauseOnOverage: true, Now: func() time.Time { return now }}
	reset := now.Add(time.Hour)
	w.setPersistedOverageHold(true, &reset)
	if !w.ShouldPauseOnOverage() {
		t.Fatal("recovered hold not active")
	}
	now = reset.Add(time.Second)
	if w.ShouldPauseOnOverage() {
		t.Fatal("expired cached hold still blocks dispatch")
	}
}

func TestOverageDoesNotLockOrdinaryScanWork(t *testing.T) {
	for _, operation := range []string{"preflight", "claim", "finalize"} {
		t.Run(operation, func(t *testing.T) {
			w, skill, repoID := newResumeTestWorker(t, &recordingRunner{})
			w.PauseOnOverage = true
			scan := db.Scan{RepositoryID: repoID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
			if err := w.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			w.overageMu.Lock()
			done := make(chan error, 1)
			go func() {
				switch operation {
				case "preflight":
					_, err := w.preflightSkillUnlessOverage(t.Context(), &scan, 0)
					done <- err
				case "claim":
					done <- w.startScanUnlessOverage(&scan)
				case "finalize":
					done <- w.finalizeScan(context.Background(), &scan, "", nil, time.Hour, func(Event) {}, func() {})
				}
			}()
			select {
			case err := <-done:
				w.overageMu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				w.overageMu.Unlock()
				<-done
				t.Fatal("ordinary scan work waited for overage mutex")
			}
		})
	}
}

func TestOveragePauseWinsStalePrerequisiteFailure(t *testing.T) {
	w := newPreflightWorker(t)
	w.PauseOnOverage = true
	scan := seedPreflightFixtures(t, w, "threat-model")
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", IsUsingOverage: true})
	w.failScanPrereqs(scan, scan.SkillName, "prereqs failed", []string{"threat-model"})
	var got db.Scan
	if err := w.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != db.ScanPaused || got.Error != OveragePauseReason || got.FinishedAt != nil {
		t.Fatalf("prerequisite failure overwrote pause: %+v", got)
	}
	// The conditional start claim must also reject the stale queued snapshot.
	if err := w.startScan(scan); !errors.Is(err, errScanClaimLost) {
		t.Fatalf("stale claim = %v", err)
	}
}
