package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

func holdFindingWriteLock(t *testing.T, gdb *gorm.DB, findingID uint) *gorm.DB {
	t.Helper()
	tx := gdb.Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	t.Cleanup(func() { _ = tx.Rollback().Error })
	if err := tx.Model(&Finding{}).Where("id = ?", findingID).UpdateColumn("title", "lock holder").Error; err != nil {
		t.Fatal(err)
	}
	return tx
}

func observeFindingWriteBusy(t *testing.T, gdb *gorm.DB) <-chan struct{} {
	t.Helper()
	busy := make(chan struct{}, 1)
	const name = "test:observe_finding_write_busy"
	if err := gdb.Callback().Update().After("gorm:update").Register(name, func(d *gorm.DB) {
		var sqliteErr interface{ Code() int }
		if d.Statement.Table != "findings" || !errors.As(d.Error, &sqliteErr) || sqliteErr.Code() != sqliteBusyCode {
			return
		}
		select {
		case busy <- struct{}{}:
		default:
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := gdb.Callback().Update().Remove(name); err != nil {
			t.Errorf("remove busy observer: %v", err)
		}
	})
	return busy
}

func startFindingWrite(t *testing.T, gdb *gorm.DB, write func(*gorm.DB) error) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(gdb.Statement.Context)
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		errs <- write(gdb.WithContext(ctx))
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return errs
}

func waitForFindingWriteBusy(t *testing.T, busy <-chan struct{}, errs <-chan error) {
	t.Helper()
	select {
	case <-busy:
	case err := <-errs:
		t.Fatalf("write returned before observing SQLITE_BUSY: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for SQLITE_BUSY")
	}
}

func awaitFindingWrite(t *testing.T, errs <-chan error) error {
	t.Helper()
	select {
	case err := <-errs:
		return err
	case <-time.After(findingWriteRetryTimeout + 5*time.Second):
		t.Fatalf("finding write exceeded the %s retry budget plus cleanup allowance", findingWriteRetryTimeout)
		return nil
	}
}

func findingWriteHistory(t *testing.T, gdb *gorm.DB, findingID uint) []FindingHistory {
	t.Helper()
	var history []FindingHistory
	if err := gdb.Where("finding_id = ?", findingID).Find(&history).Error; err != nil {
		t.Fatal(err)
	}
	return history
}

func TestFindingWrites_waitForActiveWriter(t *testing.T) {
	at := time.Date(2026, time.September, 10, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, field, oldValue, newValue string
		write                           func(*gorm.DB, uint) error
	}{
		{"field", severityField, "High", "Medium", func(gdb *gorm.DB, id uint) error {
			return WriteFindingField(gdb, id, severityField, "Medium", SourceAnalyst, "test")
		}},
		{"time", "released_at", "", at.Format(time.RFC3339), func(gdb *gorm.DB, id uint) error {
			return WriteFindingTimeField(gdb, id, "released_at", at, SourceAnalyst, "test")
		}},
		{"severity cap", severityField, "High", "Medium", func(gdb *gorm.DB, id uint) error {
			_, err := ReconcileFindingSeverityCap(gdb, id, "Medium", SourceSystem, "test")
			return err
		}},
		{"outer transaction", severityField, "High", "Medium", func(gdb *gorm.DB, id uint) error {
			return FindingWriteTransaction(gdb, id, func(tx *gorm.DB) error {
				return WriteFindingField(tx, id, severityField, "Medium", SourceAnalyst, "test")
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gdb := newTestDB(t)
			f := seedFinding(t, gdb)
			lock := holdFindingWriteLock(t, gdb, f.ID)
			busy := observeFindingWriteBusy(t, gdb)
			errs := startFindingWrite(t, gdb, func(gdb *gorm.DB) error { return tc.write(gdb, f.ID) })
			waitForFindingWriteBusy(t, busy, errs)

			// A real read-to-write upgrade must survive contention longer than
			// the former 15 ms retry budget, not just reload a stale snapshot.
			select {
			case err := <-errs:
				t.Fatalf("write returned while the lock was held: %v", err)
			case <-time.After(200 * time.Millisecond):
			}
			if err := lock.Commit().Error; err != nil {
				t.Fatal(err)
			}
			if err := awaitFindingWrite(t, errs); err != nil {
				t.Fatalf("write after lock release: %v", err)
			}

			var stored Finding
			if err := gdb.First(&stored, f.ID).Error; err != nil {
				t.Fatal(err)
			}
			if tc.field == severityField && stored.Severity != tc.newValue {
				t.Errorf("severity = %q, want %q", stored.Severity, tc.newValue)
			}
			if tc.field == "released_at" && (stored.ReleasedAt == nil || !stored.ReleasedAt.Equal(at)) {
				t.Errorf("released_at = %v, want %v", stored.ReleasedAt, at)
			}
			history := findingWriteHistory(t, gdb, f.ID)
			if len(history) != 1 {
				t.Fatalf("history len = %d, want 1: %+v", len(history), history)
			}
			if h := history[0]; h.Field != tc.field || h.OldValue != tc.oldValue || h.NewValue != tc.newValue {
				t.Errorf("unexpected history: %+v", h)
			}
		})
	}
}

func TestWriteFindingField_lockWaitStops(t *testing.T) {
	for _, mode := range []string{"cancel", "caller deadline", "retry deadline"} {
		t.Run(mode, func(t *testing.T) {
			gdb := newTestDB(t)
			f := seedFinding(t, gdb)
			lock := holdFindingWriteLock(t, gdb, f.ID)
			busy := observeFindingWriteBusy(t, gdb)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "caller deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 200*time.Millisecond)
				defer stop()
			}
			errs := startFindingWrite(t, gdb.WithContext(ctx), func(gdb *gorm.DB) error {
				return WriteFindingField(gdb, f.ID, severityField, "Medium", SourceAnalyst, "test")
			})
			waitForFindingWriteBusy(t, busy, errs)
			wantErr := context.DeadlineExceeded
			if mode == "cancel" {
				cancel()
				wantErr = context.Canceled
			}
			if err := awaitFindingWrite(t, errs); !errors.Is(err, wantErr) {
				t.Fatalf("write error = %v, want %v", err, wantErr)
			}
			if err := lock.Rollback().Error; err != nil {
				t.Fatal(err)
			}
			var stored Finding
			if err := gdb.First(&stored, f.ID).Error; err != nil {
				t.Fatal(err)
			}
			if stored.Severity != "High" {
				t.Errorf("severity = %q, want High after failed write", stored.Severity)
			}
			if history := findingWriteHistory(t, gdb, f.ID); len(history) != 0 {
				t.Errorf("history = %+v, want none after failed write", history)
			}
			if err := WriteFindingField(gdb, f.ID, severityField, "Medium", SourceAnalyst, "retry"); err != nil {
				t.Fatalf("write after cancellation and lock release: %v", err)
			}
		})
	}
}

func TestFindingWriteTransaction_retriesWholeOperation(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	var attempts int
	err := FindingWriteTransaction(gdb, f.ID, func(tx *gorm.DB) error {
		attempts++
		var current Finding
		if err := tx.First(&current, f.ID).Error; err != nil {
			return err
		}
		if current.Severity != "High" || current.Title != "t" {
			t.Errorf("attempt %d saw an unrolled-back write: %+v", attempts, current)
		}
		if err := WriteFindingField(tx, f.ID, severityField, "Medium", SourceAnalyst, "test"); err != nil {
			return err
		}
		if err := WriteFindingField(tx, f.ID, "title", "changed", SourceAnalyst, "test"); err != nil {
			return err
		}
		if attempts == 1 {
			return errFindingWriteConflict
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
	history := findingWriteHistory(t, gdb, f.ID)
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2: %+v", len(history), history)
	}
	var stored Finding
	if err := gdb.First(&stored, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Severity != "Medium" || stored.Title != "changed" {
		t.Errorf("finding = severity %q, title %q", stored.Severity, stored.Title)
	}
}

func TestFindingWriteTransaction_leavesCallerOwnedRetryToOwner(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	var attempts int
	if err := gdb.Transaction(func(tx *gorm.DB) error {
		err := FindingWriteTransaction(tx, f.ID, func(tx *gorm.DB) error {
			attempts++
			if err := WriteFindingField(tx, f.ID, severityField, "Medium", SourceAnalyst, "test"); err != nil {
				return err
			}
			return errFindingWriteConflict
		})
		if !errors.Is(err, errFindingWriteConflict) {
			t.Errorf("error = %v, want conflict returned to transaction owner", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 inside caller-owned transaction", attempts)
	}
	if history := findingWriteHistory(t, gdb, f.ID); len(history) != 0 {
		t.Errorf("history = %+v, want none after savepoint rollback", history)
	}
}
