package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

type busyError struct{}

func (busyError) Error() string { return "database busy" }
func (busyError) Code() int     { return sqliteBusyCode }

func TestWriteTransactionReplaysUntilBudget(t *testing.T) {
	gdb := newTestDB(t)
	attempts := 0
	err := WriteTransaction(context.Background(), gdb, 200*time.Millisecond, nil, func(tx *gorm.DB) error {
		attempts++
		if err := tx.Create(&Subproject{RepositoryID: 1, Path: "rolled-back"}).Error; err != nil {
			return err
		}
		return busyError{}
	})
	if !errors.Is(err, context.DeadlineExceeded) || attempts < 2 {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
	var count int64
	if err := gdb.Model(&Subproject{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("partial writes persisted: %d", count)
	}
}

func TestWriteTransactionRecovers(t *testing.T) {
	gdb := newTestDB(t)
	attempts := 0
	err := WriteTransaction(context.Background(), gdb, time.Minute, nil, func(tx *gorm.DB) error {
		attempts++
		if attempts == 1 {
			return busyError{}
		}
		return tx.Create(&Subproject{RepositoryID: 1, Path: "kept"}).Error
	})
	if err != nil || attempts != 2 {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
}

func TestWriteTransactionDoesNotRetryOtherErrors(t *testing.T) {
	gdb := newTestDB(t)
	attempts := 0
	want := errors.New("constraint failed")
	err := WriteTransaction(context.Background(), gdb, time.Minute, nil, func(*gorm.DB) error {
		attempts++
		return want
	})
	if !errors.Is(err, want) || attempts != 1 {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
}

func TestWriteTransactionCancelled(t *testing.T) {
	gdb := newTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := WriteTransaction(ctx, gdb, time.Minute, nil, func(*gorm.DB) error {
		t.Fatal("write after cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestWithPragmasKeepsCallerBusyTimeout(t *testing.T) {
	gdb, err := Connect(t.TempDir() + "/t.db?_pragma=busy_timeout(50)")
	if err != nil {
		t.Fatal(err)
	}
	closeOnCleanup(t, gdb)
	var timeout int
	if err := gdb.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatal(err)
	}
	if timeout != 50 {
		t.Fatalf("busy_timeout=%d, want 50", timeout)
	}
}
