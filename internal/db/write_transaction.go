package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/retry"
)

const (
	sqliteBusyCode         = 5
	sqliteBusySnapshotCode = 517
	sqlitePrimaryCodeMask  = 0xff
	writeRetryMaxDelay     = 100 * time.Millisecond
)

// WriteTransaction runs write in a transaction. On SQLite it replays the whole
// transaction on SQLITE_BUSY until budget runs out or ctx ends, so write may
// run more than once: it must reset per-attempt state and avoid external side
// effects. Other dialects get a single attempt. A non-nil log gets a
// TimedTransaction record per slow or busy attempt.
func WriteTransaction(ctx context.Context, gdb *gorm.DB, budget time.Duration, log *slog.Logger, write func(*gorm.DB) error) error {
	if gdb.Name() != string(DialectSQLite) {
		return gdb.WithContext(ctx).Transaction(write)
	}
	return retryTransaction(ctx, gdb, budget, "write transaction", log, sqliteBusyRetryDelay, write)
}

func retryTransaction(ctx context.Context, gdb *gorm.DB, budget time.Duration, label string, log *slog.Logger, retryDelay func(error, int) (time.Duration, bool), write func(*gorm.DB) error) error {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	gdb = gdb.WithContext(ctx)
	for attempt := 1; ; attempt++ {
		attemptLog := log
		if log != nil {
			attemptLog = log.With("attempt", attempt)
		}
		err := TimedTransaction(gdb, attemptLog, write)
		if err == nil {
			return nil
		}
		delay, retryable := retryDelay(err, attempt)
		if !retryable {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return errors.Join(err, ctxErr)
			}
			return err
		}
		if waitErr := retry.Sleep(ctx, delay); waitErr != nil {
			return fmt.Errorf("%s stopped after %d attempts: %w", label, attempt, errors.Join(err, waitErr))
		}
	}
}

// A stale WAL snapshot needs a fresh transaction immediately; an active
// writer needs time to release its lock. Both retries start after rollback.
func sqliteBusyRetryDelay(err error, attempt int) (time.Duration, bool) {
	var sqliteErr interface{ Code() int }
	if !errors.As(err, &sqliteErr) || sqliteErr.Code()&sqlitePrimaryCodeMask != sqliteBusyCode {
		return 0, false
	}
	if sqliteErr.Code() == sqliteBusySnapshotCode {
		return 0, true
	}
	return retry.BackoffDelay(attempt, time.Millisecond, writeRetryMaxDelay), true
}
