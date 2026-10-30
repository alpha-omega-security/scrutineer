package worker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/retry"
)

const (
	subprojectWriteTimeout   = 15 * time.Second
	subprojectRetryBaseDelay = 10 * time.Millisecond
	subprojectRetryMaxDelay  = 100 * time.Millisecond
	sqliteBusyCode           = 5
	sqlitePrimaryCodeMask    = 0xff
)

// Replay the whole transaction so a stale WAL snapshot is discarded too.
func subprojectWriteTransaction(ctx context.Context, gdb *gorm.DB, log *slog.Logger, write func(*gorm.DB) error) error {
	if gdb.Name() != "sqlite" {
		return gdb.WithContext(ctx).Transaction(write)
	}
	ctx, cancel := context.WithTimeout(ctx, subprojectWriteTimeout)
	defer cancel()
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := db.TimedTransaction(gdb.WithContext(ctx), log.With("attempt", attempt), write)
		if err == nil {
			return nil
		}
		var sqliteErr interface{ Code() int }
		if !errors.As(err, &sqliteErr) || sqliteErr.Code()&sqlitePrimaryCodeMask != sqliteBusyCode {
			return err
		}
		if waitErr := retry.Sleep(ctx, retry.BackoffDelay(attempt, subprojectRetryBaseDelay, subprojectRetryMaxDelay)); waitErr != nil {
			return errors.Join(err, waitErr)
		}
	}
}
