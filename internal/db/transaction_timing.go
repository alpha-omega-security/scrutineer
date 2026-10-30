package db

import (
	"errors"
	"log/slog"
	"time"

	"gorm.io/gorm"
)

const slowTransactionThreshold = time.Second

// TimedTransaction includes begin, lock waits, callback work and commit/rollback.
// It logs timing and error codes without SQL, bound values or error messages.
// A nil log runs the transaction without timing it.
func TimedTransaction(gdb *gorm.DB, log *slog.Logger, write func(*gorm.DB) error) error {
	return timedTransaction(gdb, log, slowTransactionThreshold, write)
}

func timedTransaction(gdb *gorm.DB, log *slog.Logger, slow time.Duration, write func(*gorm.DB) error) error {
	started := time.Now()
	err := gdb.Transaction(write)
	if log == nil || gdb.Name() != string(DialectSQLite) {
		return err
	}
	elapsed := time.Since(started)
	code := 0
	var sqliteErr interface{ Code() int }
	if errors.As(err, &sqliteErr) {
		code = sqliteErr.Code()
	}
	if elapsed < slow && code&sqlitePrimaryCodeMask != sqliteBusyCode {
		return err
	}
	outcome := "committed"
	if err != nil {
		outcome = "failed"
	}
	log.WarnContext(gdb.Statement.Context, "sqlite transaction slow or busy",
		"started_at", started.UTC(), "duration_ms", elapsed.Milliseconds(),
		"outcome", outcome, "sqlite_code", code)
	return err
}
