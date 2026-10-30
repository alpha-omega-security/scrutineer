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
func TimedTransaction(gdb *gorm.DB, log *slog.Logger, write func(*gorm.DB) error) error {
	started := time.Now()
	err := gdb.Transaction(write)
	if gdb.Name() != string(DialectSQLite) {
		return err
	}
	elapsed := time.Since(started)
	code := 0
	var sqliteErr interface{ Code() int }
	if errors.As(err, &sqliteErr) {
		code = sqliteErr.Code()
	}
	if elapsed < slowTransactionThreshold && code&0xff != sqliteBusyCode {
		return err
	}
	if log == nil {
		log = slog.Default()
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
