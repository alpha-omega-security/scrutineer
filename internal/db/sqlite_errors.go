package db

import "errors"

// SQLiteErrorCode returns the extended SQLite result code wrapped in err, or 0.
func SQLiteErrorCode(err error) int {
	var sqliteErr interface{ Code() int }
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code()
	}
	return 0
}

// IsSQLiteBusy reports SQLITE_BUSY and its extended codes, such as
// SQLITE_BUSY_SNAPSHOT.
func IsSQLiteBusy(err error) bool {
	return SQLiteErrorCode(err)&sqlitePrimaryCodeMask == sqliteBusyCode
}
