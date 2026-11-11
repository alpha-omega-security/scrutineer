package db

import (
	"errors"
	"fmt"
	"testing"
)

type sqliteCodeError int

func (e sqliteCodeError) Error() string { return fmt.Sprintf("sqlite %d", int(e)) }
func (e sqliteCodeError) Code() int     { return int(e) }

func TestSQLiteErrorCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
		busy bool
	}{
		{"nil", nil, 0, false},
		{"plain", errors.New("boom"), 0, false},
		{"busy", sqliteCodeError(5), 5, true},
		{"busy snapshot", sqliteCodeError(517), 517, true},
		{"wrapped busy", fmt.Errorf("save: %w", sqliteCodeError(5)), 5, true},
		{"locked", sqliteCodeError(6), 6, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SQLiteErrorCode(tc.err); got != tc.code {
				t.Errorf("SQLiteErrorCode = %d, want %d", got, tc.code)
			}
			if got := IsSQLiteBusy(tc.err); got != tc.busy {
				t.Errorf("IsSQLiteBusy = %t, want %t", got, tc.busy)
			}
		})
	}
}
