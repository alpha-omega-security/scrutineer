package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

const (
	testSlowThreshold = 10 * time.Millisecond
	testSlowWrite     = 2 * testSlowThreshold
)

type timingRecord struct {
	Level      string `json:"level"`
	Message    string `json:"msg"`
	DurationMS int64  `json:"duration_ms"`
	Outcome    string `json:"outcome"`
	SQLiteCode int    `json:"sqlite_code"`
}

func slowTimingRecord(t *testing.T, logs *bytes.Buffer, outcome string) {
	t.Helper()
	var record timingRecord
	if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
		t.Fatalf("timing log %q: %v", logs, err)
	}
	if record.Level != "WARN" || record.Message != "sqlite transaction slow or busy" || record.Outcome != outcome || record.SQLiteCode != 0 || record.DurationMS < testSlowThreshold.Milliseconds() {
		t.Fatalf("timing log: %+v", record)
	}
}

func TestTimedTransactionSlowCommit(t *testing.T) {
	gdb := newTestDB(t)
	var logs bytes.Buffer
	repo := Repository{URL: "https://example.com/slow"}
	err := timedTransaction(gdb, slog.New(slog.NewJSONHandler(&logs, nil)), testSlowThreshold, func(tx *gorm.DB) error {
		time.Sleep(testSlowWrite)
		return tx.Create(&repo).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	slowTimingRecord(t, &logs, "committed")
}

func TestTimedTransactionSlowRollback(t *testing.T) {
	gdb := newTestDB(t)
	var logs bytes.Buffer
	const sensitive = "report-with-sensitive-content"
	err := timedTransaction(gdb, slog.New(slog.NewJSONHandler(&logs, nil)), testSlowThreshold, func(*gorm.DB) error {
		time.Sleep(testSlowWrite)
		return errors.New(sensitive)
	})
	if err == nil || err.Error() != sensitive {
		t.Fatalf("error = %v, want original error", err)
	}
	slowTimingRecord(t, &logs, "failed")
	if strings.Contains(logs.String(), sensitive) {
		t.Fatalf("error content leaked into timing log: %s", &logs)
	}
}
