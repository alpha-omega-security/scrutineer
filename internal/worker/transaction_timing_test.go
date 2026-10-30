package worker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

type transactionTimingRecord struct {
	Level      string    `json:"level"`
	Message    string    `json:"msg"`
	Operation  string    `json:"operation"`
	Scan       uint      `json:"scan"`
	Repo       uint      `json:"repo"`
	Skill      string    `json:"skill"`
	Attempt    int       `json:"attempt"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Outcome    string    `json:"outcome"`
	SQLiteCode int       `json:"sqlite_code"`
}

func assertSubprojectTiming(t *testing.T, s subprojectsScanTest, outcome string, code int) transactionTimingRecord {
	t.Helper()
	var matches []transactionTimingRecord
	for line := range strings.SplitSeq(strings.TrimSpace(s.logs.String()), "\n") {
		var record transactionTimingRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Operation == "ingest_subprojects" {
			matches = append(matches, record)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("transaction logs = %+v; all logs: %s", matches, s.logs)
	}
	record := matches[0]
	if record.Level != "WARN" || record.Message != "sqlite transaction slow or busy" || record.Scan != s.scan.ID || record.Repo != s.scan.RepositoryID || record.Skill != "subprojects" || record.Attempt != 1 || record.Outcome != outcome || record.SQLiteCode != code {
		t.Fatalf("transaction log: %+v", record)
	}
	if record.StartedAt.IsZero() || record.StartedAt.After(time.Now()) || record.DurationMS < 0 {
		t.Fatalf("invalid timing: %+v", record)
	}
	return record
}

func TestScanTransactionTimingSlowCommit(t *testing.T) {
	s := newSubprojectsScanTest(t)
	const delay = 1100 * time.Millisecond
	if err := s.db.Callback().Update().After("gorm:update").Register("test:slow_write", func(tx *gorm.DB) {
		if tx.Statement.Table == "subprojects" && tx.Error == nil {
			time.Sleep(delay)
		}
	}); err != nil {
		t.Fatal(err)
	}
	persisted := s.run(t, `{"subprojects":[{"path":"core","name":"updated"}]}`)
	if persisted.Status != db.ScanDone {
		t.Fatalf("scan: %+v", persisted)
	}
	record := assertSubprojectTiming(t, s, "committed", 0)
	if record.DurationMS < delay.Milliseconds() {
		t.Fatalf("duration = %dms, want >= %s", record.DurationMS, delay)
	}
	rows := s.rows(t)
	if len(rows) != 1 || rows[0].Name != "updated" {
		t.Fatalf("persisted rows: %+v", rows)
	}
	t.Logf("scan=%d repo=%d operation=%s outcome=%s duration_ms=%d", record.Scan, record.Repo, record.Operation, record.Outcome, record.DurationMS)
}

func TestScanTransactionTimingSlowRollback(t *testing.T) {
	s := newSubprojectsScanTest(t)
	const sensitive = "report-with-sensitive-content"
	if err := s.db.Callback().Delete().Before("gorm:delete").Register("test:failed_write", func(tx *gorm.DB) {
		if tx.Statement.Table == "subprojects" {
			time.Sleep(1100 * time.Millisecond)
			_ = tx.AddError(errors.New(sensitive))
		}
	}); err != nil {
		t.Fatal(err)
	}
	persisted := s.run(t, `{"subprojects":[{"path":"core","name":"updated"}]}`)
	if persisted.Status != db.ScanFailed || !strings.Contains(persisted.Error, sensitive) {
		t.Fatalf("scan: %+v", persisted)
	}
	assertSubprojectTiming(t, s, "failed", 0)
	if strings.Contains(s.logs.String(), sensitive) {
		t.Fatalf("error content leaked into timing log: %s", s.logs)
	}
	rows := s.rows(t)
	if len(rows) != 2 || rows[0].Name != "old" {
		t.Fatalf("rollback rows: %+v", rows)
	}
}
