package worker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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

func assertSubprojectTiming(t *testing.T, s subprojectsScanTest, outcome string, code int) {
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
}
