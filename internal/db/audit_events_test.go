package db

import (
	"encoding/json"
	"errors"
	"testing"

	"gorm.io/gorm"
)

func TestLogEventPersistsJSONPayloadAndIndexes(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := LogEvent(gdb, AuditEventInput{
		Kind:        "scan.started",
		SubjectType: "scan",
		SubjectID:   42,
		Actor:       "security-deep-dive",
		Source:      SourceSystem,
		Payload:     map[string]any{"repository_id": 7, "status": "running"},
	}); err != nil {
		t.Fatalf("LogEvent: %v", err)
	}

	var got AuditEvent
	if err := gdb.First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.Kind != "scan.started" || got.SubjectType != "scan" || got.SubjectID != 42 {
		t.Fatalf("event = %#v", got)
	}
	if got.Source != SourceSystem || got.Actor != "security-deep-dive" {
		t.Fatalf("provenance = source %q actor %q", got.Source, got.Actor)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(got.Payload), &payload); err != nil {
		t.Fatalf("payload %q is not JSON: %v", got.Payload, err)
	}
	if payload["status"] != "running" || payload["repository_id"] != float64(7) {
		t.Fatalf("payload = %#v", payload)
	}
	for _, name := range []string{"idx_audit_events_kind_created_at", "idx_audit_events_subject"} {
		if !gdb.Migrator().HasIndex(&AuditEvent{}, name) {
			t.Errorf("missing index %s", name)
		}
	}
}

func TestLogEventRejectsInvalidInput(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	cases := []AuditEventInput{
		{SubjectType: "scan", SubjectID: 1, Source: SourceSystem},
		{Kind: "scan.started", SubjectID: 1, Source: SourceSystem},
		{Kind: "scan.started", SubjectType: "scan", Source: SourceSystem},
		{Kind: "scan.started", SubjectType: "scan", SubjectID: 1},
		{Kind: "scan.started", SubjectType: "scan", SubjectID: 1, Source: SourceSystem, Payload: make(chan int)},
	}
	for _, input := range cases {
		if err := LogEvent(gdb, input); err == nil {
			t.Errorf("LogEvent(%#v) succeeded", input)
		}
	}
}

func TestLogEventParticipatesInCallerTransaction(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	err = gdb.Transaction(func(tx *gorm.DB) error {
		if err := LogEvent(tx, AuditEventInput{
			Kind: "scan.started", SubjectType: "scan", SubjectID: 1, Source: SourceSystem,
		}); err != nil {
			return err
		}
		return errors.New("roll back")
	})
	if err == nil {
		t.Fatal("Transaction succeeded")
	}
	var count int64
	if err := gdb.Model(&AuditEvent{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("event count = %d, want 0 after rollback", count)
	}
}
