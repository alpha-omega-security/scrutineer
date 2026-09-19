package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"gorm.io/gorm"
)

func findingAuditEvents(t *testing.T, gdb *gorm.DB, findingID uint) []AuditEvent {
	t.Helper()
	var events []AuditEvent
	if err := gdb.Where("subject_type = ? AND subject_id = ?", AuditSubjectFinding, findingID).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func assertFindingAuditPayload(t *testing.T, event AuditEvent, repositoryID uint, field string, oldValue, newValue any) {
	t.Helper()
	want, err := json.Marshal(map[string]any{"repository_id": repositoryID, "field": field, "old_value": oldValue, "new_value": newValue})
	if err != nil {
		t.Fatal(err)
	}
	var gotPayload, wantPayload map[string]any
	if err := json.Unmarshal([]byte(event.Payload), &gotPayload); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantPayload); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotPayload, wantPayload) {
		t.Fatalf("payload = %s, want %s", event.Payload, want)
	}
}

func TestFindingMutationAuditFields(t *testing.T) {
	for _, tc := range []struct{ field, old, new, kind string }{
		{"status", "new", "triaged", AuditEventFindingStatusChanged},
		{"severity", "High", "Low", AuditEventFindingSeverityChanged},
	} {
		t.Run(tc.field, func(t *testing.T) {
			gdb := newTestDB(t)
			f := seedFinding(t, gdb)
			for range 2 {
				if err := WriteFindingField(gdb, f.ID, tc.field, tc.new, SourceAnalyst, "reviewer"); err != nil {
					t.Fatal(err)
				}
			}
			events := findingAuditEvents(t, gdb, f.ID)
			if len(events) != 1 || events[0].Kind != tc.kind || events[0].Source != SourceAnalyst || events[0].Actor != "reviewer" {
				t.Fatalf("events = %+v", events)
			}
			assertFindingAuditPayload(t, events[0], f.RepositoryID, tc.field, tc.old, tc.new)
			var history []FindingHistory
			if err := gdb.Where("finding_id = ?", f.ID).Find(&history).Error; err != nil {
				t.Fatal(err)
			}
			if len(history) != 1 || history[0].OldValue != tc.old || history[0].NewValue != tc.new || history[0].By != "reviewer" {
				t.Fatalf("history = %+v", history)
			}
		})
	}
}

func TestFindingMutationAuditLabels(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	for _, names := range [][]string{
		{" b ", "a", "a", ""},
		{"a", "b"},
		{"b", "a", "b"},
		{"c"},
		{},
		nil,
	} {
		if err := SetFindingLabels(gdb, f.ID, names, SourceAnalyst, "reviewer"); err != nil {
			t.Fatal(err)
		}
	}
	events := findingAuditEvents(t, gdb, f.ID)
	if len(events) != 3 {
		t.Fatalf("events = %+v, want add/replace/clear only", events)
	}
	for _, event := range events {
		if event.Kind != AuditEventFindingLabelsChanged || event.Source != SourceAnalyst || event.Actor != "reviewer" {
			t.Fatalf("event = %+v", event)
		}
	}
	assertFindingAuditPayload(t, events[0], f.RepositoryID, "labels", []string{}, []string{"a", "b"})
	assertFindingAuditPayload(t, events[1], f.RepositoryID, "labels", []string{"a", "b"}, []string{"c"})
	assertFindingAuditPayload(t, events[2], f.RepositoryID, "labels", []string{"c"}, []string{})
	if err := gdb.Preload("Labels").First(&f, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if len(f.Labels) != 0 {
		t.Fatalf("labels not cleared: %+v", f.Labels)
	}
}

func rejectFindingAuditWrites(t *testing.T, gdb *gorm.DB) error {
	t.Helper()
	injected := errors.New("audit unavailable")
	const callback = "test:fail_finding_audit"
	if err := gdb.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "AuditEvent" {
			_ = tx.AddError(injected)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := gdb.Callback().Create().Remove(callback); err != nil {
			t.Error(err)
		}
	})
	return injected
}

func assertNoNewFindingAuditRows(t *testing.T, gdb *gorm.DB, findingID uint) {
	t.Helper()
	for _, query := range []*gorm.DB{
		gdb.Model(&FindingHistory{}).Where("finding_id = ?", findingID),
		gdb.Model(&FindingLabel{}).Where("name = ?", "new-label"),
	} {
		var count int64
		if err := query.Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%T count after rollback = %d", query.Statement.Model, count)
		}
	}
}

func TestFindingMutationAuditFailureRollsBack(t *testing.T) {
	for name, write := range map[string]func(*gorm.DB, uint) error{
		"status": func(tx *gorm.DB, id uint) error {
			return WriteFindingField(tx, id, "status", "triaged", SourceAnalyst, "")
		},
		"severity": func(tx *gorm.DB, id uint) error {
			return WriteFindingField(tx, id, "severity", "Low", SourceModel, "verify")
		},
		"labels": func(tx *gorm.DB, id uint) error {
			return SetFindingLabels(tx, id, []string{"new-label"}, SourceAnalyst, "")
		},
		"severity cap": func(tx *gorm.DB, id uint) error {
			_, err := ReconcileFindingSeverityCap(tx, id, "Low", SourceSystem, "verify")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			gdb := newTestDB(t)
			f := seedFinding(t, gdb)
			if err := SetFindingLabels(gdb, f.ID, []string{"original"}, SourceAnalyst, ""); err != nil {
				t.Fatal(err)
			}
			injected := rejectFindingAuditWrites(t, gdb)
			if err := write(gdb, f.ID); !errors.Is(err, injected) {
				t.Fatalf("error = %v, want audit failure", err)
			}
			var got Finding
			if err := gdb.Preload("Labels").First(&got, f.ID).Error; err != nil {
				t.Fatal(err)
			}
			if got.Status != f.Status || got.Severity != f.Severity || len(got.Labels) != 1 || got.Labels[0].Name != "original" {
				t.Fatalf("mutation survived rollback: %+v", got)
			}
			assertNoNewFindingAuditRows(t, gdb, f.ID)
			if events := findingAuditEvents(t, gdb, f.ID); len(events) != 1 {
				t.Fatalf("events after rollback = %+v", events)
			}
		})
	}
}

func TestFindingMutationAuditCallerRollback(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	rollback := errors.New("abort outer transaction")
	err := FindingWriteTransaction(gdb, f.ID, func(tx *gorm.DB) error {
		if err := WriteFindingField(tx, f.ID, "severity", "Low", SourceAnalyst, ""); err != nil {
			return err
		}
		if err := SetFindingLabels(tx, f.ID, []string{"temporary"}, SourceAnalyst, ""); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var got Finding
	if err := gdb.Preload("Labels").First(&got, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Severity != f.Severity || len(got.Labels) != 0 {
		t.Fatalf("outer rollback lost: %+v", got)
	}
	if events := findingAuditEvents(t, gdb, f.ID); len(events) != 0 {
		t.Fatalf("events after rollback = %+v", events)
	}
}

func TestFindingMutationAuditConcurrentLabels(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			<-start
			if err := SetFindingLabels(gdb, f.ID, []string{"same"}, SourceAnalyst, ""); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
	if events := findingAuditEvents(t, gdb, f.ID); len(events) != 1 {
		t.Fatalf("events = %+v, want one change", events)
	}
}

func TestFindingMutationAuditSeverityCap(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	for range 2 {
		if _, err := ReconcileFindingSeverityCap(gdb, f.ID, "Low", SourceSystem, "verify"); err != nil {
			t.Fatal(err)
		}
	}
	events := findingAuditEvents(t, gdb, f.ID)
	if len(events) != 1 || events[0].Kind != AuditEventFindingSeverityChanged || events[0].Source != SourceSystem || events[0].Actor != "verify" {
		t.Fatalf("events = %+v", events)
	}
	assertFindingAuditPayload(t, events[0], f.RepositoryID, "severity", "High", "Low")
}

func TestFindingMutationAuditConcurrentLabelChain(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	var wg sync.WaitGroup
	start := make(chan struct{})
	const writers = 4
	for i := range writers {
		wg.Go(func() {
			<-start
			if err := SetFindingLabels(gdb, f.ID, []string{fmt.Sprintf("label-%d", i)}, SourceAnalyst, ""); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
	events := findingAuditEvents(t, gdb, f.ID)
	if len(events) != writers {
		t.Fatalf("events = %+v, want %d changes", events, writers)
	}
	previous := []string{}
	for _, event := range events {
		var payload struct {
			Old []string `json:"old_value"`
			New []string `json:"new_value"`
		}
		if err := json.Unmarshal([]byte(event.Payload), &payload); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(payload.Old, previous) {
			t.Fatalf("event has stale old value: %s, previous=%v", event.Payload, previous)
		}
		previous = payload.New
	}
	if err := gdb.Preload("Labels").First(&f, f.ID).Error; err != nil {
		t.Fatal(err)
	}
	if len(f.Labels) != 1 || len(previous) != 1 || f.Labels[0].Name != previous[0] {
		t.Fatalf("labels %+v differ from last event %v", f.Labels, previous)
	}
}

func TestFindingMutationAuditNoEventsForRejectedOrOtherFields(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	if err := WriteFindingField(gdb, f.ID, "status", "invalid", SourceAnalyst, ""); err == nil {
		t.Fatal("accepted invalid status")
	}
	if err := WriteFindingField(gdb, f.ID+1, "severity", "Low", SourceAnalyst, ""); err == nil {
		t.Fatal("accepted missing finding")
	}
	if err := SetFindingLabels(gdb, f.ID+1, []string{"new-label"}, SourceAnalyst, ""); err == nil {
		t.Fatal("accepted labels for missing finding")
	}
	if err := WriteFindingField(gdb, f.ID, "title", "updated", SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	if events := findingAuditEvents(t, gdb, f.ID); len(events) != 0 {
		t.Fatalf("events = %+v", events)
	}
}
