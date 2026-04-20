package db

import (
	"path/filepath"
	"testing"

	"gorm.io/gorm"
)

const severityField = "severity"

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	return gdb
}

func seedFinding(t *testing.T, gdb *gorm.DB) Finding {
	t.Helper()
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Kind: "skill", Status: ScanDone}
	gdb.Create(&scan)
	f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "t", Severity: "High", Status: FindingNew}
	gdb.Create(&f)
	return f
}

func TestWriteFindingField_logsHistory(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if err := WriteFindingField(gdb, f.ID, severityField, "Critical", SourceAnalyst, "me"); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.First(&refreshed, f.ID)
	if refreshed.Severity != "Critical" {
		t.Errorf("severity = %q, want Critical", refreshed.Severity)
	}
	var history []FindingHistory
	gdb.Where("finding_id = ?", f.ID).Find(&history)
	if len(history) != 1 {
		t.Fatalf("history len = %d, want 1", len(history))
	}
	h := history[0]
	if h.Field != severityField || h.OldValue != "High" || h.NewValue != "Critical" || h.Source != SourceAnalyst || h.By != "me" {
		t.Errorf("history row: %+v", h)
	}
}

func TestWriteFindingField_noOpWhenUnchanged(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if err := WriteFindingField(gdb, f.ID, severityField, "High", SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	var count int64
	gdb.Model(&FindingHistory{}).Where("finding_id = ?", f.ID).Count(&count)
	if count != 0 {
		t.Errorf("history rows = %d, want 0", count)
	}
}

func TestWriteFindingField_rejectsUnknownField(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	if err := WriteFindingField(gdb, f.ID, "does_not_exist", "x", SourceAnalyst, ""); err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestAddFindingNote_rejectsEmpty(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)
	if _, err := AddFindingNote(gdb, f.ID, "   ", ""); err == nil {
		t.Error("expected error on empty note")
	}
}

func TestSetFindingLabels_replacesSet(t *testing.T) {
	gdb := newTestDB(t)
	f := seedFinding(t, gdb)

	if err := SetFindingLabels(gdb, f.ID, []string{"wontfix", "needs-info"}); err != nil {
		t.Fatal(err)
	}
	var refreshed Finding
	gdb.Preload("Labels").First(&refreshed, f.ID)
	if len(refreshed.Labels) != 2 {
		t.Fatalf("labels len = %d, want 2", len(refreshed.Labels))
	}

	if err := SetFindingLabels(gdb, f.ID, []string{"duplicate"}); err != nil {
		t.Fatal(err)
	}
	var again Finding
	gdb.Preload("Labels").First(&again, f.ID)
	if len(again.Labels) != 1 || again.Labels[0].Name != "duplicate" {
		t.Errorf("expected only duplicate label, got %+v", again.Labels)
	}
}

func TestSeedDefaultLabels_idempotent(t *testing.T) {
	gdb := newTestDB(t)
	if err := SeedDefaultLabels(gdb); err != nil {
		t.Fatal(err)
	}
	var count1 int64
	gdb.Model(&FindingLabel{}).Count(&count1)
	if err := SeedDefaultLabels(gdb); err != nil {
		t.Fatal(err)
	}
	var count2 int64
	gdb.Model(&FindingLabel{}).Count(&count2)
	if count1 != count2 {
		t.Errorf("second seed inserted rows: %d -> %d", count1, count2)
	}
}
