package db

import (
	"fmt"
	"testing"

	"gorm.io/gorm"
)

func seedSiblingFinding(t *testing.T, gdb *gorm.DB, base Finding, status FindingLifecycle, duplicateOf uint) Finding {
	t.Helper()
	f := Finding{ScanID: base.ScanID, RepositoryID: base.RepositoryID, Title: "t", Severity: "High", Status: status, DuplicateOfID: duplicateOf}
	if err := gdb.Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	return f
}

func subsumedNote(parent uint) FindingNote {
	return FindingNote{Body: fmt.Sprintf("%s%d\n\nreason", SubsumedNotePrefix, parent)}
}

func TestSubsumingParent(t *testing.T) {
	gdb := newTestDB(t)
	self := seedFinding(t, gdb)
	open := seedSiblingFinding(t, gdb, self, FindingTriaged, 0)
	dupOfSelf := seedSiblingFinding(t, gdb, self, FindingDuplicate, self.ID)
	dupOfOpen := seedSiblingFinding(t, gdb, self, FindingDuplicate, open.ID)
	dupOfDupOfSelf := seedSiblingFinding(t, gdb, self, FindingDuplicate, dupOfSelf.ID)
	unlinkedDup := seedSiblingFinding(t, gdb, self, FindingDuplicate, 0)
	cycleA := seedSiblingFinding(t, gdb, self, FindingDuplicate, 0)
	cycleB := seedSiblingFinding(t, gdb, self, FindingDuplicate, cycleA.ID)
	if err := gdb.Model(&cycleA).Update("duplicate_of_id", cycleB.ID).Error; err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		notes []FindingNote
		want  uint
	}{
		{"no notes", nil, 0},
		{"other notes", []FindingNote{{Body: "finding-dedup: chains with finding #9"}, {Body: "analyst note"}}, 0},
		{"open parent", []FindingNote{subsumedNote(open.ID)}, open.ID},
		{"parent later merged into this finding", []FindingNote{subsumedNote(dupOfSelf.ID)}, 0},
		{"parent merged into this finding through a chain", []FindingNote{subsumedNote(dupOfDupOfSelf.ID)}, 0},
		{"parent merged into another finding", []FindingNote{subsumedNote(dupOfOpen.ID)}, open.ID},
		{"stale note then a live one", []FindingNote{subsumedNote(dupOfSelf.ID), subsumedNote(open.ID)}, open.ID},
		{"duplicate without a canonical", []FindingNote{subsumedNote(unlinkedDup.ID)}, unlinkedDup.ID},
		{"duplicate cycle", []FindingNote{subsumedNote(cycleA.ID)}, cycleA.ID},
		{"missing parent", []FindingNote{subsumedNote(99999)}, 99999},
		{"note naming itself", []FindingNote{subsumedNote(self.ID)}, 0},
		{"no id", []FindingNote{{Body: SubsumedNotePrefix + "x"}}, 0},
		{"marker not on the first line", []FindingNote{{Body: "x\n" + SubsumedNotePrefix + "5"}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SubsumingParent(gdb, self, tt.notes)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("SubsumingParent = %d, want %d", got, tt.want)
			}
		})
	}
}
