package worker

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

// betterEvidenceSetup returns a worker, a dedup scan, a canonical finding
// with a thin report and a duplicate with a fuller one.
func betterEvidenceSetup(t *testing.T, headStatus db.FindingLifecycle) (*Worker, db.Scan, db.Finding, db.Finding) {
	t.Helper()
	gdb := dbtest.Open(t)
	scan, fs := setupDedupRepo(t, gdb, 2)
	head, member := fs[0], fs[1]
	gdb.Model(&head).Updates(map[string]any{
		"status": headStatus, "title": "old title", "location": "a.c:1", "trace": "old trace",
		"validation": "old poc", "prior_art": "old prior art", "severity": "Medium", "cwe": "CWE-79",
	})
	gdb.Model(&member).Updates(map[string]any{
		"title": "clean title", "location": "b.c:9", "locations": "b.c:9\nb.c:10", "trace": "clear trace",
		"validation": "tiny poc", "prior_art": "matching prior art", "severity": "Critical", "cwe": "CWE-787",
	})
	gdb.First(&head, head.ID)
	gdb.First(&member, member.ID)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	return w, scan, head, member
}

func runBetterEvidence(t *testing.T, w *Worker, scan db.Scan, head uint, dups []uint, better uint) {
	t.Helper()
	ids := make([]string, len(dups))
	for i, d := range dups {
		ids[i] = fmt.Sprint(d)
	}
	report := fmt.Sprintf(`{"duplicates":[{"canonical_id":%d,"duplicate_ids":[%s],"better_evidence_id":%d,"reason":"same bug, cleaner report"}]}`,
		head, strings.Join(ids, ","), better)
	if err := w.parseFindingDedupOutput(&scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
}

func reloadFinding(gdb *gorm.DB, id uint) db.Finding {
	var f db.Finding
	gdb.First(&f, id)
	return f
}

func assertNotPromoted(t *testing.T, gdb *gorm.DB, head db.Finding) {
	t.Helper()
	got := reloadFinding(gdb, head.ID)
	if got.Title != head.Title || got.Trace != head.Trace || got.Validation != head.Validation || got.Location != head.Location {
		t.Errorf("head body changed: %+v", got)
	}
	var n int64
	gdb.Model(&db.FindingHistory{}).Where("finding_id = ? AND field = ?", head.ID, "trace").Count(&n)
	if n != 0 {
		t.Errorf("unexpected trace history rows: %d", n)
	}
}

func TestParseFindingDedup_betterEvidencePromotesOntoCanonical(t *testing.T) {
	w, scan, head, member := betterEvidenceSetup(t, db.FindingNew)
	if err := db.RecordFindingObservation(w.DB, db.FindingObservation{
		FindingID: head.ID, ScanID: scan.ID, RepositoryID: head.RepositoryID, Title: "old title", Evidence: "old trace",
	}); err != nil {
		t.Fatal(err)
	}
	runBetterEvidence(t, w, scan, head.ID, []uint{member.ID}, member.ID)

	got := reloadFinding(w.DB, head.ID)
	if got.Status != db.FindingNew || got.Severity != "Medium" || got.CWE != "CWE-79" {
		t.Errorf("assessment changed: status=%s severity=%s cwe=%s", got.Status, got.Severity, got.CWE)
	}
	if got.Title != "clean title" || got.Trace != "clear trace" || got.Validation != "tiny poc" ||
		got.PriorArt != "matching prior art" {
		t.Errorf("body not promoted: %+v", got)
	}
	if got.Location != head.Location || got.Locations != head.Locations {
		t.Errorf("location moved to %q / %q, want the canonical's %q / %q", got.Location, got.Locations, head.Location, head.Locations)
	}
	var locHist int64
	w.DB.Model(&db.FindingHistory{}).Where("finding_id = ? AND field IN ?", head.ID, []string{"location", "locations"}).Count(&locHist)
	if locHist != 0 {
		t.Errorf("unexpected location history rows: %d", locHist)
	}
	dup := reloadFinding(w.DB, member.ID)
	if dup.Status != db.FindingDuplicate || dup.DuplicateOfID != head.ID {
		t.Errorf("duplicate = %s of %d", dup.Status, dup.DuplicateOfID)
	}

	var hist db.FindingHistory
	if err := w.DB.Where("finding_id = ? AND field = ?", head.ID, "trace").First(&hist).Error; err != nil {
		t.Fatalf("missing trace history: %v", err)
	}
	if hist.Source != db.SourceModel || hist.By != findingDedupSkill || hist.OldValue != "old trace" || hist.NewValue != "clear trace" {
		t.Errorf("history = %+v", hist)
	}
	var sev int64
	w.DB.Model(&db.FindingHistory{}).Where("finding_id = ? AND field IN ?", head.ID, []string{"severity", "cwe", "status"}).Count(&sev)
	if sev != 0 {
		t.Errorf("assessment fields got history rows: %d", sev)
	}

	found := false
	for _, n := range findingNotes(w.DB, head.ID) {
		if strings.HasPrefix(n.Body, fmt.Sprintf("finding-dedup: took evidence from finding #%d", member.ID)) {
			found = true
		}
	}
	if !found {
		t.Errorf("missing evidence note: %+v", findingNotes(w.DB, head.ID))
	}

	obs := observationsOf(t, w, head.ID)
	if len(obs) != 1 || obs[0].Title != "old title" || obs[0].Evidence != "old trace" {
		t.Errorf("head observations changed: %+v", obs)
	}
}

func TestParseFindingDedup_betterEvidenceKeepsAnalystEdits(t *testing.T) {
	w, scan, head, member := betterEvidenceSetup(t, db.FindingTriaged)
	w.DB.Create(&db.FindingHistory{FindingID: head.ID, Field: "title", OldValue: "x", NewValue: "old title", Source: db.SourceAnalyst, By: "me"})
	runBetterEvidence(t, w, scan, head.ID, []uint{member.ID}, member.ID)

	got := reloadFinding(w.DB, head.ID)
	if got.Title != "old title" {
		t.Errorf("analyst title overwritten: %q", got.Title)
	}
	if got.Trace != "clear trace" || got.Validation != "tiny poc" {
		t.Errorf("other fields not promoted: %+v", got)
	}
}

func TestParseFindingDedup_betterEvidenceSkippedFromReady(t *testing.T) {
	for _, status := range []db.FindingLifecycle{db.FindingReady, db.FindingReported} {
		w, scan, head, member := betterEvidenceSetup(t, status)
		runBetterEvidence(t, w, scan, head.ID, []uint{member.ID}, member.ID)
		assertNotPromoted(t, w.DB, head)
		if dup := reloadFinding(w.DB, member.ID); dup.Status != db.FindingDuplicate {
			t.Errorf("%s: duplicate status = %s", status, dup.Status)
		}
	}
}

func TestParseFindingDedup_betterEvidenceMustNameAValidDuplicate(t *testing.T) {
	w, scan, head, member := betterEvidenceSetup(t, db.FindingNew)
	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	w.DB.Create(&other)
	foreign := db.Finding{ScanID: scan.ID, RepositoryID: other.ID, FindingID: "F9", Title: "foreign", Trace: "foreign trace", Status: db.FindingNew}
	w.DB.Create(&foreign)

	runBetterEvidence(t, w, scan, head.ID, []uint{member.ID}, foreign.ID)
	assertNotPromoted(t, w.DB, head)

	runBetterEvidence(t, w, scan, head.ID, []uint{foreign.ID}, foreign.ID)
	assertNotPromoted(t, w.DB, head)

	third := db.Finding{ScanID: scan.ID, RepositoryID: head.RepositoryID, FindingID: "F8", Title: "third", Trace: "third trace", Status: db.FindingNew}
	w.DB.Create(&third)
	runBetterEvidence(t, w, scan, head.ID, []uint{member.ID}, third.ID)
	assertNotPromoted(t, w.DB, head)
}

func TestParseFindingDedup_withoutBetterEvidenceLeavesBodyAlone(t *testing.T) {
	w, scan, head, member := betterEvidenceSetup(t, db.FindingNew)
	runBetterEvidence(t, w, scan, head.ID, []uint{member.ID}, 0)
	assertNotPromoted(t, w.DB, head)
	if dup := reloadFinding(w.DB, member.ID); dup.Status != db.FindingDuplicate {
		t.Errorf("duplicate status = %s", dup.Status)
	}
}

func TestParseFindingDedup_betterEvidenceKeepsValidationWithCapturedPoC(t *testing.T) {
	w, scan, head, member := betterEvidenceSetup(t, db.FindingNew)
	if err := w.DB.Create(&db.FindingPoC{FindingID: head.ID, ScanID: scan.ID, Files: []byte(`[]`)}).Error; err != nil {
		t.Fatal(err)
	}
	runBetterEvidence(t, w, scan, head.ID, []uint{member.ID}, member.ID)
	got := reloadFinding(w.DB, head.ID)
	if got.Validation != "old poc" {
		t.Errorf("validation = %q, want the text describing the captured PoC", got.Validation)
	}
	if got.Trace != "clear trace" {
		t.Errorf("trace = %q, other fields should still be promoted", got.Trace)
	}
}
