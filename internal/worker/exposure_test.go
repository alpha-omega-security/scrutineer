package worker

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func newExposureWorker(t *testing.T) *Worker {
	t.Helper()
	gdb, err := db.Open("file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	return &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
}

func seedExposureFixtures(t *testing.T, w *Worker) (db.Scan, db.Skill, db.Dependent) {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/example/lib", Name: "lib"}
	if err := w.DB.Create(&repo).Error; err != nil {
		t.Fatalf("seed repo: %v", err)
	}
	dep := db.Dependent{RepositoryID: repo.ID, Name: "downstream",
		RepositoryURL: "https://github.com/example/downstream"}
	if err := w.DB.Create(&dep).Error; err != nil {
		t.Fatalf("seed dependent: %v", err)
	}
	parentScan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanDone}
	if err := w.DB.Create(&parentScan).Error; err != nil {
		t.Fatalf("seed parent scan: %v", err)
	}
	f := db.Finding{ScanID: parentScan.ID, RepositoryID: repo.ID, Title: "x"}
	if err := w.DB.Create(&f).Error; err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobExposure, Status: db.ScanRunning}
	scan.FindingID = &f.ID
	scan.DependentID = &dep.ID
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	skill := db.Skill{Name: "exposure", Body: "x"}
	if err := w.DB.Create(&skill).Error; err != nil {
		t.Fatalf("seed skill: %v", err)
	}
	return scan, skill, dep
}

func TestParseExposureOutput_knownNotAffected(t *testing.T) {
	w := newExposureWorker(t)
	scan, skill, dep := seedExposureFixtures(t, w)

	report := `{"status":"known_not_affected","justification":"vulnerable_code_not_in_execute_path","rationale":"only test code reaches it","spec_version":1}`
	if err := w.parseExposureOutput(&skill, &scan, dep.ID, report, func(Event) {}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var row db.FindingDependent
	if err := w.DB.Where("finding_id = ? AND dependent_id = ?", *scan.FindingID, dep.ID).First(&row).Error; err != nil {
		t.Fatalf("row: %v", err)
	}
	if row.Status != db.ExposureKnownNotAffected {
		t.Errorf("status = %q", row.Status)
	}
	if row.Justification != db.JustifVulnerableCodeNotInPath {
		t.Errorf("justification = %q", row.Justification)
	}
}

func TestParseExposureOutput_dropsJustificationWhenAffected(t *testing.T) {
	w := newExposureWorker(t)
	scan, skill, dep := seedExposureFixtures(t, w)

	report := `{"status":"known_affected","justification":"vulnerable_code_not_present","spec_version":1}`
	if err := w.parseExposureOutput(&skill, &scan, dep.ID, report, func(Event) {}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var row db.FindingDependent
	w.DB.Where("finding_id = ? AND dependent_id = ?", *scan.FindingID, dep.ID).First(&row)
	if row.Justification != "" {
		t.Errorf("justification should be dropped on known_affected, got %q", row.Justification)
	}
}

func TestParseExposureOutput_unknownStatusFallsBack(t *testing.T) {
	w := newExposureWorker(t)
	scan, skill, dep := seedExposureFixtures(t, w)

	report := `{"status":"maybe","spec_version":1}`
	if err := w.parseExposureOutput(&skill, &scan, dep.ID, report, func(Event) {}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	var row db.FindingDependent
	w.DB.Where("finding_id = ? AND dependent_id = ?", *scan.FindingID, dep.ID).First(&row)
	if row.Status != db.ExposureUnderInvestigation {
		t.Errorf("status = %q, want under_investigation fallback", row.Status)
	}
}

func TestParseExposureOutput_invalidJSON(t *testing.T) {
	w := newExposureWorker(t)
	scan, skill, dep := seedExposureFixtures(t, w)
	if err := w.parseExposureOutput(&skill, &scan, dep.ID, "not-json", func(Event) {}); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestParseExposureOutputReportsGenericValidationFailure(t *testing.T) {
	w := newExposureWorker(t)
	scan, skill, dep := seedExposureFixtures(t, w)
	skill.SchemaJSON = `{"type":"object","required":["status"]}`
	var events []Event
	if err := w.parseExposureOutput(&skill, &scan, dep.ID, `{}`, func(event Event) {
		events = append(events, event)
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, event := range events {
		if strings.Contains(event.Text, "validation: report.json does not pass Scrutineer report validation") {
			return
		}
	}
	t.Fatalf("validation event missing from %#v", events)
}

func TestParseExposureOutput_upsertsExistingRow(t *testing.T) {
	w := newExposureWorker(t)
	scan, skill, dep := seedExposureFixtures(t, w)

	if err := w.DB.Create(&db.FindingDependent{
		FindingID:     *scan.FindingID,
		DependentID:   dep.ID,
		Status:        db.ExposureUnderInvestigation,
		Justification: "old justification",
		Rationale:     "old rationale",
		ScanCommit:    "old-commit",
	}).Error; err != nil {
		t.Fatalf("seed finding dependent: %v", err)
	}
	scan.Commit = "new-commit"
	report := `{"status":"known_not_affected","justification":"vulnerable_code_not_in_execute_path","rationale":"new rationale","spec_version":1}`
	if err := w.parseExposureOutput(&skill, &scan, dep.ID, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var rows []db.FindingDependent
	w.DB.Where("finding_id = ? AND dependent_id = ?", *scan.FindingID, dep.ID).Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("expected upsert, got %d rows", len(rows))
	}
	row := rows[0]
	if row.Status != db.ExposureKnownNotAffected {
		t.Errorf("status = %q", row.Status)
	}
	if row.Justification != db.JustifVulnerableCodeNotInPath || row.Rationale != "new rationale" {
		t.Errorf("verdict fields = %+v", row)
	}
	if row.ScanID == nil || *row.ScanID != scan.ID || row.ScanCommit != scan.Commit {
		t.Errorf("scan fields = %+v", row)
	}
}

func TestDependentCacheRoot_keyedByURL(t *testing.T) {
	a := dependentCacheRoot("/data", "https://github.com/a/b")
	b := dependentCacheRoot("/data", "https://github.com/a/b")
	c := dependentCacheRoot("/data", "https://github.com/c/d")
	if a != b {
		t.Errorf("same URL must yield same path: %s vs %s", a, b)
	}
	if a == c {
		t.Errorf("different URLs must yield different paths")
	}
}
