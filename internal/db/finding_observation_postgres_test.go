package db

import (
	"testing"

	"scrutineer/internal/testutil"
)

// TestPostgresFindingObservations runs the upsert and duplicate walk on PostgreSQL.
func TestPostgresFindingObservations(t *testing.T) {
	gdb, err := OpenBackend(Options{Dialect: DialectPostgres, DSN: testutil.PostgresDSN(t)})
	if err != nil {
		t.Fatalf("OpenBackend postgres: %v", err)
	}
	closePostgres(t, gdb)

	repo := Repository{URL: "https://example.com/pg/observations", Name: "pg-observations"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	first := Scan{RepositoryID: repo.ID, Commit: "aaa111", Model: "model-a", Backend: "claude", Status: ScanDone}
	second := Scan{RepositoryID: repo.ID, Commit: "bbb222", Model: "model-b", Backend: "codex", Status: ScanDone}
	for _, s := range []*Scan{&first, &second} {
		if err := gdb.Create(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	canonical := Finding{ScanID: first.ID, RepositoryID: repo.ID, Title: "canonical", Severity: "High"}
	if err := gdb.Create(&canonical).Error; err != nil {
		t.Fatal(err)
	}
	dup := Finding{ScanID: second.ID, RepositoryID: repo.ID, Title: "dup", Severity: "Low",
		Status: FindingDuplicate, DuplicateOfID: canonical.ID}
	if err := gdb.Create(&dup).Error; err != nil {
		t.Fatal(err)
	}

	preview := ObservationFromFinding(&first, &Finding{ID: canonical.ID, Title: "preview", Severity: "Medium"})
	final := ObservationFromFinding(&first, &Finding{ID: canonical.ID, Title: "final", Severity: "High", Trace: "a -> b"})
	other := ObservationFromFinding(&second, &Finding{ID: dup.ID, Title: "dup", Severity: "Low"})
	if err := RecordFindingObservation(gdb, preview); err != nil {
		t.Fatalf("record preview: %v", err)
	}
	if err := RecordFindingObservation(gdb, final, other); err != nil {
		t.Fatalf("record batch: %v", err)
	}

	rows, _, err := FindingContributions(gdb, canonical.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("contributions = %d rows, want 2: %+v", len(rows), rows)
	}
	got := map[uint]FindingObservation{}
	for _, r := range rows {
		got[r.ScanID] = r
	}
	if o := got[first.ID]; o.Title != "final" || o.Severity != "High" || o.Commit != "aaa111" || o.Evidence == "" {
		t.Errorf("first scan observation = %+v, want the final report", o)
	}
	if o := got[second.ID]; o.FindingID != dup.ID || o.Severity != "Low" || o.Backend != "codex" || o.Model != "model-b" {
		t.Errorf("duplicate observation = %+v", o)
	}
}
