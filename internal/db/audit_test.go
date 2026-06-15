package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAddFindingReview_rejectsUnknownVerdict(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "rej.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone}
	gdb.Create(&scan)
	f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Severity: "Low"}
	gdb.Create(&f)
	if _, err := AddFindingReview(gdb, f.ID, "definitely-real", "", "", "andrew"); err == nil {
		t.Errorf("AddFindingReview accepted free-text verdict")
	}
}

func TestAddFindingReview_storesAndListsNewestFirst(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "list.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone}
	gdb.Create(&scan)
	f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Severity: "Low"}
	gdb.Create(&f)

	if _, err := AddFindingReview(gdb, f.ID, "false_positive", "test fixture", "false_positive", "andrew"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := AddFindingReview(gdb, f.ID, "uncertain", "reconsidering", "false_positive", "andrew"); err != nil {
		t.Fatal(err)
	}
	rows, err := ListFindingReviews(gdb, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Verdict != "uncertain" || rows[1].Verdict != "false_positive" {
		t.Errorf("order wrong: %s, %s", rows[0].Verdict, rows[1].Verdict)
	}
}

func TestAuditQueue_includesLowRejectedAndRevalidatedNotTruePositive(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone}
	gdb.Create(&scan)
	low := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "low", Severity: "Low", Status: FindingNew}
	gdb.Create(&low)
	rejected := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rej", Severity: "High", Status: FindingRejected}
	gdb.Create(&rejected)
	revalFP := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rev-fp", Severity: "High", Status: FindingNew, LastRevalidateVerdict: "false_positive"}
	gdb.Create(&revalFP)
	highOK := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "high", Severity: "High", Status: FindingNew}
	gdb.Create(&highOK)
	revalTP := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rev-tp", Severity: "High", Status: FindingNew, LastRevalidateVerdict: "true_positive"}
	gdb.Create(&revalTP)

	rows, err := AuditQueue(gdb, AuditQueueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint]bool{}
	for _, r := range rows {
		got[r.ID] = true
	}
	if !got[low.ID] || !got[rejected.ID] || !got[revalFP.ID] {
		t.Errorf("queue missing low/rejected/revalidate=fp: got %v", got)
	}
	if got[highOK.ID] || got[revalTP.ID] {
		t.Errorf("queue included findings the automation pursued: got %v", got)
	}
}

func TestAuditQueue_excludesReviewedFindings(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "reviewed.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone}
	gdb.Create(&scan)
	low := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "low", Severity: "Low", Status: FindingNew}
	gdb.Create(&low)
	if _, err := AddFindingReview(gdb, low.ID, "false_positive", "ok", "", "andrew"); err != nil {
		t.Fatal(err)
	}
	rows, err := AuditQueue(gdb, AuditQueueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == low.ID {
			t.Errorf("reviewed finding %d still in queue", r.ID)
		}
	}
}

// TestAuditQueue_sinceFilterComparesInstants pins the fix for SQLite's
// text-based timestamp comparison: a created_at stored with a +02:00 offset
// must compare against a UTC Since by instant, not by lexical string order.
func TestAuditQueue_sinceFilterComparesInstants(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "since.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone}
	gdb.Create(&scan)
	f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "low", Severity: "Low", Status: FindingNew}
	gdb.Create(&f)

	// 2026-01-01 12:00 +02:00 == 2026-01-01 10:00 UTC. As text it sorts after
	// "2026-01-01 11:00...+00:00", so a naive >= comparison includes it even
	// though Since is an hour later.
	zone := time.FixedZone("E2", 2*3600)
	created := time.Date(2026, 1, 1, 12, 0, 0, 0, zone)
	gdb.Model(&Finding{}).Where("id = ?", f.ID).Update("created_at", created)

	count := func(since time.Time) int {
		rows, err := AuditQueue(gdb, AuditQueueOptions{Since: since})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	after := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	if n := count(after); n != 0 {
		t.Errorf("Since one hour after creation returned %d rows, want 0", n)
	}
	before := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	if n := count(before); n != 1 {
		t.Errorf("Since one hour before creation returned %d rows, want 1", n)
	}
}

func TestComputeAuditMetrics_agreementOnlyCountsKnownAutomatedOutcomes(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone}
	gdb.Create(&scan)
	mk := func(i uint) Finding {
		f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F" + string(rune('0'+i)), Severity: "Low"}
		gdb.Create(&f)
		return f
	}
	f1, f2, f3, f4 := mk(1), mk(2), mk(3), mk(4)

	_, _ = AddFindingReview(gdb, f1.ID, "false_positive", "", "false_positive", "andrew") // agree
	_, _ = AddFindingReview(gdb, f2.ID, "true_positive", "", "false_positive", "andrew")  // overturn
	_, _ = AddFindingReview(gdb, f3.ID, "uncertain", "", "uncertain", "andrew")           // agree
	_, _ = AddFindingReview(gdb, f4.ID, "true_positive", "", "", "andrew")                // no auto outcome; excluded

	m, err := ComputeAuditMetrics(gdb)
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalReviews != 4 {
		t.Errorf("total = %d, want 4", m.TotalReviews)
	}
	if m.WithAutomatedOutcome != 3 {
		t.Errorf("with-automated = %d, want 3", m.WithAutomatedOutcome)
	}
	if m.Agreements != 2 {
		t.Errorf("agreements = %d, want 2", m.Agreements)
	}
	if got := m.AgreementRate; got < 0.66 || got > 0.67 {
		t.Errorf("agreement rate = %v, want ~0.667", got)
	}
}

func TestLatestRevalidateVerdict(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "lv.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := Scan{RepositoryID: repo.ID, Status: ScanDone}
	gdb.Create(&scan)
	f := Finding{ScanID: scan.ID, RepositoryID: repo.ID, Severity: "High"}
	gdb.Create(&f)

	if got := LatestRevalidateVerdict(gdb, f.ID); got != "" {
		t.Errorf("no notes: got %q, want empty", got)
	}
	_, _ = AddFindingNote(gdb, f.ID, "revalidate: false_positive\n\nfixture path", "revalidate")
	if got := LatestRevalidateVerdict(gdb, f.ID); got != "false_positive" {
		t.Errorf("got %q, want false_positive", got)
	}
	time.Sleep(2 * time.Millisecond)
	_, _ = AddFindingNote(gdb, f.ID, "revalidate: true_positive\n\nsink reachable", "revalidate")
	if got := LatestRevalidateVerdict(gdb, f.ID); got != "true_positive" {
		t.Errorf("latest: got %q, want true_positive", got)
	}
}
