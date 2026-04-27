package worker

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
)

func TestParseFindingsOutput_dedupesAcrossScans(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
			Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}

	// Scan 1: two findings.
	report1 := `{"findings":[
		{"id":"F1","title":"SQLi in users","severity":"High","cwe":"CWE-89","location":"src/users.rb:42"},
		{"id":"F2","title":"XSS in view","severity":"Medium","cwe":"CWE-79","location":"src/view.erb:10"}
	]}`
	s1 := mkScan("abc")
	if err := w.parseFindingsOutput(s1, report1, emit); err != nil {
		t.Fatal(err)
	}

	var after1 []db.Finding
	gdb.Order("id").Find(&after1)
	if len(after1) != 2 {
		t.Fatalf("after first scan: %d findings, want 2", len(after1))
	}
	if after1[0].SeenCount != 1 || after1[0].LastSeenScanID != s1.ID {
		t.Errorf("new finding seen-count/last-seen wrong: %+v", after1[0])
	}

	// Scan 2: F1 reappears at a different line, F2 gone, new F3.
	report2 := `{"findings":[
		{"id":"F1","title":"SQL injection in users","severity":"High","cwe":"CWE-89","location":"src/users.rb:77"},
		{"id":"F3","title":"Path traversal","severity":"High","cwe":"CWE-22","location":"src/files.rb:5"}
	]}`
	s2 := mkScan("def")
	if err := w.parseFindingsOutput(s2, report2, emit); err != nil {
		t.Fatal(err)
	}

	var after2 []db.Finding
	gdb.Order("id").Find(&after2)
	if len(after2) != 3 {
		t.Fatalf("after second scan: %d findings, want 3 (F1 deduped, F3 new)", len(after2))
	}

	// F1 (first row) should have last-seen bumped, seen=2, but ScanID/Commit
	// (first-seen) and Title unchanged.
	f1 := after2[0]
	if f1.ScanID != s1.ID || f1.Commit != "abc" {
		t.Errorf("F1 first-seen overwritten: scan=%d commit=%q", f1.ScanID, f1.Commit)
	}
	if f1.LastSeenScanID != s2.ID || f1.LastSeenCommit != "def" || f1.SeenCount != 2 {
		t.Errorf("F1 last-seen not bumped: %+v", f1)
	}
	if f1.Title != "SQLi in users" {
		t.Errorf("F1 title overwritten by rescan: %q", f1.Title)
	}

	// F2 untouched.
	f2 := after2[1]
	if f2.LastSeenScanID != s1.ID || f2.SeenCount != 1 {
		t.Errorf("F2 should be unchanged: %+v", f2)
	}

	// F3 is new from scan 2.
	f3 := after2[2]
	if f3.ScanID != s2.ID || f3.CWE != "CWE-22" || f3.SeenCount != 1 {
		t.Errorf("F3: %+v", f3)
	}

	// History row for the re-observation.
	var hist []db.FindingHistory
	gdb.Where("finding_id = ? AND field = ?", f1.ID, "observed").Find(&hist)
	if len(hist) != 1 || hist[0].By != "security-deep-dive" {
		t.Errorf("want one observed history row for F1, got %+v", hist)
	}
}

func TestParseFindingsOutput_preservesAnalystStatusOnReobservation(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"noise","severity":"Low","cwe":"CWE-200","location":"x.go:1"}]}`
	s1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s1)
	if err := w.parseFindingsOutput(s1, report, emit); err != nil {
		t.Fatal(err)
	}

	// Analyst rejects it.
	gdb.Model(&db.Finding{}).Where("repository_id = ?", repo.ID).Update("status", db.FindingRejected)

	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep", Status: db.ScanDone, Commit: "def"}
	gdb.Create(s2)
	if err := w.parseFindingsOutput(s2, report, emit); err != nil {
		t.Fatal(err)
	}

	var rows []db.Finding
	gdb.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("rejected finding should still dedupe, got %d rows", len(rows))
	}
	if rows[0].Status != db.FindingRejected {
		t.Errorf("rescan must not resurrect a rejected finding: status=%s", rows[0].Status)
	}
	if rows[0].SeenCount != 2 {
		t.Errorf("seen count = %d, want 2", rows[0].SeenCount)
	}
}

func TestParseFindingsOutput_intraScanCollisionCreatesOneRow(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Same CWE, same file, two lines: file-level fingerprint collides.
	report := `{"findings":[
		{"id":"F1","title":"a","severity":"Low","cwe":"CWE-89","location":"q.go:10"},
		{"id":"F2","title":"b","severity":"Low","cwe":"CWE-89","location":"q.go:20"}
	]}`
	s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "k", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s)
	if err := w.parseFindingsOutput(s, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 1 {
		t.Errorf("intra-scan fingerprint collision should yield one row, got %d", n)
	}
	if s.FindingsCount != 2 {
		t.Errorf("scan.FindingsCount should report what the scan found (2), got %d", s.FindingsCount)
	}
}
