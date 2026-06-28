package worker

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestParseFindingsOutput_capturesSnippetAndRefreshesOnReobserve(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[{"id":"F1","title":"t","severity":"High","location":"main.go:10"}]}`

	// Scan 1: checkout on disk, snippet captured around line 10.
	scan1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanDone, Commit: "aaa"}
	gdb.Create(scan1)
	writeNumberedFile(t, filepath.Join(w.scanWorkRoot(scan1), "src"), "main.go", 20)
	if err := w.parseFindingsOutput(&db.Skill{}, scan1, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	var f db.Finding
	gdb.First(&f)
	if !strings.Contains(f.Snippet, "line 10") || !strings.Contains(f.Snippet, "line 5") {
		t.Fatalf("ingest did not capture snippet: %q", f.Snippet)
	}
	first := f.Snippet

	// Scan 2: checkout present but the code drifted; the snippet refreshes.
	scan2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanDone, Commit: "bbb"}
	gdb.Create(scan2)
	src2 := filepath.Join(w.scanWorkRoot(scan2), "src")
	if err := os.MkdirAll(src2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src2, "main.go"),
		[]byte("a\nb\nc\nd\ne\nf\ng\nh\ni\nDRIFTED\nk\nl\nm\nn\no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := w.parseFindingsOutput(&db.Skill{}, scan2, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	gdb.First(&f)
	if !strings.Contains(f.Snippet, "DRIFTED") || f.Snippet == first {
		t.Errorf("re-observe with a present checkout did not refresh snippet: %q", f.Snippet)
	}
	drifted := f.Snippet

	// Scan 3: checkout evicted; the stored snippet must survive, not be wiped.
	scan3 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanDone, Commit: "ccc"}
	gdb.Create(scan3)
	if err := w.parseFindingsOutput(&db.Skill{}, scan3, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	gdb.First(&f)
	if f.Snippet != drifted {
		t.Errorf("re-observe without a checkout wiped snippet: was %q now %q", drifted, f.Snippet)
	}

	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 1 {
		t.Errorf("expected one deduped finding row, got %d", n)
	}
}

func TestParseFindingsOutput_referencesCreatedOnNewAndUpsertedOnReobserve(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	scan1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "zizmor", Status: db.ScanDone, Commit: "aaa"}
	gdb.Create(scan1)
	report1 := `{"findings":[{
		"id":"F1","title":"artipacked","severity":"Medium","location":".github/workflows/x.yml:18",
		"references":[{"url":"https://docs.zizmor.sh/audits/#artipacked","summary":"zizmor docs: artipacked","tags":"docs"}]
	}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, scan1, report1, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var refs []db.FindingReference
	gdb.Find(&refs)
	if len(refs) != 1 || refs[0].URL != "https://docs.zizmor.sh/audits/#artipacked" || refs[0].Tags != "docs" {
		t.Fatalf("after first scan: refs = %+v, want one docs reference", refs)
	}

	// Re-observe the same finding with the same docs reference plus a new one;
	// only the new URL should be inserted, the existing row is not duplicated.
	scan2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "zizmor", Status: db.ScanDone, Commit: "bbb"}
	gdb.Create(scan2)
	report2 := `{"findings":[{
		"id":"F1","title":"artipacked","severity":"Medium","location":".github/workflows/x.yml:18",
		"references":[
			{"url":"https://docs.zizmor.sh/audits/#artipacked","summary":"zizmor docs: artipacked","tags":"docs"},
			{"url":"https://example.com/blog/artipacked","summary":"blog","tags":"article"}
		]
	}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, scan2, report2, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	gdb.Order("url").Find(&refs)
	if len(refs) != 2 {
		t.Fatalf("after re-observe: %d references, want 2 (existing + new)", len(refs))
	}
	if refs[0].URL != "https://docs.zizmor.sh/audits/#artipacked" || refs[1].URL != "https://example.com/blog/artipacked" {
		t.Errorf("references not upserted as expected: %+v", refs)
	}

	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 1 {
		t.Errorf("expected dedup: 1 finding row, got %d", n)
	}
}

func TestParseFindingsOutput_minConfidenceDropsBelowThreshold(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone}
	gdb.Create(scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[
		{"id":"F1","title":"a","severity":"High","cwe":"CWE-1","location":"a.rb:1","confidence":"high"},
		{"id":"F2","title":"b","severity":"High","cwe":"CWE-2","location":"b.rb:1","confidence":"low"},
		{"id":"F3","title":"c","severity":"High","cwe":"CWE-3","location":"c.rb:1"}
	]}`
	skill := &db.Skill{MinConfidence: "medium"}
	var lines []string
	emit := func(e Event) { lines = append(lines, e.Text) }

	if err := w.parseFindingsOutput(skill, scan, report, emit); err != nil {
		t.Fatal(err)
	}
	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 1 {
		t.Errorf("stored %d findings, want 1 (only high-confidence)", n)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "dropped 2 finding(s) below min_confidence=medium") {
		t.Errorf("expected drop log line, got: %s", joined)
	}
}

func TestParseFindingsOutput_failOnTriggers(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone}
	gdb.Create(scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[
		{"id":"F1","title":"a","severity":"Medium","cwe":"CWE-1","location":"a.rb:1"},
		{"id":"F2","title":"b","severity":"Critical","cwe":"CWE-2","location":"b.rb:1"}
	]}`
	skill := &db.Skill{FailOn: "High"}
	err = w.parseFindingsOutput(skill, scan, report, func(Event) {})
	var fe *FailOnThresholdError
	if !errors.As(err, &fe) {
		t.Fatalf("expected FailOnThresholdError, got %v", err)
	}
	if fe.Worst != "Critical" || fe.Threshold != "High" {
		t.Errorf("error fields: %+v", fe)
	}
	var n int64
	gdb.Model(&db.Finding{}).Count(&n)
	if n != 2 {
		t.Errorf("findings should still be stored on fail_on, got %d", n)
	}
}

func TestParseFindingsOutput_failOnNoTriggerBelowThreshold(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "x", Status: db.ScanDone}
	gdb.Create(scan)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[{"id":"F1","title":"a","severity":"Low","cwe":"CWE-1","location":"a.rb:1"}]}`
	if err := w.parseFindingsOutput(&db.Skill{FailOn: "High"}, scan, report, func(Event) {}); err != nil {
		t.Errorf("Low finding should not trigger fail_on=High: %v", err)
	}
}

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
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report1, emit); err != nil {
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
	if err := w.parseFindingsOutput(&db.Skill{}, s2, report2, emit); err != nil {
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
	if f1.MissedCount != 0 {
		t.Errorf("F1 reappeared, missed count should be 0, got %d", f1.MissedCount)
	}

	// F2 did not reappear: last-seen stays at s1, missed count bumped.
	f2 := after2[1]
	if f2.LastSeenScanID != s1.ID || f2.SeenCount != 1 {
		t.Errorf("F2 last-seen should be unchanged: %+v", f2)
	}
	if f2.MissedCount != 1 || f2.LastMissedScanID != s2.ID {
		t.Errorf("F2 should be marked not-observed by s2: missed=%d last_missed=%d",
			f2.MissedCount, f2.LastMissedScanID)
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
	// History row for the miss.
	var miss []db.FindingHistory
	gdb.Where("finding_id = ? AND field = ?", f2.ID, "not_observed").Find(&miss)
	if len(miss) != 1 || miss[0].By != "security-deep-dive" {
		t.Errorf("want one not_observed history row for F2, got %+v", miss)
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
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report, emit); err != nil {
		t.Fatal(err)
	}

	// Analyst rejects it.
	gdb.Model(&db.Finding{}).Where("repository_id = ?", repo.ID).Update("status", db.FindingRejected)

	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep", Status: db.ScanDone, Commit: "def"}
	gdb.Create(s2)
	if err := w.parseFindingsOutput(&db.Skill{}, s2, report, emit); err != nil {
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

func TestParseFindingsOutput_intraScanCollisionMergesLocations(t *testing.T) {
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
	if err := w.parseFindingsOutput(&db.Skill{}, s, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var rows []db.Finding
	gdb.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("intra-scan fingerprint collision should yield one row, got %d", len(rows))
	}
	if s.FindingsCount != 1 {
		t.Errorf("scan.FindingsCount should report grouped findings (1), got %d", s.FindingsCount)
	}
	f := rows[0]
	if f.Location != "q.go:10" {
		t.Errorf("primary Location = %q, want first match q.go:10", f.Location)
	}
	if f.Locations != "q.go:10\nq.go:20" {
		t.Errorf("Locations = %q, want both match positions joined", f.Locations)
	}
	if f.ExtraLocationCount() != 1 {
		t.Errorf("ExtraLocationCount = %d, want 1", f.ExtraLocationCount())
	}
}

func TestParseFindingsOutput_locationsArrayFromReport(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	report := `{"findings":[{
		"id":"F1","title":"var-in-href","severity":"Medium","cwe":"CWE-79",
		"location":"a.html:5",
		"locations":["a.html:5","a.html:12","b.html:3"]
	}]}`
	s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s)
	if err := w.parseFindingsOutput(&db.Skill{}, s, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.Locations != "a.html:5\na.html:12\nb.html:3" {
		t.Errorf("Locations = %q, want array joined and primary deduped", f.Locations)
	}
	if got := f.LocationList(); len(got) != 3 || got[2] != "b.html:3" {
		t.Errorf("LocationList = %v, want 3 entries", got)
	}
	if f.ExtraLocationCount() != 2 {
		t.Errorf("ExtraLocationCount = %d, want 2", f.ExtraLocationCount())
	}
}

func TestParseFindingsOutput_rescanRefreshesLocations(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep",
			Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}

	report1 := `{"findings":[{"id":"F1","title":"x","severity":"Low","cwe":"CWE-79",
		"location":"a.html:5","locations":["a.html:5","a.html:12","a.html:30"]}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("abc"), report1, emit); err != nil {
		t.Fatal(err)
	}

	// Upstream fixes one occurrence and shifts another; rescan reports two.
	report2 := `{"findings":[{"id":"F1","title":"x","severity":"Low","cwe":"CWE-79",
		"location":"a.html:7","locations":["a.html:7","a.html:30"]}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("def"), report2, emit); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.Location != "a.html:7" {
		t.Errorf("rescan should refresh primary location: %q", f.Location)
	}
	if f.Locations != "a.html:7\na.html:30" {
		t.Errorf("rescan should replace location set, not accumulate: %q", f.Locations)
	}
	if f.SeenCount != 2 {
		t.Errorf("SeenCount = %d, want 2", f.SeenCount)
	}
}

func TestParseFindingsOutput_notObservedScopedToSkillAndSubpath(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`

	// security-deep-dive at root finds F1.
	s1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
		SubPath: "", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s1)
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report, emit); err != nil {
		t.Fatal(err)
	}

	// semgrep at root finds nothing. Different skill: must not mark F1 missed.
	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "semgrep",
		SubPath: "", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s2)
	if err := w.parseFindingsOutput(&db.Skill{}, s2, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	// security-deep-dive on subpath "pkg/foo" finds nothing. Different
	// subpath: must not mark F1 missed.
	s3 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
		SubPath: "pkg/foo", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s3)
	if err := w.parseFindingsOutput(&db.Skill{}, s3, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.MissedCount != 0 {
		t.Errorf("out-of-scope rescans must not mark F1 missed: missed=%d", f.MissedCount)
	}

	// security-deep-dive at root finds nothing. In scope: F1 missed.
	s4 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
		SubPath: "", Status: db.ScanDone, Commit: "def"}
	gdb.Create(s4)
	if err := w.parseFindingsOutput(&db.Skill{}, s4, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	gdb.First(&f)
	if f.MissedCount != 1 || f.LastMissedScanID != s4.ID {
		t.Errorf("in-scope rescan should mark F1 missed: missed=%d last_missed=%d",
			f.MissedCount, f.LastMissedScanID)
	}
}

func TestParseFindingsOutput_reobservationResetsMissedCount(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`
	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
			Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}

	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("aaa"), report, emit); err != nil {
		t.Fatal(err)
	}
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("bbb"), `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("ccc"), `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.MissedCount != 2 {
		t.Fatalf("after two empty rescans MissedCount = %d, want 2", f.MissedCount)
	}

	// Reappears: missed count resets, seen count is now 2.
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("ddd"), report, emit); err != nil {
		t.Fatal(err)
	}
	gdb.First(&f)
	if f.MissedCount != 0 || f.LastMissedScanID != 0 {
		t.Errorf("re-observation should reset missed: missed=%d last_missed=%d",
			f.MissedCount, f.LastMissedScanID)
	}
	if f.SeenCount != 2 || f.LastSeenCommit != "ddd" {
		t.Errorf("seen=%d last_seen_commit=%q, want 2/ddd", f.SeenCount, f.LastSeenCommit)
	}
}

func TestParseFindingsOutput_autoRejectReversibility(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), AutoRejectMissedCount: 2}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`
	mkScan := func(commit string) *db.Scan {
		s := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "security-deep-dive",
			Status: db.ScanDone, Commit: commit}
		gdb.Create(s)
		return s
	}

	// 1. Initial observation
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("aaa"), report, emit); err != nil {
		t.Fatal(err)
	}

	// Set the status to triaged manually to verify it restores to triaged, not new
	var f db.Finding
	gdb.First(&f)
	gdb.Model(&f).Update("status", db.FindingTriaged)
	gdb.Create(&db.FindingHistory{FindingID: f.ID, Field: "status", OldValue: "new", NewValue: "triaged", Source: db.SourceAnalyst, By: "test"})

	// 2. Missed twice -> auto-rejected
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("bbb"), `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("ccc"), `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	gdb.First(&f)
	if f.Status != db.FindingRejected {
		t.Fatalf("finding should be auto-rejected after 2 misses, got %s", f.Status)
	}

	// 3. Re-observed -> status restored
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("ddd"), report, emit); err != nil {
		t.Fatal(err)
	}

	gdb.First(&f)
	if f.Status != db.FindingTriaged {
		t.Fatalf("finding should be restored to triaged, got %s", f.Status)
	}

	var hist db.FindingHistory
	gdb.Where("finding_id = ? AND field = 'status'", f.ID).Order("id desc").First(&hist)
	if hist.Source != db.SourceSystem || hist.NewValue != "triaged" {
		t.Errorf("expected SourceSystem reopen history row, got source=%s new_value=%s", hist.Source, hist.NewValue)
	}

	// 4. Analyst rejects it
	gdb.Model(&f).Update("status", db.FindingRejected)
	gdb.Create(&db.FindingHistory{FindingID: f.ID, Field: "status", OldValue: "triaged", NewValue: "rejected", Source: db.SourceAnalyst, By: "tester"})

	// 5. Re-observed again -> remains rejected because last change was analyst
	if err := w.parseFindingsOutput(&db.Skill{}, mkScan("eee"), report, emit); err != nil {
		t.Fatal(err)
	}

	gdb.First(&f)
	if f.Status != db.FindingRejected {
		t.Fatalf("analyst-rejected finding should not reopen, got %s", f.Status)
	}
}

func TestParseFindingsOutput_notObservedSkipsClosedFindings(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	emit := func(Event) {}

	report := `{"findings":[{"id":"F1","title":"x","severity":"High","cwe":"CWE-89","location":"a.rb:1"}]}`
	s1 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "k", Status: db.ScanDone, Commit: "abc"}
	gdb.Create(s1)
	if err := w.parseFindingsOutput(&db.Skill{}, s1, report, emit); err != nil {
		t.Fatal(err)
	}
	gdb.Model(&db.Finding{}).Where("repository_id = ?", repo.ID).Update("status", db.FindingFixed)

	s2 := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "k", Status: db.ScanDone, Commit: "def"}
	gdb.Create(s2)
	if err := w.parseFindingsOutput(&db.Skill{}, s2, `{"findings":[]}`, emit); err != nil {
		t.Fatal(err)
	}

	var f db.Finding
	gdb.First(&f)
	if f.MissedCount != 0 {
		t.Errorf("closed finding should not accrue missed count: missed=%d", f.MissedCount)
	}
}
