package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"log/slog"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newStreamWorker(t *testing.T) (*Worker, db.Repository) {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	return &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, repo
}

func TestPersistStreamedFinding_createsRowFromBody(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa", ScanGroup: "grp-1"}
	w.DB.Create(scan)

	body := []byte(`{"id":"F1","title":"t","severity":"High","location":"main.go:10",
		"dup_check":"compared against F0; distinct sink"}`)
	f, err := w.PersistStreamedFinding(scan, body)
	if err != nil {
		t.Fatal(err)
	}
	if f.ID == 0 {
		t.Fatal("streamed finding was not persisted")
	}
	if f.ScanID != scan.ID || f.RepositoryID != repo.ID || f.Commit != "aaa" {
		t.Errorf("scan identity not stamped from the scan: %+v", f)
	}
	if f.DupCheck != "compared against F0; distinct sink" {
		t.Errorf("dup_check = %q, want the emitted sentence", f.DupCheck)
	}
	if f.Fingerprint == "" {
		t.Error("streamed finding has no fingerprint, final report cannot reconcile against it")
	}
}

func TestPersistStreamedFinding_newFindingDoesNotLogRecordNotFound(t *testing.T) {
	base := dbtest.Open(t)
	var logs bytes.Buffer
	gdb := base.Session(&gorm.Session{
		Logger: logger.New(log.New(&logs, "", 0), logger.Config{LogLevel: logger.Warn}),
	})
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa"}
	gdb.Create(scan)
	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	_, err := w.PersistStreamedFinding(scan, []byte(`{"id":"F1","title":"t","severity":"High","location":"main.go:10"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "record not found") {
		t.Fatalf("expected new streamed finding to avoid noisy GORM miss log, got:\n%s", logs.String())
	}
}

// A finding streamed mid-scan and then re-ingested from the final report.json
// of the SAME scan must reconcile to one row without inflating seen_count or
// writing a spurious observed-again history row.
func TestPersistStreamedFinding_reconcilesWithFinalReport(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa", ScanGroup: "grp-1"}
	w.DB.Create(scan)

	if _, err := w.PersistStreamedFinding(scan, []byte(`{"id":"F1","title":"t","severity":"High","location":"main.go:10"}`)); err != nil {
		t.Fatal(err)
	}

	report := `{"findings":[{"id":"F1","title":"t","severity":"High","location":"main.go:10"}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var rows []db.Finding
	w.DB.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("streamed-then-final reconciled to %d rows, want 1", len(rows))
	}
	if rows[0].SeenCount != 1 {
		t.Errorf("seen_count = %d, want 1 (the same scan must not count a finding twice)", rows[0].SeenCount)
	}
	var observed int64
	w.DB.Model(&db.FindingHistory{}).Where("finding_id = ? AND field = ?", rows[0].ID, "observed").Count(&observed)
	if observed != 0 {
		t.Errorf("observed-again history rows = %d, want 0 for a same-scan reconcile", observed)
	}
}

// ownedByThisScan uses immutable ScanID to protect an earlier scan's content.
func TestPersistStreamedFinding_crossScanStreamThenReportKeepsPriorContent(t *testing.T) {
	w, repo := newStreamWorker(t)
	a := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanDone, Commit: "aaa"}
	w.DB.Create(a)
	original := db.Finding{
		ScanID: a.ID, RepositoryID: repo.ID, Commit: "aaa", LastSeenScanID: a.ID, SeenCount: 1,
		Title: "legit title", Severity: "High", Location: "main.go:10", CWE: "CWE-78",
		Trace: "triaged trace", Status: db.FindingTriaged,
		Fingerprint: db.FingerprintFinding("sd", "", "CWE-78", "main.go:10", "legit title"),
	}
	w.DB.Create(&original)

	b := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "bbb"}
	w.DB.Create(b)

	// Scan B streams the same fingerprint: cross-scan re-observation sets
	// last_seen_scan_id = B but must not touch content.
	if _, err := w.PersistStreamedFinding(b, []byte(`{"title":"legit title","severity":"Low","location":"main.go:10","cwe":"CWE-78"}`)); err != nil {
		t.Fatal(err)
	}
	// Scan B's final report tries to replace the content.
	report := `{"findings":[{"id":"F1","title":"legit title","severity":"Low","cwe":"CWE-78",
		"location":"main.go:10","trace":"attacker-controlled replacement"}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, b, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var got db.Finding
	w.DB.First(&got, original.ID)
	if got.ScanID != a.ID {
		t.Fatalf("ScanID rewritten to %d; creation ownership must be immutable", got.ScanID)
	}
	if got.Trace != "triaged trace" || got.Severity != "High" {
		t.Fatalf("cross-scan stream-then-report overwrote content: trace=%q severity=%q", got.Trace, got.Severity)
	}
	if got.LastSeenScanID != b.ID || got.SeenCount != 2 {
		t.Fatalf("re-observation accounting lost: last_seen=%d seen_count=%d", got.LastSeenScanID, got.SeenCount)
	}
}

func TestDoSkillCreatorReportRefreshesAfterSiblingStream(t *testing.T) {
	w, creator := costCapFixture(t, 0)
	if err := w.DB.Model(&db.Skill{}).Where("id = ?", *creator.SkillID).
		Updates(map[string]any{"name": "sd", "output_kind": "findings"}).Error; err != nil {
		t.Fatal(err)
	}
	sibling := db.Scan{RepositoryID: creator.RepositoryID, SkillID: creator.SkillID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "bbb"}
	if err := w.DB.Create(&sibling).Error; err != nil {
		t.Fatal(err)
	}
	var findingID uint
	w.Runner = &capRunner{first: func(_ context.Context, _ func(Event)) (SkillResult, error) {
		var running db.Scan
		if err := w.DB.First(&running, creator.ID).Error; err != nil {
			return SkillResult{}, err
		}
		finding, err := w.PersistStreamedFinding(&running, []byte(`{"title":"Preview","severity":"High","location":"main.go:10","cwe":"CWE-78"}`))
		if err != nil {
			return SkillResult{}, err
		}
		findingID = finding.ID
		if _, err := w.PersistStreamedFinding(&sibling, []byte(`{"title":"Sibling","severity":"Low","location":"main.go:10","cwe":"CWE-78"}`)); err != nil {
			return SkillResult{}, err
		}
		var observed db.Finding
		if err := w.DB.First(&observed, findingID).Error; err != nil {
			return SkillResult{}, err
		}
		if observed.ScanID != creator.ID || observed.LastSeenScanID != sibling.ID {
			return SkillResult{}, errors.New("sibling stream did not re-observe the creator's finding")
		}
		return SkillResult{Report: `{"findings":[{"id":"F1","title":"Final title","severity":"Critical","location":"main.go:10","cwe":"CWE-78","trace":"Creator final report"}]}`}, nil
	}}
	if scan := runCapScan(t, w, creator); scan.Status != db.ScanDone {
		t.Fatalf("creator scan: status=%s error=%s", scan.Status, scan.Error)
	}
	var got db.Finding
	if err := w.DB.First(&got, findingID).Error; err != nil {
		t.Fatal(err)
	}
	if got.ScanID != creator.ID || got.LastSeenScanID != creator.ID {
		t.Fatalf("finding ownership/last-seen = %d/%d, want creator %d", got.ScanID, got.LastSeenScanID, creator.ID)
	}
	if got.Title != "Final title" || got.Severity != "Critical" || got.Trace != "Creator final report" {
		t.Fatalf("creator's final content not persisted: title=%q severity=%q trace=%q", got.Title, got.Severity, got.Trace)
	}
}

// A finding streamed with only the required minimal fields and then
// reconciled with the same scan's final report must pick up the full
// parser-owned content of the final report: the streamed row is a preview,
// the report is the authoritative version of the same finding.
func TestPersistStreamedFinding_sameScanReconcileRefreshesFinalReportContent(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa", ScanGroup: "grp-1"}
	w.DB.Create(scan)

	if _, err := w.PersistStreamedFinding(scan, []byte(`{"title":"t","severity":"High","location":"main.go:10"}`)); err != nil {
		t.Fatal(err)
	}

	report := `{"findings":[{
		"id":"F1","title":"t","severity":"Critical","confidence":"High",
		"location":"main.go:22","locations":["main.go:22","util.go:7"],
		"sinks":["exec","eval"],"affected":"<= 2.4.1",
		"reachability":"reachable","quality_tier":"high",
		"trace":"user input reaches exec","boundary":"public HTTP handler",
		"validation":"no sanitisation on the path segment",
		"prior_art":"GHSA-xxxx-yyyy-zzzz","reach":"2 of 3 entry points exposed",
		"rating":"exploitable pre-auth","dup_check":"distinct sink from F2"
	}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var rows []db.Finding
	w.DB.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("streamed-then-final reconciled to %d rows, want 1", len(rows))
	}
	got := rows[0]
	for _, tc := range []struct{ field, got, want string }{
		{"finding_id", got.FindingID, "F1"},
		{"severity", got.Severity, "Critical"},
		{"confidence", got.Confidence, "high"},
		{"sinks", got.Sinks, "exec, eval"},
		{"location", got.Location, "main.go:22"},
		{"locations", got.Locations, "main.go:22\nutil.go:7"},
		{"affected", got.Affected, "<= 2.4.1"},
		{"reachability", got.Reachability, "reachable"},
		{"quality_tier", got.QualityTier, "high"},
		{"trace", got.Trace, "user input reaches exec"},
		{"boundary", got.Boundary, "public HTTP handler"},
		{"validation", got.Validation, "no sanitisation on the path segment"},
		{"prior_art", got.PriorArt, "GHSA-xxxx-yyyy-zzzz"},
		{"reach", got.Reach, "2 of 3 entry points exposed"},
		{"rating", got.Rating, "exploitable pre-auth"},
		{"dup_check", got.DupCheck, "distinct sink from F2"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want final-report value %q", tc.field, tc.got, tc.want)
		}
	}
}

// When the CWE carries the fingerprint the title is not folded in, so the
// final report may reword it; same-scan reconciliation must keep the final
// wording. Cross-scan re-observation deliberately keeps the original title
// (TestParseFindingsOutput_dedupesAcrossScans locks that in).
func TestPersistStreamedFinding_sameScanReconcileRefreshesRewordedTitle(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa", ScanGroup: "grp-1"}
	w.DB.Create(scan)

	if _, err := w.PersistStreamedFinding(scan, []byte(`{"title":"SQLi","severity":"High","cwe":"CWE-89","location":"db.go:5"}`)); err != nil {
		t.Fatal(err)
	}

	report := `{"findings":[{"id":"F1","title":"SQL injection in query builder","severity":"High","cwe":"CWE-89","location":"db.go:5"}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var rows []db.Finding
	w.DB.Find(&rows)
	if len(rows) != 1 {
		t.Fatalf("streamed-then-final reconciled to %d rows, want 1", len(rows))
	}
	if rows[0].Title != "SQL injection in query builder" {
		t.Errorf("title = %q, want the final-report wording", rows[0].Title)
	}
}

// A finding streamed mid-scan but then left out of the final report.json must
// survive (a sibling may have stood down citing it) yet carry a `retracted`
// history row so it is no longer indistinguishable from a confirmed finding.
func TestPersistStreamedFinding_retractedWhenAbsentFromFinalReport(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa", ScanGroup: "grp-1"}
	w.DB.Create(scan)

	streamed, err := w.PersistStreamedFinding(scan, []byte(`{"id":"F1","title":"dropped later","severity":"High","location":"main.go:10"}`))
	if err != nil {
		t.Fatal(err)
	}

	// Final report confirms a different finding, not the streamed one.
	report := `{"findings":[{"id":"F2","title":"kept","severity":"High","location":"other.go:20"}]}`
	if err := w.parseFindingsOutput(&db.Skill{}, scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}

	var still db.Finding
	if err := w.DB.First(&still, streamed.ID).Error; err != nil {
		t.Fatalf("streamed finding was deleted, want it kept: %v", err)
	}
	var retracted int64
	w.DB.Model(&db.FindingHistory{}).Where("finding_id = ? AND field = ?", streamed.ID, "retracted").Count(&retracted)
	if retracted != 1 {
		t.Errorf("retracted history rows = %d, want 1", retracted)
	}
	// The confirmed finding must not be flagged retracted.
	var kept db.Finding
	w.DB.Where("finding_id = ?", "F2").First(&kept)
	var keptRetracted int64
	w.DB.Model(&db.FindingHistory{}).Where("finding_id = ? AND field = ?", kept.ID, "retracted").Count(&keptRetracted)
	if keptRetracted != 0 {
		t.Errorf("confirmed finding wrongly retracted: %d rows", keptRetracted)
	}
}

func TestPersistStreamedFinding_rejectsInvalid(t *testing.T) {
	w, repo := newStreamWorker(t)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa"}
	w.DB.Create(scan)

	for name, body := range map[string]string{
		"malformed JSON":   `{not json`,
		"missing title":    `{"severity":"High","location":"a.go:1"}`,
		"missing severity": `{"title":"t","location":"a.go:1"}`,
		"missing location": `{"title":"t","severity":"High"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := w.PersistStreamedFinding(scan, []byte(body)); !errors.Is(err, ErrInvalidFinding) {
				t.Errorf("err = %v, want ErrInvalidFinding", err)
			}
		})
	}

	var n int64
	w.DB.Model(&db.Finding{}).Count(&n)
	if n != 0 {
		t.Errorf("invalid findings created %d rows, want 0", n)
	}
}
