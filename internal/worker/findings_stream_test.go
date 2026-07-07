package worker

import (
	"bytes"
	"errors"
	"io"
	"log"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newStreamWorker(t *testing.T) (*Worker, db.Repository) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
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
	base, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	gdb := base.Session(&gorm.Session{
		Logger: logger.New(log.New(&logs, "", 0), logger.Config{LogLevel: logger.Warn}),
	})
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	scan := &db.Scan{RepositoryID: repo.ID, Kind: JobSkill, SkillName: "sd", Status: db.ScanRunning, Commit: "aaa"}
	gdb.Create(scan)
	w := &Worker{DB: gdb, DataDir: t.TempDir(), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	_, err = w.PersistStreamedFinding(scan, []byte(`{"id":"F1","title":"t","severity":"High","location":"main.go:10"}`))
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
