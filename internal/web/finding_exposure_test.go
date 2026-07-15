package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gorm.io/gorm"
	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func seedExposureFinding(t *testing.T, s *Server) (db.Finding, db.Skill) {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/example/lib.git", Name: "lib", FullName: "example/lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "ReDoS", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&f)
	skill := db.Skill{Name: "exposure", Body: "x", Active: true, OutputFile: "report.json", OutputKind: "exposure"}
	s.DB.Create(&skill)
	return f, skill
}

func TestFindingExposureRun_enqueuesScanPerDependent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f, skill := seedExposureFinding(t, s)
	for _, name := range []string{"a", "b", "c"} {
		s.DB.Create(&db.Dependent{RepositoryID: f.RepositoryID, Name: name, Ecosystem: "npm",
			RepositoryURL: "https://github.com/example/" + name, DependentRepos: 100})
	}
	skipped := db.Dependent{RepositoryID: f.RepositoryID, Name: "no-url", Ecosystem: "npm", DependentRepos: 50}
	s.DB.Create(&skipped)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != 200 && w.Code != 303 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var scans []db.Scan
	s.DB.Where("kind = ? AND skill_id = ?", worker.JobExposure, skill.ID).Find(&scans)
	if len(scans) != 3 {
		t.Fatalf("expected 3 exposure scans, got %d", len(scans))
	}
	for _, sc := range scans {
		if sc.FindingID == nil || sc.DependentID == nil {
			t.Errorf("scan %d missing finding_id or dependent_id", sc.ID)
		}
	}

	var rows []db.FindingDependent
	s.DB.Where("finding_id = ?", f.ID).Find(&rows)
	if len(rows) != 1 || rows[0].DependentID != skipped.ID || rows[0].Status != db.ExposureUnderInvestigation {
		t.Fatalf("expected one under_investigation row for the URL-less dependent, got %+v", rows)
	}
	if flash := flashFrom(t, w); !strings.Contains(flash.Title, "3 queued") || !strings.Contains(flash.Title, "1 skipped") {
		t.Errorf("flash = %q, want 3 queued / 1 skipped", flash.Title)
	}
}

func TestFindingExposureRun_reportsPartialSuccess(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f, skill := seedExposureFinding(t, s)
	first := db.Dependent{RepositoryID: f.RepositoryID, Name: "first", Ecosystem: "npm", RepositoryURL: "https://github.com/example/first", DependentRepos: 400}
	failed := db.Dependent{RepositoryID: f.RepositoryID, Name: "failed", Ecosystem: "npm", RepositoryURL: "https://github.com/example/failed", DependentRepos: 300}
	last := db.Dependent{RepositoryID: f.RepositoryID, Name: "last", Ecosystem: "npm", RepositoryURL: "https://github.com/example/last", DependentRepos: 200}
	skipped := db.Dependent{RepositoryID: f.RepositoryID, Name: "no-url", Ecosystem: "npm", DependentRepos: 100}
	for _, dep := range []*db.Dependent{&first, &failed, &last, &skipped} {
		if err := s.DB.Create(dep).Error; err != nil {
			t.Fatalf("seed dependent: %v", err)
		}
	}
	failExposureScanCreate(t, s, failed.ID)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodPost, fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want redirect: %s", w.Code, w.Body)
	}
	if w.Header().Get("Location") != fmt.Sprintf("/findings/%d", f.ID) {
		t.Errorf("location = %q", w.Header().Get("Location"))
	}
	flash := flashFrom(t, w)
	if flash.Category != errorKey || !strings.Contains(flash.Title, "2 queued") || !strings.Contains(flash.Title, "1 skipped") || !strings.Contains(flash.Title, "1 errored") {
		t.Errorf("flash = %+v, want partial-success counts", flash)
	}

	var scans []db.Scan
	if err := s.DB.Where("kind = ? AND skill_id = ?", worker.JobExposure, skill.ID).Find(&scans).Error; err != nil {
		t.Fatalf("load exposure scans: %v", err)
	}
	if len(scans) != 2 {
		t.Fatalf("exposure scans = %d, want 2", len(scans))
	}
	queued := map[uint]bool{}
	for _, scan := range scans {
		if scan.DependentID != nil {
			queued[*scan.DependentID] = true
		}
	}
	if !queued[first.ID] || !queued[last.ID] || queued[failed.ID] {
		t.Errorf("queued dependents = %v, want first and last only", queued)
	}
	var rows []db.FindingDependent
	if err := s.DB.Where("finding_id = ? AND dependent_id = ?", f.ID, skipped.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load skipped exposure: %v", err)
	}
	if len(rows) != 1 || rows[0].Status != db.ExposureUnderInvestigation {
		t.Errorf("skipped exposure rows = %+v", rows)
	}
}

func TestFindingExposureRun_continuesAfterSkippedExposureWriteFailure(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f, skill := seedExposureFinding(t, s)
	skipped := db.Dependent{RepositoryID: f.RepositoryID, Name: "no-url", Ecosystem: "npm", DependentRepos: 200}
	queued := db.Dependent{RepositoryID: f.RepositoryID, Name: "queued", Ecosystem: "npm", RepositoryURL: "https://github.com/example/queued", DependentRepos: 100}
	for _, dep := range []*db.Dependent{&skipped, &queued} {
		if err := s.DB.Create(dep).Error; err != nil {
			t.Fatalf("seed dependent: %v", err)
		}
	}
	failSkippedExposureCreate(t, s, skipped.ID)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodPost, fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d, want redirect: %s", w.Code, w.Body)
	}
	flash := flashFrom(t, w)
	if flash.Category != errorKey || !strings.Contains(flash.Title, "1 queued") || strings.Contains(flash.Title, "skipped") || !strings.Contains(flash.Title, "1 errored") {
		t.Errorf("flash = %+v, want 1 queued / 1 errored with no skipped count", flash)
	}

	var scans []db.Scan
	if err := s.DB.Where("kind = ? AND skill_id = ?", worker.JobExposure, skill.ID).Find(&scans).Error; err != nil {
		t.Fatalf("load exposure scans: %v", err)
	}
	if len(scans) != 1 || scans[0].DependentID == nil || *scans[0].DependentID != queued.ID {
		t.Fatalf("exposure scans = %+v, want queued dependent only", scans)
	}
	var rows []db.FindingDependent
	if err := s.DB.Where("finding_id = ? AND dependent_id = ?", f.ID, skipped.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load skipped exposure: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("skipped exposure rows = %+v, want none after failed write", rows)
	}
}

func failExposureScanCreate(t *testing.T, s *Server, dependentID uint) {
	t.Helper()
	const callback = "test:fail-exposure-scan-create"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		scan, ok := tx.Statement.Dest.(*db.Scan)
		if !ok || scan.DependentID == nil || *scan.DependentID != dependentID {
			return
		}
		_ = tx.AddError(errors.New("injected exposure enqueue failure"))
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DB.Callback().Create().Remove(callback); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	})
}

func failSkippedExposureCreate(t *testing.T, s *Server, dependentID uint) {
	t.Helper()
	const callback = "test:fail-skipped-exposure-create"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		row, ok := tx.Statement.Dest.(*db.FindingDependent)
		if !ok || row.DependentID != dependentID {
			return
		}
		_ = tx.AddError(errors.New("injected skipped exposure write failure"))
	}); err != nil {
		t.Fatalf("register callback: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DB.Callback().Create().Remove(callback); err != nil {
			t.Errorf("remove callback: %v", err)
		}
	})
}

func TestRecordSkippedExposure_preservesExistingRow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	f, _ := seedExposureFinding(t, s)
	dep := db.Dependent{RepositoryID: f.RepositoryID, Name: "no-url", Ecosystem: "npm"}
	if err := s.DB.Create(&dep).Error; err != nil {
		t.Fatalf("seed dependent: %v", err)
	}
	if err := s.DB.Create(&db.FindingDependent{
		FindingID:     f.ID,
		DependentID:   dep.ID,
		Status:        db.ExposureKnownAffected,
		Justification: "old justification",
		Rationale:     "old rationale",
		ScanID:        &f.ScanID,
		ScanCommit:    "old-commit",
	}).Error; err != nil {
		t.Fatalf("seed finding dependent: %v", err)
	}

	if err := s.recordSkippedExposure(f.ID, dep.ID); err != nil {
		t.Fatalf("record skipped exposure: %v", err)
	}

	var rows []db.FindingDependent
	if err := s.DB.Where("finding_id = ? AND dependent_id = ?", f.ID, dep.ID).Find(&rows).Error; err != nil {
		t.Fatalf("load finding dependent: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("finding dependent rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.Status != db.ExposureKnownAffected || row.Justification != "old justification" || row.Rationale != "old rationale" {
		t.Errorf("verdict fields = %+v", row)
	}
	if row.ScanID == nil || *row.ScanID != f.ScanID || row.ScanCommit != "old-commit" {
		t.Errorf("scan fields = %+v", row)
	}
}

func TestFindingExposureRun_noDependents422(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedExposureFinding(t, s)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != 422 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestFindingExposureRun_rejectsZizmorFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/example/lib.git", Name: "lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: zizmorSkillName}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "workflow issue", Severity: "High"}
	s.DB.Create(&f)
	s.DB.Create(&db.Skill{Name: exposureSkillName, Body: "x", Active: true, OutputFile: "report.json", OutputKind: "exposure"})
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "a",
		RepositoryURL: "https://github.com/example/a", DependentRepos: 1})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "not supported") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestFindingExposureRun_skillMissing412(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/x/y", Name: "y"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "x"}
	s.DB.Create(&f)
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "a",
		RepositoryURL: "https://github.com/example/a", DependentRepos: 1})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", fmt.Sprintf("/findings/%d/exposure", f.ID)))
	if w.Code != 412 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "exposure skill is not installed") {
		t.Errorf("body = %q", w.Body.String())
	}
}
