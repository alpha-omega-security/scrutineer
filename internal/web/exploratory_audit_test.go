package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func exploratoryFixture(t *testing.T, s *Server) (db.Scan, db.Skill) {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/exploration", Name: "exploration"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	triage := db.Scan{RepositoryID: repo.ID, SkillName: "triage", Status: db.ScanDone}
	for triage.ID = 1; !selectExploratoryAudit(triage.ID); triage.ID++ {
	}
	if err := s.DB.Create(&triage).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: deepDiveSkillName, Body: "audit", Active: true, Source: "disk", SourcePath: "../../skills/security-deep-dive", OutputFile: "report.json", OutputKind: "findings"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	parent := db.Scan{RepositoryID: repo.ID, SkillName: threatModelSkillName, Status: db.ScanDone, TriageScanID: &triage.ID, ScanGroup: "triage-batch"}
	if err := s.DB.Create(&parent).Error; err != nil {
		t.Fatal(err)
	}
	return parent, skill
}

func TestExploratoryAuditSelection(t *testing.T) {
	selected := 0
	for id := uint(1); id <= 3000; id++ {
		first := selectExploratoryAudit(id)
		if first != selectExploratoryAudit(id) {
			t.Fatal("selection changed for the same invocation")
		}
		if first {
			selected++
		}
	}
	if selected < 750 || selected > 1500 {
		t.Fatalf("selected %d of 3000 runs, outside requested 25-50%%", selected)
	}
}

func TestExploratoryAuditFanoutIdempotent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	parent, skill := exploratoryFixture(t, s)
	s.autoEnqueueFocusAreaDeepDives(&parent)
	for range 6 {
		s.autoEnqueueFocusAreaDeepDives(&parent)
	}
	var scans []db.Scan
	if err := s.DB.Where("skill_id = ?", skill.ID).Order("id").Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 || scans[0].ExplorationMode != "" || scans[1].ExplorationMode != worker.ExplorationRandomDig {
		t.Fatalf("expected planned then random dig, got %+v", scans)
	}
	extra := scans[1]
	if extra.ScanGroup != parent.ScanGroup || extra.TriageScanID == nil || *extra.TriageScanID != *parent.TriageScanID || extra.FocusArea != "" {
		t.Fatalf("wrong exploratory lineage/scope: %+v", extra)
	}
	for _, status := range []db.ScanStatus{db.ScanFailed, db.ScanCancelled, db.ScanDone} {
		if err := s.DB.Model(&extra).Update("status", status).Error; err != nil {
			t.Fatal(err)
		}
		s.autoEnqueueFocusAreaDeepDives(&parent)
		var count int64
		if err := s.DB.Model(&db.Scan{}).Where("exploration_mode <> ''").Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("status %s: extra count=%d err=%v", status, count, err)
		}
	}
}

func TestExploratoryAuditCompetingInsert(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	parent, skill := exploratoryFixture(t, s)
	s.enqueueFocusAreaDeepDive(&parent, skill.ID, parent.ScanGroup, "")
	inserted := false
	const callback = "test:competing_exploratory_scan"
	if err := s.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		scan, ok := tx.Statement.Dest.(*db.Scan)
		if !ok || scan.ExplorationMode == "" || inserted {
			return
		}
		inserted = true
		competitor := *scan
		competitor.ID = 0
		competitor.APIToken = NewAPIToken()
		// Commit a competitor on a separate connection after the initial
		// check but before our INSERT acquires the write lock.
		if err := s.DB.Session(&gorm.Session{NewDB: true}).Create(&competitor).Error; err != nil {
			t.Error(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.DB.Callback().Create().Remove(callback); err != nil {
			t.Error(err)
		}
	})
	if err := s.enqueueExploratoryAudit(&parent, skill.ID, parent.ScanGroup); !errors.Is(err, errExploratoryAuditExists) {
		t.Fatalf("enqueue error = %v, want competing audit rejection", err)
	}
	if !inserted {
		t.Fatal("competing insert was not exercised")
	}
	var count int64
	if err := s.DB.Model(&db.Scan{}).Where("exploration_mode <> ''").Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("want only the competing row to survive: count=%d err=%v", count, err)
	}
	assertQueuedJobCount(t, s, 1)
}

func TestExploratoryAuditSkipsUnsupportedSkills(t *testing.T) {
	for _, mode := range []string{"ui", "missing-reference", "empty-reference", "host", "host-split"} {
		t.Run(mode, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			parent, skill := exploratoryFixture(t, s)
			source := skill.SourcePath
			switch mode {
			case "ui":
				source = ""
			case "missing-reference":
				source = t.TempDir()
			case "empty-reference":
				source = t.TempDir()
				if err := os.MkdirAll(filepath.Join(source, "references"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, "references", "random-dig.md"), []byte(" \n"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "host":
				s.Worker.Runner = worker.LocalClaude{}
			case "host-split":
				s.Worker.Runner = worker.HostSplitRunner{Host: worker.LocalClaude{}, HostSkills: []string{deepDiveSkillName}}
			}
			if err := s.DB.Model(&skill).Update("source_path", source).Error; err != nil {
				t.Fatal(err)
			}
			s.autoEnqueueFocusAreaDeepDives(&parent)
			var scans []db.Scan
			if err := s.DB.Where("skill_id = ?", skill.ID).Find(&scans).Error; err != nil {
				t.Fatal(err)
			}
			if len(scans) != 1 || scans[0].ExplorationMode != "" {
				t.Fatalf("want only the planned audit, got %+v", scans)
			}
		})
	}
}

func TestScansRetryFailedPreservesExploration(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	parent, skill := exploratoryFixture(t, s)
	failed := db.Scan{RepositoryID: parent.RepositoryID, SkillID: &skill.ID, SkillName: skill.Name,
		Kind: worker.JobSkill, Status: db.ScanFailed, TriageScanID: parent.TriageScanID,
		ExplorationMode: worker.ExplorationRandomDig, ExplorationPath: "lib", ScanGroup: parent.ScanGroup}
	if err := s.DB.Create(&failed).Error; err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.scansRetryFailed(w, localReq(http.MethodPost, "/scans/retry-failed"))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("retry: %d %s", w.Code, w.Body)
	}
	var fresh db.Scan
	if err := s.DB.Where("parent_scan_id = ?", failed.ID).First(&fresh).Error; err != nil {
		t.Fatal(err)
	}
	if fresh.TriageScanID == nil || *fresh.TriageScanID != *parent.TriageScanID || fresh.ExplorationMode != failed.ExplorationMode || fresh.ExplorationPath != failed.ExplorationPath || fresh.ScanGroup != failed.ScanGroup {
		t.Fatalf("retry lost exploration scope: %+v", fresh)
	}
}

func TestExploratoryAuditEligibility(t *testing.T) {
	for _, mode := range []string{"no-planned", "manual", "failed", "diff", "wrong-scope", "wrong-triage", "not-selected"} {
		t.Run(mode, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			parent, skill := exploratoryFixture(t, s)
			switch mode {
			case "manual":
				parent.TriageScanID = nil
			case "failed":
				parent.Status = db.ScanFailed
			case "diff":
				parent.RescanMode = db.ScanRescanModeDiff
			case "wrong-scope":
				parent.SubPath = "other"
			case "wrong-triage":
				if err := s.DB.Model(&db.Scan{}).Where("id = ?", parent.TriageScanID).Update("skill_name", "metadata").Error; err != nil {
					t.Fatal(err)
				}
			case "not-selected":
				id := uint(1)
				for selectExploratoryAudit(id) {
					id++
				}
				parent.TriageScanID = &id
			}
			if mode != "no-planned" {
				s.enqueueFocusAreaDeepDive(&parent, skill.ID, parent.ScanGroup, "")
			}
			s.autoEnqueueExploratoryAudit(&parent, skill.ID, parent.ScanGroup)
			var count int64
			if err := s.DB.Model(&db.Scan{}).Where("exploration_mode <> ''").Count(&count).Error; err != nil || count != 0 {
				t.Fatalf("extra count=%d err=%v", count, err)
			}
		})
	}
}

func TestExploratoryAuditConfiguredDefaultGroup(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	parent, skill := exploratoryFixture(t, s)
	parent.ScanGroup = ""
	config := "focus_areas:\n  - name: parser\n    paths: [lib/**]\n    surface: untrusted input\n  - name: handler\n    paths: [web/**]\n    surface: HTTP requests\n"
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", parent.RepositoryID).Update("scan_config", config).Error; err != nil {
		t.Fatal(err)
	}
	s.autoEnqueueFocusAreaDeepDives(&parent)
	s.autoEnqueueFocusAreaDeepDives(&parent)
	var scans []db.Scan
	if err := s.DB.Where("skill_id = ?", skill.ID).Order("id").Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if len(scans) != 3 {
		t.Fatalf("got %d scans, want two planned and one extra", len(scans))
	}
	for i, scan := range scans {
		if scan.ScanGroup != fmt.Sprintf("focus-%d", parent.ID) {
			t.Errorf("wrong derived group: %q", scan.ScanGroup)
		}
		if i < 2 && (scan.FocusArea == "" || scan.ExplorationMode != "") {
			t.Errorf("planned audit changed: %+v", scan)
		}
	}
	if scans[2].ExplorationMode != worker.ExplorationRandomDig || scans[2].FocusArea != "" {
		t.Fatalf("extra audit inherited plan: %+v", scans[2])
	}
	classifier := db.Skill{Name: revalidateSkillName, Body: "classify", Active: true, Source: "ui", OutputFile: "report.json"}
	if err := s.DB.Create(&classifier).Error; err != nil {
		t.Fatal(err)
	}
	finding := db.Finding{RepositoryID: parent.RepositoryID, ScanID: scans[2].ID, Title: "source finding", Severity: "High"}
	if err := s.DB.Create(&finding).Error; err != nil {
		t.Fatal(err)
	}
	s.autoEnqueueRevalidate(&scans[2], &finding)
	var count int64
	if err := s.DB.Model(&db.Scan{}).Where("skill_id = ? AND finding_id = ?", classifier.ID, finding.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("ordinary revalidation gate: count=%d err=%v", count, err)
	}
}

func TestExploratoryAPILineageAndIsolation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, caller := seedRunningScan(t, s)
	if err := s.DB.Model(&caller).Update("skill_name", "triage").Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: threatModelSkillName, Body: "model", Active: true, Source: "ui", OutputFile: "report.json", SchemaJSON: `{"type":"object"}`}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+caller.APIToken)
		out := httptest.NewRecorder()
		s.Handler().ServeHTTP(out, r)
		return out
	}
	out := request(http.MethodPost, fmt.Sprintf("/api/repositories/%d/skills/threat-model/run", repo.ID), `{}`)
	if out.Code != http.StatusCreated {
		t.Fatalf("enqueue: %d %s", out.Code, out.Body)
	}
	var child db.Scan
	if err := s.DB.Where("skill_id = ?", skill.ID).First(&child).Error; err != nil {
		t.Fatal(err)
	}
	if child.TriageScanID == nil || *child.TriageScanID != caller.ID {
		t.Fatalf("triage lineage lost: %+v", child)
	}
	if err := s.DB.Model(&caller).Updates(map[string]any{"exploration_mode": worker.ExplorationRandomDig, "skill_id": skill.ID}).Error; err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		fmt.Sprintf("/api/repositories/%d", repo.ID),
		fmt.Sprintf("/api/repositories/%d/scans?skill=threat-model", repo.ID),
		fmt.Sprintf("/api/scans/%d", child.ID),
	} {
		if got := request(http.MethodGet, path, ""); got.Code != http.StatusForbidden {
			t.Errorf("%s: status=%d body=%s", path, got.Code, got.Body)
		}
	}
	if got := request(http.MethodPost, fmt.Sprintf("/api/scans/%d/validate-report", caller.ID), `{}`); got.Code != http.StatusOK {
		t.Errorf("own schema validation: %d %s", got.Code, got.Body)
	}
	if got := request(http.MethodPost, fmt.Sprintf("/api/scans/%d/validate-report", child.ID), `{}`); got.Code != http.StatusForbidden {
		t.Errorf("other schema validation: %d %s", got.Code, got.Body)
	}
}
