package web

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"scrutineer/internal/db"
)

func TestTriageFindingSkillJoinsReflectionCohort(t *testing.T) {
	for _, callerSkill := range []string{"triage", "metadata"} {
		t.Run(callerSkill, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo, caller := seedRunningScan(t, s)
			if err := s.DB.Model(&caller).Update("skill_name", callerSkill).Error; err != nil {
				t.Fatal(err)
			}
			finding := db.Finding{RepositoryID: repo.ID, ScanID: caller.ID, FindingID: "F1", Title: "test", Severity: "High", Status: db.FindingNew}
			if err := s.DB.Create(&finding).Error; err != nil {
				t.Fatal(err)
			}
			skill := db.Skill{Name: "verify", Active: true, OutputKind: "verify", Body: "verify", Source: "ui"}
			if err := s.DB.Create(&skill).Error; err != nil {
				t.Fatal(err)
			}
			response := apiReq(t, s, http.MethodPost, fmt.Sprintf("/api/findings/%d/skills/verify/run", finding.ID), caller.APIToken, `{}`)
			if response.Code != http.StatusCreated {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			var child db.Scan
			if err := s.DB.Where("skill_id = ?", skill.ID).First(&child).Error; err != nil {
				t.Fatal(err)
			}
			if callerSkill == "triage" {
				if child.TriageScanID == nil || *child.TriageScanID != caller.ID {
					t.Fatal("triage finding scan missing cohort provenance")
				}
			} else if child.TriageScanID != nil {
				t.Fatal("non-triage caller assigned cohort provenance")
			}
		})
	}
}

func TestAutoEnqueueReflection(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/reflection", Name: "reflection", ThreatModel: `{"description":"existing"}`}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "reflect", Active: true, OutputKind: "reflection", Body: "reflect"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	triage := db.Scan{RepositoryID: repo.ID, SkillName: "triage", Status: db.ScanDone}
	if err := s.DB.Create(&triage).Error; err != nil {
		t.Fatal(err)
	}
	s.autoEnqueueReflection(&triage)
	assertReflectionCount(t, s, 0)
	child := db.Scan{RepositoryID: repo.ID, SkillName: "verify", Status: db.ScanRunning, TriageScanID: &triage.ID}
	if err := s.DB.Create(&child).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&repo).Update("threat_model", "").Error; err != nil {
		t.Fatal(err)
	}
	s.autoEnqueueReflection(&triage)
	assertReflectionCount(t, s, 0)
	if err := s.DB.Model(&repo).Update("threat_model", `{"description":"existing"}`).Error; err != nil {
		t.Fatal(err)
	}
	triage.Ref = "feature"
	s.autoEnqueueReflection(&triage)
	assertReflectionCount(t, s, 0)
	triage.Ref = ""
	triage.Status = db.ScanFailed
	s.autoEnqueueReflection(&triage)
	assertReflectionCount(t, s, 0)
	triage.Status = db.ScanDone
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { s.autoEnqueueReflection(&triage) })
	}
	wg.Wait()
	assertReflectionCount(t, s, 1)
	var scan db.Scan
	if err := s.DB.Where("skill_name = ?", "reflect").First(&scan).Error; err != nil {
		t.Fatal(err)
	}
	if scan.TriageScanID == nil || *scan.TriageScanID != triage.ID || scan.RepositoryID != repo.ID || scan.Status != db.ScanQueued {
		t.Fatalf("wrong reflection: %+v", scan)
	}
	if err := s.DB.Model(&scan).Update("status", db.ScanDone).Error; err != nil {
		t.Fatal(err)
	}
	s.autoEnqueueReflection(&triage)
	assertReflectionCount(t, s, 1)
}

func assertReflectionCount(t *testing.T, s *Server, want int64) {
	t.Helper()
	var count int64
	if err := s.DB.Model(&db.Scan{}).Where("skill_name = ?", "reflect").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("reflection count = %d, want %d", count, want)
	}
}

func TestThreatModelRefreshPreservesReflection(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/reflect-model", Name: "reflect-model", ThreatModel: `{"reflection_notes":[{"summary":"retained"}],"description":"old"}`}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, SkillName: threatModelSkillName, Status: db.ScanDone, Report: `{"description":"new","reflection_notes":[{"summary":"invented"}]}`}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	s.autoUpdateThreatModel(&scan)
	if err := s.DB.First(&repo, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	const expected = "{\n  \"description\": \"new\",\n  \"reflection_notes\": [\n    {\n      \"summary\": \"retained\"\n    }\n  ]\n}"
	if repo.ThreatModel != expected {
		t.Fatalf("model = %s", repo.ThreatModel)
	}
}
