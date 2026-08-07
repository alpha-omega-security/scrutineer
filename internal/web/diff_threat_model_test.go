package web

import (
	"strings"
	"testing"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func TestAutoUpdateThreatModelFullScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		Report:       `{"spec_version":1}`,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	s.autoUpdateThreatModel(&scan)

	var got db.Repository
	if err := s.DB.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.ThreatModel, `"spec_version": 1`) {
		t.Fatalf("ThreatModel = %q, want full threat-model report", got.ThreatModel)
	}
}

func TestAutoUpdateThreatModelSmallDiffSkips(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo", ThreatModel: `{"old":true}`}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		RescanMode:   db.ScanRescanModeDiff,
		DiffStats:    `{"changed_files":1,"files":[{"path":"README.md"}]}`,
		Coverage:     `{"requested_mode":"diff","actual_mode":"diff"}`,
		Report:       `{"spec_version":2}`,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	s.autoUpdateThreatModel(&scan)

	var gotRepo db.Repository
	if err := s.DB.First(&gotRepo, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if gotRepo.ThreatModel != repo.ThreatModel {
		t.Fatalf("ThreatModel = %q, want unchanged %q", gotRepo.ThreatModel, repo.ThreatModel)
	}
	var gotScan db.Scan
	if err := s.DB.First(&gotScan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(gotScan.Coverage)
	if !ok || rec.ThreatModel == nil {
		t.Fatalf("coverage = %q, want a threat-model state", gotScan.Coverage)
	}
	if rec.ThreatModel.Update != "skipped_small_diff" || rec.ThreatModel.Material {
		t.Fatalf("threat model = %+v, want skipped non-material diff", *rec.ThreatModel)
	}
}

func TestAutoUpdateThreatModelMaterialDiffUpdates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo", ThreatModel: `{"old":true}`}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		RescanMode:   db.ScanRescanModeDiff,
		DiffStats:    `{"changed_files":1,"files":[{"path":"internal/auth/session.go"}]}`,
		Coverage:     `{"requested_mode":"diff","actual_mode":"diff"}`,
		Report:       `{"spec_version":2}`,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	s.autoUpdateThreatModel(&scan)

	var gotRepo db.Repository
	if err := s.DB.First(&gotRepo, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotRepo.ThreatModel, `"spec_version": 2`) {
		t.Fatalf("ThreatModel = %q, want material diff report", gotRepo.ThreatModel)
	}
	var gotScan db.Scan
	if err := s.DB.First(&gotScan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(gotScan.Coverage)
	if !ok || rec.ThreatModel == nil {
		t.Fatalf("coverage = %q, want a threat-model state", gotScan.Coverage)
	}
	if rec.ThreatModel.Update != "updated" || !rec.ThreatModel.Material {
		t.Fatalf("threat model = %+v, want updated material diff", *rec.ThreatModel)
	}
}
