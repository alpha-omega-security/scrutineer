package web

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

func TestAutoSeedRepoScanConfig(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/seed", Name: "seed"}
	s.DB.Create(&repo)
	scan := &db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		Report:       `{"scan_config":{"focus_areas":[{"name":"parser","paths":["src/parse/**"],"surface":"accepts bytes"}],"skip":["tests/**"]}}`,
	}
	s.autoSeedRepoScanConfig(scan)
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ScanConfig == "" || !strings.Contains(got.ScanConfig, "focus_areas:") || !strings.Contains(got.ScanConfig, "tests/**") {
		t.Fatalf("ScanConfig = %q", got.ScanConfig)
	}
}

func TestFinalizedThreatModelFocusConfigBoundaries(t *testing.T) {
	for _, count := range []int{repoconfig.MaxFocusAreas, repoconfig.MaxFocusAreas + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			s, cleanup := newTestServer(t)
			defer cleanup()
			repo := db.Repository{URL: "https://example.com/focus-seed", Name: "focus-seed"}
			if err := s.DB.Create(&repo).Error; err != nil {
				t.Fatal(err)
			}
			deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "report.json", OutputKind: "findings", Active: true, Source: "ui"}
			if err := s.DB.Create(&deepDive).Error; err != nil {
				t.Fatal(err)
			}
			cfg, err := repoconfig.Parse(legacyFocusScanConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			cfg.FocusAreas = cfg.FocusAreas[:count]
			raw, err := json.Marshal(map[string]any{"scan_config": cfg})
			if err != nil {
				t.Fatal(err)
			}
			scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: threatModelSkillName, Report: string(raw), ScanGroup: "focus-boundary"}
			if err := s.DB.Create(&scan).Error; err != nil {
				t.Fatal(err)
			}
			s.Worker.OnScanFinalized(&scan)
			requireFocusSeedBoundary(t, s, repo.ID, deepDive.ID, cfg)
		})
	}
}

func TestAutoSeedRepoScanConfigIgnoresReconThenAcceptsThreatModel(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/recon", Name: "recon"}
	s.DB.Create(&repo)
	recon := &db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    "recon",
		Report:       `{"focus_areas":[{"name":"XML parser","paths":["lib/xml*.c"],"surface":"XML documents supplied by library callers"}],"notes":[]}`,
	}
	s.autoSeedRepoScanConfig(recon)
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ScanConfig != "" {
		t.Fatalf("recon seeded ScanConfig = %q", got.ScanConfig)
	}

	threatModel := &db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		Report:       `{"scan_config":{"focus_areas":[{"name":"XML parser","paths":["lib/xml*.c"],"surface":"XML documents supplied by library callers"}],"known_bugs":["GHSA-xxxx-yyyy"],"attack_surface":"XML documents from callers","skip":["tests/**"]}}`,
	}
	s.autoSeedRepoScanConfig(threatModel)
	s.DB.First(&got, repo.ID)
	for _, want := range []string{"XML parser", "lib/xml*.c", "GHSA-xxxx-yyyy", "XML documents from callers", "tests/**"} {
		if !strings.Contains(got.ScanConfig, want) {
			t.Fatalf("ScanConfig = %q, missing %q", got.ScanConfig, want)
		}
	}
	if strings.Contains(got.ScanConfig, "notes") {
		t.Fatalf("ScanConfig = %q", got.ScanConfig)
	}
}

func TestAutoSeedRepoScanConfigSeedsLegacyNull(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/seed-null", Name: "seed-null"}
	s.DB.Create(&repo)
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("scan_config", nil).Error; err != nil {
		t.Fatal(err)
	}
	scan := &db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		Report:       `{"scan_config":{"skip":["tests/**"]}}`,
	}
	s.autoSeedRepoScanConfig(scan)
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if !strings.Contains(got.ScanConfig, "tests/**") {
		t.Fatalf("ScanConfig = %q, want seeded value", got.ScanConfig)
	}
}

func TestAutoSeedRepoScanConfigPreservesAnalystConfig(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/seed-existing", Name: "seed-existing", ScanConfig: "skip: [vendor/**]\n"}
	s.DB.Create(&repo)
	scan := &db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		Report:       `{"scan_config":{"skip":["tests/**"]}}`,
	}
	s.autoSeedRepoScanConfig(scan)
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ScanConfig != repo.ScanConfig {
		t.Fatalf("ScanConfig = %q, want %q", got.ScanConfig, repo.ScanConfig)
	}
}

func requireFocusSeedBoundary(t *testing.T, s *Server, repoID, skillID uint, cfg repoconfig.Config) {
	t.Helper()
	count := len(cfg.FocusAreas)
	var got db.Repository
	if err := s.DB.First(&got, repoID).Error; err != nil {
		t.Fatal(err)
	}
	wantScans := int64(count)
	if count > repoconfig.MaxFocusAreas {
		wantScans = 0
		if got.ScanConfig != "" {
			t.Fatal("over-cap proposal was saved")
		}
	} else {
		parsed, err := repoconfig.Parse(got.ScanConfig)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(parsed, cfg) {
			t.Fatalf("seeded guidance=%+v, want %+v", parsed, cfg)
		}
	}
	var focused int64
	if err := s.DB.Model(&db.Scan{}).Where("repository_id = ? AND skill_id = ? AND focus_area <> ''", repoID, skillID).Count(&focused).Error; err != nil {
		t.Fatal(err)
	}
	if focused != wantScans {
		t.Fatalf("focused scans=%d, want %d", focused, wantScans)
	}
}
