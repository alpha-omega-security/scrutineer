package web

import (
	"strings"
	"testing"

	"scrutineer/internal/db"
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

func TestAutoSeedRepoScanConfigFromRecon(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/recon", Name: "recon"}
	s.DB.Create(&repo)
	scan := &db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    reconSkillName,
		Report:       `{"scan_config":{"focus_areas":[{"name":"XML parser","paths":["lib/xml*.c"],"surface":"XML documents supplied by library callers"}]}}`,
	}
	s.autoSeedRepoScanConfig(scan)
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if !strings.Contains(got.ScanConfig, "XML parser") || !strings.Contains(got.ScanConfig, "lib/xml*.c") {
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
