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
