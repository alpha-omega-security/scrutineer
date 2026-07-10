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
