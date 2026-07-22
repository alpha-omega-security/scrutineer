package web

import (
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestRepositoryHealthTickRefreshesStoredHealth(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	pushedAt := now.Add(-3 * 365 * 24 * time.Hour)
	repo := db.Repository{URL: "https://example.com/zombie", Name: "zombie", PushedAt: &pushedAt}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "widget", DependentRepos: 100}).Error; err != nil {
		t.Fatal(err)
	}
	maintainer := db.Maintainer{Login: "former", Status: db.MaintainerInactive}
	if err := s.DB.Create(&maintainer).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&repo).Association("Maintainers").Append(&maintainer); err != nil {
		t.Fatal(err)
	}

	s.repositoryHealthTick(now)

	var got db.Repository
	if err := s.DB.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Health != db.RepositoryHealthZombie {
		t.Fatalf("health = %q, want %q", got.Health, db.RepositoryHealthZombie)
	}
}

func TestRepositoryHealthTickAgesRepositoriesWithoutParserRuns(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	pushedAt := now.Add(-364 * 24 * time.Hour)
	repo := db.Repository{URL: "https://example.com/active", Name: "active", PushedAt: &pushedAt}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	maintainer := db.Maintainer{Login: "current", Status: db.MaintainerActive}
	if err := s.DB.Create(&maintainer).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&repo).Association("Maintainers").Append(&maintainer); err != nil {
		t.Fatal(err)
	}

	s.repositoryHealthTick(now)
	var got db.Repository
	if err := s.DB.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Health != db.RepositoryHealthActive {
		t.Fatalf("initial health = %q, want %q", got.Health, db.RepositoryHealthActive)
	}

	s.repositoryHealthTick(now.Add(2 * 24 * time.Hour))
	if err := s.DB.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Health != db.RepositoryHealthStale {
		t.Fatalf("aged health = %q, want %q", got.Health, db.RepositoryHealthStale)
	}
}
