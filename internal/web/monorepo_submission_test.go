package web

import (
	"context"
	"testing"

	"scrutineer/internal/db"
)

func TestCreateOrTriageRepo_recordsSubmittedSubproject(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.prefetchEcosystems = func(uint) {}

	repo, _, err := s.createOrTriageRepo(context.Background(), RepoInput{
		CloneURL: "https://github.com/rails/rails", Owner: "rails", Name: "rails",
		SubPath: "activesupport",
	}, "", true)
	if err != nil {
		t.Fatalf("createOrTriageRepo: %v", err)
	}
	var sub db.Subproject
	if err := s.DB.Where("repository_id = ? AND path = ?", repo.ID, "activesupport").First(&sub).Error; err != nil {
		t.Fatalf("submitted subproject not recorded: %v", err)
	}
	if sub.Name != "activesupport" {
		t.Errorf("subproject name = %q, want activesupport", sub.Name)
	}
}

func TestCreateOrTriageRepo_rejectsTraversalSubPath(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.prefetchEcosystems = func(uint) {}

	_, _, err := s.createOrTriageRepo(context.Background(), RepoInput{
		CloneURL: "https://github.com/rails/rails", Owner: "rails", Name: "rails",
		SubPath: "../etc",
	}, "", true)
	if err == nil {
		t.Fatal("expected error for traversal sub_path, got nil")
	}
	var n int64
	s.DB.Model(&db.Repository{}).Where("url = ?", "https://github.com/rails/rails").Count(&n)
	if n != 0 {
		t.Errorf("repo row created despite invalid sub_path (count=%d)", n)
	}
}

// hasOpenRepoScopedScan must scope its conflict check by sub_path so two
// monorepo sub-packages can run the same skill concurrently.
func TestHasOpenRepoScopedScan_subPathScoped(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "deep", Active: true}
	s.DB.Create(&skill)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, Status: db.ScanRunning, SubPath: "activesupport"})

	if !s.hasOpenRepoScopedScan(repo.ID, skill.ID, "activesupport") {
		t.Error("want open scan detected for activesupport")
	}
	if s.hasOpenRepoScopedScan(repo.ID, skill.ID, "actionpack") {
		t.Error("actionpack must not collide with activesupport's in-flight scan")
	}
	if s.hasOpenRepoScopedScan(repo.ID, skill.ID, "") {
		t.Error("repo-root scope must not collide with a sub-path scan")
	}
}
