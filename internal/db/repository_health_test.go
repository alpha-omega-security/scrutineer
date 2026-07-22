package db

import (
	"strings"
	"testing"
	"time"
)

func TestAssessRepositoryHealth(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	active := Maintainer{Status: MaintainerActive}
	inactive := Maintainer{Status: MaintainerInactive}

	tests := []struct {
		name     string
		repo     Repository
		packages []Package
		people   []Maintainer
		want     RepositoryHealth
	}{
		{
			name:   "recent push with active maintainer is active",
			repo:   Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
			people: []Maintainer{active},
			want:   RepositoryHealthActive,
		},
		{
			name: "old push remains stale without maintainer evidence",
			repo: Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			want: RepositoryHealthStale,
		},
		{
			name:   "legacy empty maintainer status does not imply abandonment",
			repo:   Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			people: []Maintainer{{}},
			want:   RepositoryHealthStale,
		},
		{
			name:   "old push and inactive maintainers is abandoned",
			repo:   Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			people: []Maintainer{inactive},
			want:   RepositoryHealthAbandoned,
		},
		{
			name:     "highly used abandoned package is zombie",
			repo:     Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			packages: []Package{{DependentRepos: healthZombieDependents - 1}, {DependentRepos: healthZombieDependents}},
			people:   []Maintainer{inactive},
			want:     RepositoryHealthZombie,
		},
		{
			name:     "archived package is zombie with downstream use",
			repo:     Repository{Archived: true},
			packages: []Package{{DependentRepos: healthZombieDependents}},
			want:     RepositoryHealthZombie,
		},
		{
			name: "missing evidence is unassessed",
			repo: Repository{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssessRepositoryHealth(tt.repo, tt.packages, tt.people, now)
			if got.Health != tt.want {
				t.Errorf("health = %q, want %q (%+v)", got.Health, tt.want, got)
			}
			if tt.want != "" && got.Summary == "" {
				t.Error("classified health should explain its evidence")
			}
		})
	}
}

func TestRefreshRepositoryHealth_persistsProjection(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	repo := Repository{URL: "https://example.com/zombie", Name: "zombie", PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&Package{RepositoryID: repo.ID, Name: "widget", DependentRepos: healthZombieDependents}).Error; err != nil {
		t.Fatal(err)
	}
	maintainer := Maintainer{Login: "former", Status: MaintainerInactive}
	if err := gdb.Create(&maintainer).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Model(&repo).Association("Maintainers").Append(&maintainer); err != nil {
		t.Fatal(err)
	}

	assessment, err := RefreshRepositoryHealth(gdb, repo.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Health != RepositoryHealthZombie {
		t.Fatalf("assessment = %+v, want zombie", assessment)
	}
	var got Repository
	if err := gdb.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Health != RepositoryHealthZombie {
		t.Errorf("stored health = %+v, assessment = %+v", got, assessment)
	}
	if !strings.Contains(assessment.Summary, "no active maintainers") || !strings.Contains(assessment.Summary, "dependent repos") {
		t.Errorf("summary = %q", assessment.Summary)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
