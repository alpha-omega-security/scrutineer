package db

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
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
		complete bool
		want     RepositoryHealth
	}{
		{
			name:     "recent push with active maintainer is active",
			repo:     Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
			people:   []Maintainer{active},
			complete: true,
			want:     RepositoryHealthActive,
		},
		{
			name:     "old push with maintainers scan finding nobody is stale",
			repo:     Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			complete: true,
			want:     RepositoryHealthStale,
		},
		{
			name:     "legacy empty maintainer status does not imply abandonment",
			repo:     Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			people:   []Maintainer{{}},
			complete: true,
			want:     RepositoryHealthStale,
		},
		{
			name:     "old push and inactive maintainers is abandoned",
			repo:     Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			people:   []Maintainer{inactive},
			complete: true,
			want:     RepositoryHealthAbandoned,
		},
		{
			name:     "highly used abandoned package is zombie",
			repo:     Repository{PushedAt: ptrTime(now.Add(-3 * 365 * 24 * time.Hour))},
			packages: []Package{{DependentRepos: healthZombieDependents - 1}, {DependentRepos: healthZombieDependents}},
			people:   []Maintainer{inactive},
			complete: true,
			want:     RepositoryHealthZombie,
		},
		{
			name:     "archived package is zombie with downstream use",
			repo:     Repository{Archived: true},
			packages: []Package{{DependentRepos: healthZombieDependents}},
			complete: true,
			want:     RepositoryHealthZombie,
		},
		{
			name:     "release older than eighteen months holds classification at stale despite a recent push",
			repo:     Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
			packages: []Package{{LatestReleaseAt: ptrTime(now.Add(-19 * 30 * 24 * time.Hour))}},
			people:   []Maintainer{active},
			complete: true,
			want:     RepositoryHealthStale,
		},
		{
			name: "monorepo stays active while one package still ships",
			repo: Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
			packages: []Package{
				{LatestReleaseAt: ptrTime(now.Add(-19 * 30 * 24 * time.Hour))},
				{LatestReleaseAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
			},
			people:   []Maintainer{active},
			complete: true,
			want:     RepositoryHealthActive,
		},
		{
			name:     "stale_release flag alone does not move classification with a recent release",
			repo:     Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
			packages: []Package{{RiskFlags: string(PackageRiskStaleRelease), LatestReleaseAt: ptrTime(now.Add(-30 * 24 * time.Hour))}},
			people:   []Maintainer{active},
			complete: true,
			want:     RepositoryHealthActive,
		},
		{
			name: "recent push without required scans is unassessed",
			repo: Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))},
			want: "",
		},
		{
			name: "archived is classified without full evidence",
			repo: Repository{Archived: true},
			want: RepositoryHealthAbandoned,
		},
		{
			name: "missing evidence is unassessed",
			repo: Repository{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssessRepositoryHealth(tt.repo, tt.packages, tt.people, tt.complete, now)
			if got.Health != tt.want {
				t.Errorf("health = %q, want %q (%+v)", got.Health, tt.want, got)
			}
			if tt.want != "" && got.Summary == "" {
				t.Error("classified health should explain its evidence")
			}
		})
	}
}

func TestAssessRepositoryHealth_unionsAndOrdersRiskFlags(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	repo := Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))}
	packages := []Package{
		{RiskFlags: string(PackageRiskStaleRelease) + "," + string(PackageRiskSingleMaintainer)},
		{RiskFlags: string(PackageRiskSingleMaintainer)},
	}
	people := []Maintainer{{Status: MaintainerActive}}

	got := AssessRepositoryHealth(repo, packages, people, true, now)

	want := []string{string(PackageRiskSingleMaintainer), string(PackageRiskStaleRelease)}
	if !reflect.DeepEqual(got.RiskFlags, want) {
		t.Errorf("RiskFlags = %#v, want %#v (deduped, canonically ordered)", got.RiskFlags, want)
	}
	if !strings.Contains(got.Summary, "risk flags:") {
		t.Errorf("summary should mention risk flags, got %q", got.Summary)
	}
}

func TestAssessRepositoryHealth_summaryNamesLastReleaseAge(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	repo := Repository{PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour))}
	packages := []Package{{LatestReleaseAt: ptrTime(now.Add(-60 * 24 * time.Hour))}}
	people := []Maintainer{{Status: MaintainerActive}}

	got := AssessRepositoryHealth(repo, packages, people, true, now)

	if !strings.Contains(got.Summary, "last release ") {
		t.Errorf("summary should name the last release age, got %q", got.Summary)
	}
}

func TestAssessRepositoryHealth_flagsSurviveEarlyReturn(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	repo := Repository{}
	packages := []Package{{RiskFlags: string(PackageRiskNativeExtension)}}

	got := AssessRepositoryHealth(repo, packages, nil, false, now)

	if got.Health != "" {
		t.Errorf("Health = %q, want empty (evidence incomplete)", got.Health)
	}
	want := []string{string(PackageRiskNativeExtension)}
	if !reflect.DeepEqual(got.RiskFlags, want) {
		t.Errorf("RiskFlags = %#v, want %#v even on the early-return path", got.RiskFlags, want)
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
	seedHealthScans(t, gdb, repo.ID)

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

func TestRefreshRepositoryHealthSkipsUnchangedProjection(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	updates := 0
	callbackName := "test:count_repository_health_updates"
	if err := gdb.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table == "repositories" {
			updates++
		}
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = gdb.Callback().Update().Remove(callbackName)
	}()

	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	repo := Repository{
		URL:      "https://example.com/active",
		Name:     "active",
		Health:   RepositoryHealthActive,
		PushedAt: ptrTime(now.Add(-30 * 24 * time.Hour)),
	}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	maintainer := Maintainer{Login: "current", Status: MaintainerActive}
	if err := gdb.Create(&maintainer).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Model(&repo).Association("Maintainers").Append(&maintainer); err != nil {
		t.Fatal(err)
	}
	seedHealthScans(t, gdb, repo.ID)
	updates = 0

	assessment, err := RefreshRepositoryHealth(gdb, repo.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Health != RepositoryHealthActive {
		t.Fatalf("assessment = %+v, want active", assessment)
	}
	if updates != 0 {
		t.Fatalf("repository updates = %d, want 0", updates)
	}
}

func TestRefreshRepositoryHealth_leavesHealthEmptyWithoutRequiredScans(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	repo := Repository{
		URL:      "https://example.com/curl",
		Name:     "curl",
		Health:   RepositoryHealthStale,
		PushedAt: ptrTime(now.Add(-7 * 24 * time.Hour)),
	}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	// Only metadata has run; maintainers is still manual, so the verdict must
	// stay empty rather than fall through to stale.
	if err := gdb.Create(&Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "metadata", Status: ScanDone}).Error; err != nil {
		t.Fatal(err)
	}

	assessment, err := RefreshRepositoryHealth(gdb, repo.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Health != "" {
		t.Fatalf("assessment.Health = %q, want empty until every health skill has run", assessment.Health)
	}
	var got Repository
	if err := gdb.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Health != "" {
		t.Errorf("stored health = %q, want cleared back to empty", got.Health)
	}
}

func TestRepositoryHealthEvidenceComplete_ignoresImportScans(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://example.com/r", Name: "r"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	// An import row copies the uploaded tool name into skill_name; it must not
	// satisfy the gate for the same-named skill.
	for _, name := range repositoryHealthSkills {
		if err := gdb.Create(&Scan{RepositoryID: repo.ID, Kind: "import", SkillName: name, Status: ScanDone}).Error; err != nil {
			t.Fatal(err)
		}
	}
	complete, err := RepositoryHealthEvidenceComplete(gdb, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("import-kind scans satisfied the health-evidence gate")
	}

	seedHealthScans(t, gdb, repo.ID)
	complete, err = RepositoryHealthEvidenceComplete(gdb, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("skill-kind scans did not satisfy the health-evidence gate")
	}
}

func seedHealthScans(t *testing.T, gdb *gorm.DB, repoID uint) {
	t.Helper()
	for _, name := range repositoryHealthSkills {
		if err := gdb.Create(&Scan{RepositoryID: repoID, Kind: "skill", SkillName: name, Status: ScanDone}).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
