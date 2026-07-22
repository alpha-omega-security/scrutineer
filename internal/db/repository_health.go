package db

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// RepositoryHealth describes the observed maintenance state of a repository.
// Empty is deliberately used for an unassessed repository: missing metadata or
// maintainer evidence must not be mistaken for abandonment.
type RepositoryHealth string

const (
	RepositoryHealthActive    RepositoryHealth = "active"
	RepositoryHealthStale     RepositoryHealth = "stale"
	RepositoryHealthAbandoned RepositoryHealth = "abandoned"
	RepositoryHealthZombie    RepositoryHealth = "zombie"

	healthActiveWindow     = 365 * 24 * time.Hour
	healthAbandonedWindow  = 2 * 365 * 24 * time.Hour
	healthZombieDependents = 100
)

// RepositoryHealthAssessment is the durable classification plus the evidence
// used to reach it. Summary is derived at read time for detailed views; only
// Health is stored on the repository row.
type RepositoryHealthAssessment struct {
	Health            RepositoryHealth
	Summary           string
	DependentRepos    int
	ActiveMaintainers int
	KnownMaintainers  int
}

// AssessRepositoryHealth classifies a repository from persisted evidence.
// An old push alone can make a repository stale, but abandonment additionally
// requires an explicit archived flag or maintainer evidence showing no active
// owner. That avoids treating repositories which have not yet run maintainers
// as abandoned.
func AssessRepositoryHealth(repo Repository, packages []Package, maintainers []Maintainer, now time.Time) RepositoryHealthAssessment {
	assessment := RepositoryHealthAssessment{}
	for _, pkg := range packages {
		// Published packages can share downstream repositories. The package
		// feed cannot prove those sets are disjoint, so max is conservative.
		assessment.DependentRepos = max(assessment.DependentRepos, pkg.DependentRepos)
	}
	for _, maintainer := range maintainers {
		switch maintainer.Status {
		case MaintainerActive:
			assessment.KnownMaintainers++
			assessment.ActiveMaintainers++
		case MaintainerInactive:
			assessment.KnownMaintainers++
		}
	}

	if !repo.Archived && repo.PushedAt == nil && assessment.KnownMaintainers == 0 {
		return assessment
	}

	var age time.Duration
	if repo.PushedAt != nil {
		age = now.Sub(*repo.PushedAt)
	}

	assessment.Health = repositoryHealth(repo.Archived, repo.PushedAt != nil, age, assessment)
	assessment.Summary = healthSummary(repo.Archived, repo.PushedAt, age, assessment)
	return assessment
}

func repositoryHealth(archived, hasPush bool, age time.Duration, assessment RepositoryHealthAssessment) RepositoryHealth {
	abandoned := archived || (hasPush && age >= healthAbandonedWindow && assessment.KnownMaintainers > 0 && assessment.ActiveMaintainers == 0)
	if abandoned {
		if assessment.DependentRepos >= healthZombieDependents {
			return RepositoryHealthZombie
		}
		return RepositoryHealthAbandoned
	}
	if hasPush && age <= healthActiveWindow && assessment.ActiveMaintainers > 0 {
		return RepositoryHealthActive
	}
	return RepositoryHealthStale
}

func healthSummary(archived bool, pushedAt *time.Time, age time.Duration, assessment RepositoryHealthAssessment) string {
	var parts []string
	switch {
	case archived:
		parts = append(parts, "repository is archived")
	case pushedAt == nil:
		parts = append(parts, "last push is unknown")
	default:
		parts = append(parts, fmt.Sprintf("last push %s ago", healthAge(age)))
	}
	switch {
	case assessment.KnownMaintainers == 0:
		parts = append(parts, "maintainer activity is unknown")
	case assessment.ActiveMaintainers == 0:
		parts = append(parts, "no active maintainers identified")
	default:
		parts = append(parts, fmt.Sprintf("%d active maintainer(s)", assessment.ActiveMaintainers))
	}
	if assessment.DependentRepos > 0 {
		parts = append(parts, fmt.Sprintf("up to %d dependent repos", assessment.DependentRepos))
	}
	return strings.Join(parts, "; ")
}

func healthAge(age time.Duration) string {
	if age < 0 {
		return "just now"
	}
	years := int(age / (365 * 24 * time.Hour))
	if years > 0 {
		return fmt.Sprintf("%d year(s)", years)
	}
	months := int(age / (30 * 24 * time.Hour))
	if months > 0 {
		return fmt.Sprintf("%d month(s)", months)
	}
	return "less than a month"
}

// RefreshRepositoryHealth recalculates and persists the health classification.
// It does not manufacture a status when the evidence is incomplete; legacy
// rows therefore remain empty until enough source data exists.
func RefreshRepositoryHealth(gdb *gorm.DB, repositoryID uint, now time.Time) (RepositoryHealthAssessment, error) {
	var repo Repository
	if err := gdb.First(&repo, repositoryID).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("load repository health inputs: %w", err)
	}
	var packages []Package
	if err := gdb.Where("repository_id = ?", repositoryID).Find(&packages).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("load packages for repository health: %w", err)
	}
	var maintainers []Maintainer
	if err := gdb.Joins("JOIN repository_maintainers ON repository_maintainers.maintainer_id = maintainers.id").
		Where("repository_maintainers.repository_id = ?", repositoryID).Find(&maintainers).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("load maintainers for repository health: %w", err)
	}

	assessment := AssessRepositoryHealth(repo, packages, maintainers, now)
	if err := gdb.Model(&Repository{}).Where("id = ?", repositoryID).
		Update("health", assessment.Health).Error; err != nil {
		return RepositoryHealthAssessment{}, fmt.Errorf("save repository health: %w", err)
	}
	return assessment, nil
}
