package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	ecosystems "github.com/ecosyste-ms/ecosystems-go"
	"github.com/git-pkgs/enrichment"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Per-source cache TTLs. Commits/issues/advisories move on a
// disclosure-relevant cadence (lead-maintainer turnover, freshly published
// CVEs) so they refresh weekly; registry ownership, dependents and repo
// cosmetics drift slowly enough for a month.
const (
	ttlCommits    = 7 * 24 * time.Hour
	ttlIssues     = 7 * 24 * time.Hour
	ttlAdvisories = 7 * 24 * time.Hour
	ttlPackages   = 30 * 24 * time.Hour
	ttlDependents = 30 * 24 * time.Hour
	ttlRepo       = 30 * 24 * time.Hour
)

// EcosystemsPrefetchTimeout bounds the eager on-add prefetch goroutine, which
// runs detached from the HTTP request that created the repository.
const EcosystemsPrefetchTimeout = 5 * time.Minute

const (
	// EcosystemsLookupTimeout bounds synchronous package URL lookups triggered
	// by web requests when the caller has no tighter deadline.
	EcosystemsLookupTimeout = 30 * time.Second

	// maxCachedPackages and maxCachedAdvisories bound cached arrays fetched via
	// ecosystems-go so large repositories still cache partial data instead of
	// failing when upstream pagination exceeds the client's page limit.
	maxCachedPackages   = 2000
	maxCachedAdvisories = 2000

	// maxDependentPackages caps how many of a repo's published packages we
	// chase dependents for; maxDependentsPerPackage caps the stored list per
	// package. Both bound the N+1 fan-out performed by enrichment.
	maxDependentPackages    = 25
	maxDependentsPerPackage = 30
)

const userAgent = "scrutineer (andrew@ecosyste.ms)"

type ecosystemsFetcher interface {
	fetchRepository(ctx context.Context, repoURL string) ([]byte, error)
	fetchPackages(ctx context.Context, repoURL string) ([]byte, error)
	fetchAdvisories(ctx context.Context, repoURL string) ([]byte, error)
	fetchCommits(ctx context.Context, repoURL string) ([]byte, error)
	fetchIssues(ctx context.Context, repoURL string) ([]byte, error)
	fetchDependents(ctx context.Context, repoURL string) ([]byte, error)
}

type productionEcosystemsFetcher struct {
	ecosystems *ecosystems.Client
	dependents *enrichment.EcosystemsClient
}

func newProductionEcosystemsFetcher() (*productionEcosystemsFetcher, error) {
	eco, err := ecosystems.NewClient(userAgent)
	if err != nil {
		return nil, err
	}
	dep, err := enrichment.NewEcosystemsClient()
	if err != nil {
		return nil, err
	}
	return &productionEcosystemsFetcher{ecosystems: eco, dependents: dep}, nil
}

// ResolvePURLRepositoryURL resolves a package PURL to the first repository URL
// reported by packages.ecosyste.ms.
func ResolvePURLRepositoryURL(ctx context.Context, purl string) string {
	if purl == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, EcosystemsLookupTimeout)
	defer cancel()

	client, err := ecosystems.NewClient(userAgent)
	if err != nil {
		return ""
	}
	pkgs, err := client.LookupPackagesByPURL(ctx, purl)
	if err != nil {
		return ""
	}
	for _, pkg := range pkgs {
		if pkg.RepositoryUrl != nil && *pkg.RepositoryUrl != "" {
			return *pkg.RepositoryUrl
		}
	}
	return ""
}

// ecosystemsSource describes one cached upstream payload: which columns it
// writes, how long it stays fresh, and how to fetch it for a repository URL.
type ecosystemsSource struct {
	key        string
	dataColumn string
	fetchedCol string
	ttl        time.Duration
	fetch      func(ctx context.Context, f ecosystemsFetcher, repoURL string) ([]byte, error)
}

func ecosystemsSources() []ecosystemsSource {
	return []ecosystemsSource{
		{"repo", "ecosystems_repo_data", "ecosystems_repo_fetched_at", ttlRepo, func(ctx context.Context, f ecosystemsFetcher, repoURL string) ([]byte, error) {
			return f.fetchRepository(ctx, repoURL)
		}},
		{"packages", "ecosystems_packages_data", "ecosystems_packages_fetched_at", ttlPackages, func(ctx context.Context, f ecosystemsFetcher, repoURL string) ([]byte, error) {
			return f.fetchPackages(ctx, repoURL)
		}},
		{"advisories", "ecosystems_advisories_data", "ecosystems_advisories_fetched_at", ttlAdvisories, func(ctx context.Context, f ecosystemsFetcher, repoURL string) ([]byte, error) {
			return f.fetchAdvisories(ctx, repoURL)
		}},
		{"commits", "ecosystems_commits_data", "ecosystems_commits_fetched_at", ttlCommits, func(ctx context.Context, f ecosystemsFetcher, repoURL string) ([]byte, error) {
			return f.fetchCommits(ctx, repoURL)
		}},
		{"issues", "ecosystems_issues_data", "ecosystems_issues_fetched_at", ttlIssues, func(ctx context.Context, f ecosystemsFetcher, repoURL string) ([]byte, error) {
			return f.fetchIssues(ctx, repoURL)
		}},
		{"dependents", "ecosystems_dependents_data", "ecosystems_dependents_fetched_at", ttlDependents, func(ctx context.Context, f ecosystemsFetcher, repoURL string) ([]byte, error) {
			return f.fetchDependents(ctx, repoURL)
		}},
	}
}

// RefreshEcosystems pre-fetches and caches the ecosyste.ms payloads for one
// repository. With staleOnly true, only sources past their TTL are
// re-fetched, so a scan whose cache is current is a no-op; with staleOnly
// false (the eager on-add path) every source is fetched. Best-effort:
// upstream client and fetch failures are logged and skipped, never fatal, so a
// flaky ecosyste.ms neither blocks a scan nor breaks repo creation. Local
// (file://) repos are skipped since they have no upstream entry.
func RefreshEcosystems(ctx context.Context, gdb *gorm.DB, repoID uint, staleOnly bool, log *slog.Logger) error {
	return refreshEcosystems(ctx, gdb, repoID, staleOnly, log, nil)
}

func refreshEcosystems(ctx context.Context, gdb *gorm.DB, repoID uint, staleOnly bool, log *slog.Logger, fetcher ecosystemsFetcher) error {
	if log == nil {
		log = slog.Default()
	}
	var repo db.Repository
	if err := gdb.First(&repo, repoID).Error; err != nil {
		return fmt.Errorf("load repository %d: %w", repoID, err)
	}
	if repo.IsLocal() {
		return nil
	}
	now := time.Now()
	for _, src := range ecosystemsSources() {
		if staleOnly && !src.stale(repo, now) {
			continue
		}
		if fetcher == nil {
			var err error
			fetcher, err = newProductionEcosystemsFetcher()
			if err != nil {
				log.Warn("ecosystems client setup failed", "repo", repoID, "err", err)
				return nil
			}
		}
		body, err := src.fetch(ctx, fetcher, repo.URL)
		if err != nil {
			log.Warn("ecosystems fetch failed", "repo", repoID, "source", src.key, "err", err)
			continue
		}
		if err := gdb.Model(&db.Repository{}).Where("id = ?", repoID).Updates(map[string]any{
			src.dataColumn: string(body),
			src.fetchedCol: now,
		}).Error; err != nil {
			log.Warn("ecosystems cache write failed", "repo", repoID, "source", src.key, "err", err)
			continue
		}
		if src.key == "dependents" {
			if err := updateDependentsTable(gdb, repoID, body); err != nil {
				log.Warn("ecosystems dependents table write failed", "repo", repoID, "err", err)
			}
		}
	}
	return nil
}

// stale reports whether the source's cached payload is missing or older than
// its TTL as of now.
func (s ecosystemsSource) stale(repo db.Repository, now time.Time) bool {
	at := ecosystemsFetchedAt(repo, s.key)
	return at == nil || now.Sub(*at) >= s.ttl
}

func ecosystemsFetchedAt(repo db.Repository, key string) *time.Time {
	switch key {
	case "repo":
		return repo.EcosystemsRepoFetchedAt
	case "packages":
		return repo.EcosystemsPackagesFetchedAt
	case "advisories":
		return repo.EcosystemsAdvisoriesFetchedAt
	case "commits":
		return repo.EcosystemsCommitsFetchedAt
	case "issues":
		return repo.EcosystemsIssuesFetchedAt
	case "dependents":
		return repo.EcosystemsDependentsFetchedAt
	}
	return nil
}

func (f *productionEcosystemsFetcher) fetchRepository(ctx context.Context, repoURL string) ([]byte, error) {
	repo, err := f.ecosystems.GetRepository(ctx, repoURL)
	if err != nil {
		return nil, err
	}
	if repo == nil {
		return nil, fmt.Errorf("repository not found")
	}
	return json.Marshal(repo)
}

func (f *productionEcosystemsFetcher) fetchPackages(ctx context.Context, repoURL string) ([]byte, error) {
	pkgs, err := f.ecosystems.LookupPackagesByRepositoryURL(ctx, repoURL, maxCachedPackages)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pkgs)
}

func (f *productionEcosystemsFetcher) fetchAdvisories(ctx context.Context, repoURL string) ([]byte, error) {
	advs, err := f.ecosystems.GetAdvisoriesByRepoURL(ctx, repoURL, maxCachedAdvisories)
	if err != nil {
		return nil, err
	}
	return json.Marshal(advs)
}

func (f *productionEcosystemsFetcher) fetchCommits(ctx context.Context, repoURL string) ([]byte, error) {
	commits, err := f.ecosystems.GetCommitsSummary(ctx, repoURL)
	if err != nil {
		return nil, err
	}
	if commits == nil {
		return nil, fmt.Errorf("commits summary not found")
	}
	return json.Marshal(commits)
}

func (f *productionEcosystemsFetcher) fetchIssues(ctx context.Context, repoURL string) ([]byte, error) {
	issues, err := f.ecosystems.GetIssuesSummary(ctx, repoURL)
	if err != nil {
		return nil, err
	}
	if issues == nil {
		return nil, fmt.Errorf("issues summary not found")
	}
	return json.Marshal(issues)
}

type dependentsEntry struct {
	Package    string             `json:"package"`
	Ecosystem  string             `json:"ecosystem"`
	PURL       string             `json:"purl,omitempty"`
	Dependents []dependentPackage `json:"dependents"`
}

type dependentPackage struct {
	Name                string `json:"name"`
	Ecosystem           string `json:"ecosystem"`
	PURL                string `json:"purl"`
	RepositoryURL       string `json:"repository_url,omitempty"`
	Downloads           int64  `json:"downloads"`
	DependentReposCount int    `json:"dependent_repos_count"`
	RegistryURL         string `json:"registry_url,omitempty"`
	LatestVersion       string `json:"latest_release_number,omitempty"`
}

func (f *productionEcosystemsFetcher) fetchDependents(ctx context.Context, repoURL string) ([]byte, error) {
	groups, err := f.dependents.GetDependentsByRepositoryURL(ctx, repoURL, maxDependentPackages, maxDependentsPerPackage)
	if err != nil {
		return nil, err
	}
	return dependentsPayload(groups)
}

func dependentsPayload(groups []enrichment.RepositoryDependents) ([]byte, error) {
	out := make([]dependentsEntry, 0, len(groups))
	for _, group := range groups {
		deps := make([]dependentPackage, 0, len(group.Dependents))
		for _, dep := range group.Dependents {
			deps = append(deps, dependentPackage{
				Name:                dep.Name,
				Ecosystem:           dep.Ecosystem,
				PURL:                dep.PURL,
				RepositoryURL:       dep.Repository,
				Downloads:           int64(dep.Downloads),
				DependentReposCount: dep.DependentReposCount,
				RegistryURL:         dep.RegistryURL,
				LatestVersion:       dep.LatestVersion,
			})
		}
		out = append(out, dependentsEntry{
			Package:    group.PackageName,
			Ecosystem:  group.Ecosystem,
			PURL:       group.PURL,
			Dependents: deps,
		})
	}
	return json.Marshal(out)
}

func updateDependentsTable(gdb *gorm.DB, repoID uint, payload []byte) error {
	var result []dependentsEntry
	if err := json.Unmarshal(payload, &result); err != nil {
		return fmt.Errorf("decode dependents cache: %w", err)
	}
	rows := make([]db.Dependent, 0)
	seen := make(map[string]bool)
	for _, entry := range result {
		for _, d := range entry.Dependents {
			if d.PURL != "" {
				if seen[d.PURL] {
					continue
				}
				seen[d.PURL] = true
			}
			rows = append(rows, db.Dependent{
				RepositoryID:   repoID,
				Name:           d.Name,
				Ecosystem:      db.EcosystemType(d.PURL, d.Ecosystem),
				PURL:           d.PURL,
				RepositoryURL:  d.RepositoryURL,
				Downloads:      d.Downloads,
				DependentRepos: d.DependentReposCount,
				RegistryURL:    d.RegistryURL,
				LatestVersion:  d.LatestVersion,
			})
		}
	}
	return gdb.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("repository_id = ?", repoID).Delete(&db.Dependent{}).Error; err != nil {
			return fmt.Errorf("delete old dependents: %w", err)
		}
		if len(rows) > 0 {
			if err := tx.CreateInBatches(&rows, insertBatchSize).Error; err != nil {
				return fmt.Errorf("save dependents: %w", err)
			}
		}
		return nil
	})
}
