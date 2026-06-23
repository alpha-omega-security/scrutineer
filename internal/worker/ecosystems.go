package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// ecosystemsEndpoints are the upstream ecosyste.ms lookup roots. Held as a
// value rather than constants so tests can point each one at an httptest
// server; production passes defaultEcosystemsEndpoints.
type ecosystemsEndpoints struct {
	repo       string
	packages   string
	advisories string
	commits    string
	issues     string
}

var defaultEcosystemsEndpoints = ecosystemsEndpoints{
	repo:       "https://repos.ecosyste.ms/api/v1/repositories/lookup",
	packages:   "https://packages.ecosyste.ms/api/v1/packages/lookup",
	advisories: "https://advisories.ecosyste.ms/api/v1/advisories",
	commits:    "https://commits.ecosyste.ms/api/v1/repositories/lookup",
	issues:     "https://issues.ecosyste.ms/api/v1/repositories/lookup",
}

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
	// maxDependentPackages caps how many of a repo's published packages we
	// chase dependents for; maxDependentsPerPackage caps the stored list per
	// package. Both bound the N+1 fan-out, and truncation is logged.
	maxDependentPackages    = 25
	maxDependentsPerPackage = 30
	// maxAdvisoryPages bounds how far the advisories pagination is followed.
	maxAdvisoryPages = 20
)

// ecosystemsSource describes one cached upstream payload: which columns it
// writes, how long it stays fresh, and how to fetch it for a repository URL.
type ecosystemsSource struct {
	key        string
	dataColumn string
	fetchedCol string
	ttl        time.Duration
	fetch      func(ctx context.Context, ep ecosystemsEndpoints, repoURL string, log *slog.Logger) ([]byte, error)
}

func ecosystemsSources() []ecosystemsSource {
	return []ecosystemsSource{
		{"repo", "ecosystems_repo_data", "ecosystems_repo_fetched_at", ttlRepo, lookupFetcher("url", func(ep ecosystemsEndpoints) string { return ep.repo })},
		{"packages", "ecosystems_packages_data", "ecosystems_packages_fetched_at", ttlPackages, lookupFetcher("repository_url", func(ep ecosystemsEndpoints) string { return ep.packages })},
		{"advisories", "ecosystems_advisories_data", "ecosystems_advisories_fetched_at", ttlAdvisories, fetchAdvisories},
		{"commits", "ecosystems_commits_data", "ecosystems_commits_fetched_at", ttlCommits, lookupFetcher("url", func(ep ecosystemsEndpoints) string { return ep.commits })},
		{"issues", "ecosystems_issues_data", "ecosystems_issues_fetched_at", ttlIssues, lookupFetcher("url", func(ep ecosystemsEndpoints) string { return ep.issues })},
		{"dependents", "ecosystems_dependents_data", "ecosystems_dependents_fetched_at", ttlDependents, fetchDependents},
	}
}

// RefreshEcosystems pre-fetches and caches the ecosyste.ms payloads for one
// repository. With staleOnly true, only sources past their TTL are
// re-fetched, so a scan whose cache is current is a no-op; with staleOnly
// false (the eager on-add path) every source is fetched. Best-effort: a
// failing source is logged and skipped, never fatal, so a flaky ecosyste.ms
// neither blocks a scan nor breaks repo creation. Local (file://) repos are
// skipped since they have no upstream entry.
func RefreshEcosystems(ctx context.Context, gdb *gorm.DB, repoID uint, staleOnly bool, log *slog.Logger) error {
	return refreshEcosystems(ctx, gdb, repoID, staleOnly, log, defaultEcosystemsEndpoints)
}

func refreshEcosystems(ctx context.Context, gdb *gorm.DB, repoID uint, staleOnly bool, log *slog.Logger, ep ecosystemsEndpoints) error {
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
		body, err := src.fetch(ctx, ep, repo.URL, log)
		if err != nil {
			log.Warn("ecosystems fetch failed", "repo", repoID, "source", src.key, "err", err)
			continue
		}
		if err := gdb.Model(&db.Repository{}).Where("id = ?", repoID).Updates(map[string]any{
			src.dataColumn: string(body),
			src.fetchedCol: now,
		}).Error; err != nil {
			log.Warn("ecosystems cache write failed", "repo", repoID, "source", src.key, "err", err)
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

// lookupFetcher builds a fetcher for the single-response ?param={repoURL}
// lookup endpoints (repo, packages, commits, issues).
func lookupFetcher(param string, endpoint func(ecosystemsEndpoints) string) func(context.Context, ecosystemsEndpoints, string, *slog.Logger) ([]byte, error) {
	return func(ctx context.Context, ep ecosystemsEndpoints, repoURL string, _ *slog.Logger) ([]byte, error) {
		q := url.Values{param: {repoURL}}
		return ecosystemsGet(ctx, endpoint(ep)+"?"+q.Encode())
	}
}

// fetchAdvisories follows the advisories endpoint's Link rel="next"
// pagination, concatenating the JSON arrays, and stops at the page or
// cumulative-size cap (logging when it does) so the column stays bounded.
func fetchAdvisories(ctx context.Context, ep ecosystemsEndpoints, repoURL string, log *slog.Logger) ([]byte, error) {
	q := url.Values{"repository_url": {repoURL}}
	next := ep.advisories + "?" + q.Encode()
	all := []json.RawMessage{}
	total := 0
	for page := 0; next != "" && page < maxAdvisoryPages; page++ {
		body, link, err := ecosystemsGetWithLink(ctx, next)
		if err != nil {
			return nil, err
		}
		var batch []json.RawMessage
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("decode advisories: %w", err)
		}
		all = append(all, batch...)
		total += len(body)
		if total >= maxResponseBody {
			log.Warn("advisories cache size cap reached", "repo", repoURL)
			next = ""
			break
		}
		next = link
	}
	if next != "" {
		log.Warn("advisories pagination capped", "repo", repoURL, "pages", maxAdvisoryPages)
	}
	return json.Marshal(all)
}

type dependentsEntry struct {
	Package    string            `json:"package"`
	Ecosystem  string            `json:"ecosystem"`
	Dependents []json.RawMessage `json:"dependents"`
}

// fetchDependents chains off the packages lookup: for each published package
// it follows dependent_packages_url and keeps the first page (capped). Output
// is sorted by package name so the cached blob is reproducible.
func fetchDependents(ctx context.Context, ep ecosystemsEndpoints, repoURL string, log *slog.Logger) ([]byte, error) {
	q := url.Values{"repository_url": {repoURL}}
	body, err := ecosystemsGet(ctx, ep.packages+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var pkgs []struct {
		Name                 string `json:"name"`
		Ecosystem            string `json:"ecosystem"`
		DependentPackagesURL string `json:"dependent_packages_url"`
	}
	if err := json.Unmarshal(body, &pkgs); err != nil {
		return nil, fmt.Errorf("decode packages: %w", err)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })
	if len(pkgs) > maxDependentPackages {
		log.Warn("dependents package fan-out capped", "repo", repoURL, "packages", len(pkgs), "cap", maxDependentPackages)
		pkgs = pkgs[:maxDependentPackages]
	}
	out := make([]dependentsEntry, 0, len(pkgs))
	for _, p := range pkgs {
		if p.DependentPackagesURL == "" {
			continue
		}
		depBody, err := ecosystemsGet(ctx, p.DependentPackagesURL)
		if err != nil {
			log.Warn("dependents fetch failed", "repo", repoURL, "package", p.Name, "err", err)
			continue
		}
		var deps []json.RawMessage
		if err := json.Unmarshal(depBody, &deps); err != nil {
			log.Warn("dependents decode failed", "repo", repoURL, "package", p.Name, "err", err)
			continue
		}
		if len(deps) > maxDependentsPerPackage {
			deps = deps[:maxDependentsPerPackage]
		}
		out = append(out, dependentsEntry{Package: p.Name, Ecosystem: p.Ecosystem, Dependents: deps})
	}
	return json.Marshal(out)
}

func ecosystemsGet(ctx context.Context, endpoint string) ([]byte, error) {
	body, _, err := ecosystemsGetWithLink(ctx, endpoint)
	return body, err
}

// ecosystemsGetWithLink performs one GET and returns the size-capped body plus
// the rel="next" URL from the Link header, if present. Redirects are followed
// by the default client, matching the skills' "follow redirects" note.
func ecosystemsGetWithLink(ctx context.Context, endpoint string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s returned %d", endpoint, resp.StatusCode)
	}
	return body, nextLink(resp.Header.Get("Link")), nil
}

// nextLink extracts the URL of the rel="next" entry from an RFC 8288 Link
// header, or "" when absent.
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		urlPart, params, found := strings.Cut(part, ";")
		if !found {
			continue
		}
		if !strings.Contains(params, "rel=\"next\"") && !strings.Contains(params, "rel=next") {
			continue
		}
		u := strings.TrimSpace(urlPart)
		u = strings.TrimPrefix(u, "<")
		return strings.TrimSuffix(u, ">")
	}
	return ""
}
