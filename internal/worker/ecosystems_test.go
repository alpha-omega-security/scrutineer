package worker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/enrichment"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

type fakeEcosystemsFetcher struct {
	payloads  map[string][]byte
	errs      map[string]error
	hits      map[string]int
	completed map[string]time.Time
}

type gatedPackagesFetcher struct {
	*fakeEcosystemsFetcher
	ready   chan<- struct{}
	release <-chan struct{}
}

func (f *gatedPackagesFetcher) fetchPackages(context.Context, string) ([]byte, error) {
	f.ready <- struct{}{}
	<-f.release
	return f.fetch("packages")
}

func newFakeEcosystemsFetcher() *fakeEcosystemsFetcher {
	return &fakeEcosystemsFetcher{
		payloads: map[string][]byte{
			"repo":       []byte(`{"full_name":"acme/widget","stars":10}`),
			"packages":   []byte(`[{"name":"widget","ecosystem":"npm","dependent_repos_count":12},{"name":"acme","ecosystem":"npm","dependent_repos_count":34}]`),
			"advisories": []byte(`[{"id":"GHSA-1"},{"id":"GHSA-2"}]`),
			"commits":    []byte(`{"commits":[{"login":"alice"}]}`),
			"issues":     []byte(`{"issues":[{"login":"bob"}]}`),
			"dependents": mustDependentsPayloadForTest(),
		},
		errs:      map[string]error{},
		hits:      map[string]int{},
		completed: map[string]time.Time{},
	}
}

func (f *fakeEcosystemsFetcher) fetchRepository(context.Context, string) ([]byte, error) {
	return f.fetch("repo")
}

func (f *fakeEcosystemsFetcher) fetchPackages(context.Context, string) ([]byte, error) {
	return f.fetch("packages")
}

func (f *fakeEcosystemsFetcher) fetchAdvisories(context.Context, string) ([]byte, error) {
	return f.fetch("advisories")
}

func (f *fakeEcosystemsFetcher) fetchCommits(context.Context, string) ([]byte, error) {
	return f.fetch("commits")
}

func (f *fakeEcosystemsFetcher) fetchIssues(context.Context, string) ([]byte, error) {
	return f.fetch("issues")
}

func (f *fakeEcosystemsFetcher) fetchDependents(context.Context, string) ([]byte, error) {
	return f.fetch("dependents")
}

func (f *fakeEcosystemsFetcher) fetch(key string) ([]byte, error) {
	f.hits[key]++
	defer func() { f.completed[key] = time.Now() }()
	if err := f.errs[key]; err != nil {
		return nil, err
	}
	return f.payloads[key], nil
}

func mustDependentsPayloadForTest() []byte {
	payload := []dependentsEntry{
		{
			Package:   "widget",
			Ecosystem: "npm",
			PURL:      "pkg:npm/widget",
			Dependents: []dependentPackage{
				{Name: "downstream-1", Ecosystem: "npm", PURL: "pkg:npm/downstream-1", RepositoryURL: "https://github.com/acme/downstream-1", DependentReposCount: 2},
				{Name: "downstream-1b", Ecosystem: "npm", PURL: "pkg:npm/downstream-1b", RepositoryURL: "https://github.com/acme/downstream-1b", DependentReposCount: 3},
			},
		},
		{
			Package:   "acme",
			Ecosystem: "npm",
			PURL:      "pkg:npm/acme",
			Dependents: []dependentPackage{
				{Name: "downstream-2", Ecosystem: "npm", PURL: "pkg:npm/downstream-2", RepositoryURL: "https://github.com/acme/downstream-2", DependentReposCount: 4},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return body
}

func openEcosystemsTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := db.Open("file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	return gdb
}

func TestRefreshEcosystems_populatesAllSources(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	var got db.Repository
	gdb.First(&got, repo.ID)

	checks := []struct {
		name    string
		data    string
		at      *time.Time
		wantSub string
	}{
		{"repo", got.EcosystemsRepoData, got.EcosystemsRepoFetchedAt, "acme/widget"},
		{"packages", got.EcosystemsPackagesData, got.EcosystemsPackagesFetchedAt, "widget"},
		{"advisories", got.EcosystemsAdvisoriesData, got.EcosystemsAdvisoriesFetchedAt, "GHSA-1"},
		{"commits", got.EcosystemsCommitsData, got.EcosystemsCommitsFetchedAt, "alice"},
		{"issues", got.EcosystemsIssuesData, got.EcosystemsIssuesFetchedAt, "bob"},
		{"dependents", got.EcosystemsDependentsData, got.EcosystemsDependentsFetchedAt, "downstream-1"},
	}
	for _, c := range checks {
		if !strings.Contains(c.data, c.wantSub) {
			t.Errorf("%s data = %q, want substring %q", c.name, c.data, c.wantSub)
		}
		if c.at == nil {
			t.Errorf("%s fetched_at is nil, want set", c.name)
		} else if c.at.Before(fetcher.completed[c.name]) {
			t.Errorf("%s fetched_at = %v, before fetch completed at %v", c.name, c.at, fetcher.completed[c.name])
		}
		if fetcher.hits[c.name] != 1 {
			t.Errorf("%s fetches = %d, want 1", c.name, fetcher.hits[c.name])
		}
	}

	var rows []db.Dependent
	gdb.Where("repository_id = ?", repo.ID).Order("name").Find(&rows)
	if len(rows) != 3 {
		t.Fatalf("dependent rows = %+v, want 3", rows)
	}
	var snapshots []db.DependentCountSnapshot
	gdb.Where("repository_id = ?", repo.ID).Find(&snapshots)
	if len(snapshots) != 1 || snapshots[0].DependentRepos != 34 {
		t.Fatalf("dependent count snapshots = %+v, want one snapshot with count 34", snapshots)
	}
	if got.EcosystemsPackagesFetchedAt == nil || !snapshots[0].ObservedAt.Equal(*got.EcosystemsPackagesFetchedAt) {
		t.Errorf("snapshot observed_at = %v, packages fetched_at = %v", snapshots[0].ObservedAt, got.EcosystemsPackagesFetchedAt)
	}
}

func TestRefreshEcosystems_recordsCountsOnlyWhenPackagesAreRefetched(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("initial refresh: %v", err)
	}
	if err := refreshEcosystems(context.Background(), gdb, repo.ID, true, slog.Default(), fetcher); err != nil {
		t.Fatalf("fresh-cache pass: %v", err)
	}
	var snapshots []db.DependentCountSnapshot
	if err := gdb.Where("repository_id = ?", repo.ID).Order("observed_at").Find(&snapshots).Error; err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("snapshots after fresh-cache pass = %+v, want one", snapshots)
	}
	if fetcher.hits["packages"] != 1 {
		t.Fatalf("package fetches after fresh-cache pass = %d, want 1", fetcher.hits["packages"])
	}

	stale := time.Now().Add(-ttlPackages - time.Hour)
	if err := gdb.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("ecosystems_packages_fetched_at", stale).Error; err != nil {
		t.Fatal(err)
	}
	fetcher.payloads["packages"] = []byte(`[{"name":"widget","dependent_repos_count":55},{"name":"acme","dependent_repos_count":21}]`)
	if err := refreshEcosystems(context.Background(), gdb, repo.ID, true, slog.Default(), fetcher); err != nil {
		t.Fatalf("stale-cache pass: %v", err)
	}
	if err := gdb.Where("repository_id = ?", repo.ID).Order("observed_at").Find(&snapshots).Error; err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 2 || snapshots[0].DependentRepos != 34 || snapshots[1].DependentRepos != 55 {
		t.Fatalf("snapshots after stale refresh = %+v, want counts [34 55]", snapshots)
	}
	if fetcher.hits["packages"] != 2 {
		t.Errorf("package fetches after stale refresh = %d, want 2", fetcher.hits["packages"])
	}
}

func TestRefreshEcosystems_concurrentPackagesRefreshRecordsOneSnapshot(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "ecosystems.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		fetcher := &gatedPackagesFetcher{
			fakeEcosystemsFetcher: newFakeEcosystemsFetcher(),
			ready:                 ready,
			release:               release,
		}
		go func() {
			errs <- refreshEcosystems(context.Background(), gdb, repo.ID, true, slog.Default(), fetcher)
		}()
	}
	<-ready
	<-ready
	close(release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent refresh: %v", err)
		}
	}

	var snapshots []db.DependentCountSnapshot
	if err := gdb.Where("repository_id = ?", repo.ID).Find(&snapshots).Error; err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || snapshots[0].DependentRepos != 34 {
		t.Fatalf("concurrent snapshots = %+v, want one snapshot with count 34", snapshots)
	}
}

func TestRefreshEcosystems_doesNotCacheMalformedPackageCounts(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	fetcher.payloads["packages"] = []byte(`{"not":"an array"}`)
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var got db.Repository
	if err := gdb.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.EcosystemsPackagesData != "" || got.EcosystemsPackagesFetchedAt != nil {
		t.Errorf("malformed packages payload was cached: data=%q fetched_at=%v", got.EcosystemsPackagesData, got.EcosystemsPackagesFetchedAt)
	}
	var count int64
	if err := gdb.Model(&db.DependentCountSnapshot{}).Where("repository_id = ?", repo.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("malformed packages payload recorded %d snapshots, want 0", count)
	}
}

func TestRefreshEcosystems_staleOnlySkipsFresh(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	gdb := openEcosystemsTestDB(t)

	fresh := time.Now()
	stale := fresh.Add(-8 * 24 * time.Hour)
	repo := db.Repository{
		URL:  "https://github.com/acme/widget",
		Name: "widget",
		// repo TTL is 30d: a just-now fetch is fresh and must be skipped.
		EcosystemsRepoData:      `{"cached":true}`,
		EcosystemsRepoFetchedAt: &fresh,
		// commits TTL is 7d: backdate 8 days so it is stale and re-fetched.
		EcosystemsCommitsData:      `{"cached":true}`,
		EcosystemsCommitsFetchedAt: &stale,
	}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, true, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsRepoData != `{"cached":true}` {
		t.Errorf("fresh repo source was re-fetched: %q", got.EcosystemsRepoData)
	}
	if fetcher.hits["repo"] != 0 {
		t.Errorf("fresh repo source fetched %d times, want 0", fetcher.hits["repo"])
	}
	if !strings.Contains(got.EcosystemsCommitsData, "alice") {
		t.Errorf("stale commits source not refreshed: %q", got.EcosystemsCommitsData)
	}
	if fetcher.hits["commits"] != 1 {
		t.Errorf("stale commits fetches = %d, want 1", fetcher.hits["commits"])
	}
}

func TestRefreshEcosystems_fetchErrorIsNonFatal(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	fetcher.errs["commits"] = errors.New("temporary failure")
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/a/b", Name: "b"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh returned error, want nil (best-effort): %v", err)
	}

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsCommitsData != "" {
		t.Errorf("failed source should stay empty, got %q", got.EcosystemsCommitsData)
	}
	if got.EcosystemsCommitsFetchedAt != nil {
		t.Errorf("failed source fetched_at should stay nil")
	}
	if got.EcosystemsRepoData == "" {
		t.Errorf("sibling source should still be populated despite one failure")
	}
}

// A denied domain fails identically on every source, so the first transport
// error abandons the pass instead of paying one timeout per source.
func TestRefreshEcosystems_transportErrorStopsThePass(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	fetcher.errs["repo"] = &net.DNSError{Err: "no such host", Name: "packages.ecosyste.ms", IsNotFound: true}
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/a/b", Name: "b"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh returned error, want nil (best-effort): %v", err)
	}

	if fetcher.hits["repo"] != 1 {
		t.Errorf("repo fetches = %d, want 1", fetcher.hits["repo"])
	}
	for _, key := range []string{"packages", "advisories", "commits", "issues", "dependents"} {
		if fetcher.hits[key] != 0 {
			t.Errorf("%s fetches = %d after an unreachable upstream, want 0", key, fetcher.hits[key])
		}
	}
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsPackagesData != "" {
		t.Errorf("abandoned pass still cached packages: %q", got.EcosystemsPackagesData)
	}
}

// An upstream that answers "nothing recorded for this repository" says nothing
// about the next source, so that one stays per-source.
func TestRefreshEcosystems_upstreamMissErrorKeepsGoing(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	fetcher.errs["repo"] = errors.New("repository not found")
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/a/b", Name: "b"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	for _, key := range []string{"packages", "advisories", "commits", "issues", "dependents"} {
		if fetcher.hits[key] != 1 {
			t.Errorf("%s fetches = %d after a per-source miss, want 1", key, fetcher.hits[key])
		}
	}
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsPackagesData == "" {
		t.Error("sibling source should still be cached after a per-source miss")
	}
}

// A cancelled scan abandons the pass too, but as the caller giving up rather
// than upstream being unreachable. The fetch error is deliberately one that
// unreachable() rejects, so only the ctx.Err() branch can stop the pass: with
// that branch removed the loop falls through to `continue` and the assertion
// below fails.
func TestRefreshEcosystems_cancelledContextStopsThePass(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	fetcher.errs["repo"] = errors.New("repository not found")
	if unreachable(fetcher.errs["repo"]) {
		t.Fatal("the seeded error must not be unreachable, or the test proves nothing")
	}
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/a/b", Name: "b"}
	gdb.Create(&repo)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := refreshEcosystems(ctx, gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh returned error, want nil (best-effort): %v", err)
	}

	if fetcher.hits["packages"] != 0 {
		t.Errorf("packages fetches = %d after a cancelled context, want 0", fetcher.hits["packages"])
	}
}

// The six sources span five hosts, so one host answering slowly must not
// abandon the others: a failed fetch never writes its fetched_at, so a pass
// that gave up here would restart at the same source on every later scan and
// the ones after it would never refresh again.
func TestRefreshEcosystems_slowHostDoesNotStarveLaterSources(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	fetcher.errs["advisories"] = &url.Error{
		Op:  "Get",
		URL: "https://advisories.ecosyste.ms",
		Err: context.DeadlineExceeded,
	}
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/a/b", Name: "b"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	for _, key := range []string{"commits", "issues", "dependents"} {
		if fetcher.hits[key] != 1 {
			t.Errorf("%s fetches = %d after a slow sibling host, want 1", key, fetcher.hits[key])
		}
	}
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsDependentsData == "" {
		t.Error("a slow advisories host stopped dependents from ever being cached")
	}
	if got.EcosystemsAdvisoriesFetchedAt != nil {
		t.Error("the timed-out source must stay unstamped so the TTL retries it")
	}
}

func TestUnreachable(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"dns failure", &net.DNSError{Err: "no such host", IsNotFound: true}, true},
		{"dial refused", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		{"wrapped dial", fmt.Errorf("fetch packages: %w", &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}), true},
		{"tls interception", &url.Error{Op: "Get", URL: "https://packages.ecosyste.ms", Err: &tls.CertificateVerificationError{Err: errors.New("x509: certificate signed by unknown authority")}}, true},
		{"not a tls server", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, true},
		// One host answering slowly says nothing about the other four, so a
		// response-level timeout stays a per-source failure.
		{"slow response", &url.Error{Op: "Get", URL: "https://packages.ecosyste.ms", Err: context.DeadlineExceeded}, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"cancelled", context.Canceled, false},
		{"upstream miss", errors.New("repository not found"), false},
		{"http status", errors.New("unexpected status 404"), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unreachable(tc.err); got != tc.want {
				t.Errorf("unreachable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRefreshEcosystems_skipsLocalRepo(t *testing.T) {
	fetcher := newFakeEcosystemsFetcher()
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "file:///tmp/local", Name: "local"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), fetcher); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	for key, hits := range fetcher.hits {
		if hits != 0 {
			t.Errorf("%s fetches = %d, want 0", key, hits)
		}
	}
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsRepoData != "" {
		t.Errorf("local repo got cached data: %q", got.EcosystemsRepoData)
	}
}

func TestRefreshEcosystems_missingRepoErrors(t *testing.T) {
	gdb := openEcosystemsTestDB(t)
	if err := refreshEcosystems(context.Background(), gdb, 9999, false, slog.Default(), nil); err == nil {
		t.Fatal("want error for missing repository, got nil")
	}
}

func TestDependentsPayload_mapsEnrichmentGroups(t *testing.T) {
	body, err := dependentsPayload([]enrichment.RepositoryDependents{
		{
			PackageName: "widget",
			Ecosystem:   "npm",
			PURL:        "pkg:npm/widget",
			Dependents: []enrichment.DependentPackage{
				{
					Name:                "app",
					Ecosystem:           "npm",
					PURL:                "pkg:npm/app",
					Repository:          "https://github.com/acme/app",
					RegistryURL:         "https://npmjs.org/app",
					LatestVersion:       "1.2.3",
					Downloads:           42,
					DependentReposCount: 7,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("dependentsPayload: %v", err)
	}
	var got []dependentsEntry
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(got) != 1 || got[0].Package != "widget" || got[0].PURL != "pkg:npm/widget" {
		t.Fatalf("group = %+v", got)
	}
	if len(got[0].Dependents) != 1 {
		t.Fatalf("dependents = %+v, want 1", got[0].Dependents)
	}
	dep := got[0].Dependents[0]
	if dep.RepositoryURL != "https://github.com/acme/app" ||
		dep.RegistryURL != "https://npmjs.org/app" ||
		dep.LatestVersion != "1.2.3" ||
		dep.Downloads != 42 ||
		dep.DependentReposCount != 7 {
		t.Errorf("dependent = %+v", dep)
	}
}

func TestUpdateDependentsTable_mapsEnrichmentPayload(t *testing.T) {
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	gdb.Create(&repo)
	gdb.Create(&db.Dependent{RepositoryID: repo.ID, Name: "stale", Ecosystem: "npm"})

	payload := []dependentsEntry{
		{
			Package:   "widget",
			Ecosystem: "npm",
			Dependents: []dependentPackage{
				{
					Name:                "rails-x",
					Ecosystem:           "rubygems",
					PURL:                "pkg:gem/rails-x",
					RepositoryURL:       "https://github.com/acme/rails-x",
					Downloads:           5000,
					DependentReposCount: 200,
					RegistryURL:         "https://rubygems.org/gems/rails-x",
					LatestVersion:       "7.0.0",
				},
				{
					Name:                "action-user",
					Ecosystem:           "github-actions",
					PURL:                "pkg:githubactions/acme/action-user",
					RepositoryURL:       "https://github.com/acme/action-user",
					Downloads:           42,
					DependentReposCount: 9,
					LatestVersion:       "v1",
				},
			},
		},
		{
			Package:   "widget-extra",
			Ecosystem: "npm",
			Dependents: []dependentPackage{
				{
					Name:                "rails-x-duplicate",
					Ecosystem:           "rubygems",
					PURL:                "pkg:gem/rails-x",
					RepositoryURL:       "https://github.com/acme/rails-x-duplicate",
					Downloads:           9999,
					DependentReposCount: 999,
					LatestVersion:       "9.9.9",
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	if err := updateDependentsTable(gdb, repo.ID, body); err != nil {
		t.Fatalf("update dependents table: %v", err)
	}

	var rows []db.Dependent
	gdb.Where("repository_id = ?", repo.ID).Order("name").Find(&rows)
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 2", rows)
	}
	if rows[0].Name != "action-user" ||
		rows[0].Ecosystem != "githubactions" ||
		rows[0].RepositoryURL != "https://github.com/acme/action-user" ||
		rows[0].DependentRepos != 9 ||
		rows[0].LatestVersion != "v1" {
		t.Errorf("action row = %+v", rows[0])
	}
	if rows[1].Name != "rails-x" ||
		rows[1].Ecosystem != "gem" ||
		rows[1].RepositoryURL != "https://github.com/acme/rails-x" ||
		rows[1].DependentRepos != 200 ||
		rows[1].LatestVersion != "7.0.0" ||
		rows[1].RegistryURL != "https://rubygems.org/gems/rails-x" ||
		rows[1].Downloads != 5000 {
		t.Errorf("rails row = %+v", rows[1])
	}
}
