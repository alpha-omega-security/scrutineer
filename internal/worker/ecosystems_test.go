package worker

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// ecosystemsTestServer serves canned responses for every ecosyste.ms source,
// routed by path, plus the per-package dependent lists chained off /packages
// and a two-page /advisories response so pagination is exercised.
func ecosystemsTestServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/repos", func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = io.WriteString(w, `{"full_name":"acme/widget","stars":10}`)
	})
	mux.HandleFunc("/packages", func(w http.ResponseWriter, r *http.Request) {
		hits++
		base := "http://" + r.Host
		_, _ = io.WriteString(w, `[`+
			`{"name":"widget","ecosystem":"npm","dependent_packages_url":"`+base+`/deps/widget"},`+
			`{"name":"acme","ecosystem":"npm","dependent_packages_url":"`+base+`/deps/acme"}]`)
	})
	mux.HandleFunc("/advisories", func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Query().Get("page") == "2" {
			_, _ = io.WriteString(w, `[{"id":"GHSA-2"}]`)
			return
		}
		w.Header().Set("Link", `<http://`+r.Host+`/advisories?page=2>; rel="next"`)
		_, _ = io.WriteString(w, `[{"id":"GHSA-1"}]`)
	})
	mux.HandleFunc("/commits", func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = io.WriteString(w, `{"commits":[{"login":"alice"}]}`)
	})
	mux.HandleFunc("/issues", func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = io.WriteString(w, `{"issues":[{"login":"bob"}]}`)
	})
	mux.HandleFunc("/deps/widget", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"repo":"downstream-1"}]`)
	})
	mux.HandleFunc("/deps/acme", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"repo":"downstream-2"}]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func testEndpoints(base string) ecosystemsEndpoints {
	return ecosystemsEndpoints{
		repo:       base + "/repos",
		packages:   base + "/packages",
		advisories: base + "/advisories",
		commits:    base + "/commits",
		issues:     base + "/issues",
	}
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
	srv, _ := ecosystemsTestServer(t)
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), testEndpoints(srv.URL)); err != nil {
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
		}
	}

	// advisories must concatenate both pages; dependents must cover both packages.
	if !strings.Contains(got.EcosystemsAdvisoriesData, "GHSA-2") {
		t.Errorf("advisories did not follow pagination: %q", got.EcosystemsAdvisoriesData)
	}
	if !strings.Contains(got.EcosystemsDependentsData, "downstream-2") {
		t.Errorf("dependents missing second package: %q", got.EcosystemsDependentsData)
	}
}

func TestRefreshEcosystems_staleOnlySkipsFresh(t *testing.T) {
	srv, _ := ecosystemsTestServer(t)
	gdb := openEcosystemsTestDB(t)

	fresh := time.Now()
	repo := db.Repository{
		URL:  "https://github.com/acme/widget",
		Name: "widget",
		// repo TTL is 30d: a just-now fetch is fresh and must be skipped.
		EcosystemsRepoData:      `{"cached":true}`,
		EcosystemsRepoFetchedAt: &fresh,
		// commits TTL is 7d: backdate 8 days so it is stale and re-fetched.
		EcosystemsCommitsData:      `{"cached":true}`,
		EcosystemsCommitsFetchedAt: new(fresh.Add(-8 * 24 * time.Hour)),
	}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, true, slog.Default(), testEndpoints(srv.URL)); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsRepoData != `{"cached":true}` {
		t.Errorf("fresh repo source was re-fetched: %q", got.EcosystemsRepoData)
	}
	if !strings.Contains(got.EcosystemsCommitsData, "alice") {
		t.Errorf("stale commits source not refreshed: %q", got.EcosystemsCommitsData)
	}
}

func TestRefreshEcosystems_fetchErrorIsNonFatal(t *testing.T) {
	gdb := openEcosystemsTestDB(t)
	// Server 500s on /commits only; every other source succeeds.
	mux := http.NewServeMux()
	mux.HandleFunc("/repos", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"full_name":"a/b"}`) })
	mux.HandleFunc("/packages", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `[]`) })
	mux.HandleFunc("/advisories", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `[]`) })
	mux.HandleFunc("/commits", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	mux.HandleFunc("/issues", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"issues":[]}`) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	repo := db.Repository{URL: "https://github.com/a/b", Name: "b"}
	gdb.Create(&repo)

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), testEndpoints(srv.URL)); err != nil {
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

func TestRefreshEcosystems_skipsLocalRepo(t *testing.T) {
	srv, hits := ecosystemsTestServer(t)
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "file:///tmp/local", Name: "local"}
	gdb.Create(&repo)
	*hits = 0

	if err := refreshEcosystems(context.Background(), gdb, repo.ID, false, slog.Default(), testEndpoints(srv.URL)); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if *hits != 0 {
		t.Errorf("local repo triggered %d upstream fetches, want 0", *hits)
	}
	var got db.Repository
	gdb.First(&got, repo.ID)
	if got.EcosystemsRepoData != "" {
		t.Errorf("local repo got cached data: %q", got.EcosystemsRepoData)
	}
}

func TestRefreshEcosystems_missingRepoErrors(t *testing.T) {
	gdb := openEcosystemsTestDB(t)
	if err := refreshEcosystems(context.Background(), gdb, 9999, false, slog.Default(), defaultEcosystemsEndpoints); err == nil {
		t.Fatal("want error for missing repository, got nil")
	}
}

func TestNextLink(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{`<https://x/api?page=2>; rel="next"`, "https://x/api?page=2"},
		{`<https://x/api?page=3>; rel="last", <https://x/api?page=2>; rel="next"`, "https://x/api?page=2"},
		{`<https://x/api?page=9>; rel="last"`, ""},
		{"", ""},
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := nextLink(c.header); got != c.want {
			t.Errorf("nextLink(%q) = %q, want %q", c.header, got, c.want)
		}
	}
}
