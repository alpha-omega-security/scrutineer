package worker

import (
	"context"
	"encoding/json"
	"fmt"
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
		if r.URL.Query().Get("page") == "2" {
			_, _ = io.WriteString(w, `[`+
				`{"name":"acme","ecosystem":"npm","dependent_packages_url":"`+base+`/deps/acme"}]`)
			return
		}
		w.Header().Set("Link", `<http://`+r.Host+`/packages?page=2>; rel="next"`)
		_, _ = io.WriteString(w, `[`+
			`{"name":"widget","ecosystem":"npm","dependent_packages_url":"`+base+`/deps/widget"}]`)
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
	mux.HandleFunc("/deps/widget", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = io.WriteString(w, `[{"repo":"downstream-1b"}]`)
			return
		}
		w.Header().Set("Link", `<http://`+r.Host+`/deps/widget?page=2>; rel="next"`)
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
	if !strings.Contains(got.EcosystemsPackagesData, "acme") {
		t.Errorf("packages did not follow pagination: %q", got.EcosystemsPackagesData)
	}
	if !strings.Contains(got.EcosystemsDependentsData, "downstream-2") {
		t.Errorf("dependents missing second package: %q", got.EcosystemsDependentsData)
	}
	if !strings.Contains(got.EcosystemsDependentsData, "downstream-1b") {
		t.Errorf("dependents did not follow dependent_packages_url pagination: %q", got.EcosystemsDependentsData)
	}
}

func TestFetchDependentsPaginationStopsAtCaps(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/packages", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		start, end := 0, 24
		if r.URL.Query().Get("page") == "2" {
			start, end = 24, 26
		} else {
			w.Header().Set("Link", `<http://`+r.Host+`/packages?page=2>; rel="next"`)
		}
		writeJSONArray(w, start, end, func(i int) string {
			name := fmt.Sprintf("pkg%02d", i)
			return fmt.Sprintf(`{"name":%q,"ecosystem":"npm","dependent_packages_url":%q}`, name, base+"/deps/"+name)
		})
	})
	mux.HandleFunc("/deps/pkg00", func(w http.ResponseWriter, r *http.Request) {
		start, end := 0, 29
		if r.URL.Query().Get("page") == "2" {
			start, end = 29, 31
		} else {
			w.Header().Set("Link", `<http://`+r.Host+`/deps/pkg00?page=2>; rel="next"`)
		}
		writeJSONArray(w, start, end, func(i int) string {
			return fmt.Sprintf(`{"name":"dep%02d","purl":"pkg:npm/dep%02d"}`, i, i)
		})
	})
	mux.HandleFunc("/deps/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body, err := fetchDependents(context.Background(), ecosystemsEndpoints{packages: srv.URL + "/packages"},
		"https://github.com/acme/widget", slog.Default())
	if err != nil {
		t.Fatalf("fetchDependents: %v", err)
	}
	var entries []dependentsEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != maxDependentPackages {
		t.Fatalf("dependents entries = %d, want cap %d: %s", len(entries), maxDependentPackages, body)
	}
	if findDependentsEntry(entries, "pkg25") != nil {
		t.Fatalf("package past cap was fetched: %s", body)
	}
	pkg00 := findDependentsEntry(entries, "pkg00")
	if pkg00 == nil {
		t.Fatalf("pkg00 entry missing: %s", body)
	}
	if len(pkg00.Dependents) != maxDependentsPerPackage {
		t.Fatalf("pkg00 dependents = %d, want cap %d", len(pkg00.Dependents), maxDependentsPerPackage)
	}
	joined := string(mustMarshal(t, pkg00.Dependents))
	if !strings.Contains(joined, "dep29") || strings.Contains(joined, "dep30") {
		t.Fatalf("dependent pagination/cap wrong: %s", joined)
	}
}

func TestAppendEcosystemsPagesStopsWhenInitialBodyHitsCap(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = io.WriteString(w, `[{"name":"second"}]`)
	}))
	t.Cleanup(srv.Close)

	rows, err := appendEcosystemsPages(
		context.Background(),
		[]json.RawMessage{json.RawMessage(`{"name":"first"}`)},
		maxResponseBody,
		srv.URL,
		maxEcosystemsPages-1,
		0,
		slog.Default(),
		"test pagination cap",
	)
	if err != nil {
		t.Fatalf("appendEcosystemsPages: %v", err)
	}
	if hits != 0 {
		t.Fatalf("fetched next page after first page hit response cap: hits=%d", hits)
	}
	if len(rows) != 1 || !strings.Contains(string(rows[0]), "first") {
		t.Fatalf("rows = %s, want only initial row", mustMarshal(t, rows))
	}
}

func writeJSONArray(w io.Writer, start, end int, item func(int) string) {
	_, _ = io.WriteString(w, `[`)
	for i := start; i < end; i++ {
		if i > start {
			_, _ = io.WriteString(w, `,`)
		}
		_, _ = io.WriteString(w, item(i))
	}
	_, _ = io.WriteString(w, `]`)
}

func findDependentsEntry(entries []dependentsEntry, name string) *dependentsEntry {
	for i := range entries {
		if entries[i].Package == name {
			return &entries[i]
		}
	}
	return nil
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return body
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

func TestUpdateDependentsTable_mapsUpstreamPayload(t *testing.T) {
	gdb := openEcosystemsTestDB(t)
	repo := db.Repository{URL: "https://github.com/acme/widget", Name: "widget"}
	gdb.Create(&repo)
	gdb.Create(&db.Dependent{RepositoryID: repo.ID, Name: "stale", Ecosystem: "npm"})

	payload := []dependentsEntry{
		{
			Package:   "widget",
			Ecosystem: "npm",
			Dependents: []json.RawMessage{
				json.RawMessage(`{
					"name":"rails-x",
					"ecosystem":"rubygems",
					"purl":"pkg:gem/rails-x",
					"downloads":5000,
					"dependent_repos_count":200,
					"registry_url":"https://rubygems.org/gems/rails-x",
					"latest_release_number":"7.0.0",
					"repo_metadata":{"html_url":"https://github.com/acme/rails-x"}
				}`),
				json.RawMessage(`{
					"name":"action-user",
					"ecosystem":"github-actions",
					"purl":"pkg:githubactions/acme/action-user",
					"repository_url":"https://github.com/acme/action-user",
					"downloads":42,
					"dependent_repos_count":9,
					"latest_release_number":"v1"
				}`),
			},
		},
		{
			Package:   "widget-extra",
			Ecosystem: "npm",
			Dependents: []json.RawMessage{
				json.RawMessage(`{
					"name":"rails-x-duplicate",
					"ecosystem":"rubygems",
					"purl":"pkg:gem/rails-x",
					"downloads":9999,
					"dependent_repos_count":999,
					"repository_url":"https://github.com/acme/rails-x-duplicate",
					"latest_release_number":"9.9.9"
				}`),
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
