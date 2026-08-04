package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func ecosystemsRawReq(t *testing.T, s *Server, token string, repoID uint, source string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/repositories/"+strconv.FormatUint(uint64(repoID), 10)+"/ecosystems/"+source+"/raw", nil)
	r.Host = testHost
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestAPIEcosystemsRaw_returnsCachedPayload(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	payload := `{"full_name":"acme/widget","stars":3}`
	s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).Update("ecosystems_repo_data", payload)

	w := ecosystemsRawReq(t, s, scan.APIToken, repo.ID, "repo")
	if w.Code != 200 {
		t.Fatalf("status %d, want 200. body=%s", w.Code, w.Body)
	}
	if w.Body.String() != payload {
		t.Errorf("body = %q, want verbatim %q", w.Body.String(), payload)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q, want application/json", ct)
	}
}

func TestAPIEcosystemsRaw_404WhenEmpty(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	w := ecosystemsRawReq(t, s, scan.APIToken, repo.ID, "packages")
	if w.Code != 404 {
		t.Fatalf("status %d, want 404 for uncached source. body=%s", w.Code, w.Body)
	}
}

func TestAPIEcosystemsRaw_400UnknownSource(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	w := ecosystemsRawReq(t, s, scan.APIToken, repo.ID, "bogus")
	if w.Code != 400 {
		t.Fatalf("status %d, want 400 for unknown source. body=%s", w.Code, w.Body)
	}
}

func TestAPIEcosystemsRaw_403CrossRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, scan := seedRunningScan(t, s)

	other := db.Repository{URL: "https://example.com/y", Name: "y"}
	s.DB.Create(&other)
	s.DB.Model(&db.Repository{}).Where("id = ?", other.ID).Update("ecosystems_repo_data", `{"leak":true}`)

	w := ecosystemsRawReq(t, s, scan.APIToken, other.ID, "repo")
	if w.Code != 403 {
		t.Fatalf("status %d, want 403 for cross-repo access. body=%s", w.Code, w.Body)
	}
}

func TestCreateOrTriageRepo_prefetchesNewRemoteRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	var got []uint
	s.prefetchEcosystems = func(id uint) { got = append(got, id) }

	repo, _, err := s.createOrTriageRepo(context.Background(), RepoInput{
		CloneURL: "https://github.com/acme/widget", Owner: "acme", Name: "widget",
	}, "", true)
	if err != nil {
		t.Fatalf("createOrTriageRepo: %v", err)
	}
	if len(got) != 1 || got[0] != repo.ID {
		t.Errorf("prefetch calls = %v, want one call for repo %d", got, repo.ID)
	}
}

func TestCreateOrTriageRepo_skipsPrefetchForLocalRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	called := false
	s.prefetchEcosystems = func(uint) { called = true }

	if _, _, err := s.createOrTriageRepo(context.Background(), RepoInput{
		CloneURL: LocalScheme + t.TempDir(), Name: "local", Local: true,
	}, "", true); err != nil {
		t.Fatalf("createOrTriageRepo: %v", err)
	}
	if called {
		t.Error("prefetch fired for a local repo, want skipped")
	}
}

// The guarantee is structural: DisableEcosystems neuters the two seams that
// reach the network, so a caller that forgets the handler-level check still
// cannot make a request. Asserting on a stub installed afterwards would only
// pin the caller-side check and miss exactly that.
func TestDisableEcosystems_neutersTheNetworkSeams(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DisableEcosystems()

	if s.prefetchEcosystems != nil {
		t.Error("prefetch seam still wired after DisableEcosystems")
	}
	if got := s.resolvePURL(context.Background(), "pkg:npm/widget"); got != "" {
		t.Errorf("resolvePURL seam returned %q after DisableEcosystems, want empty", got)
	}
	if s.ecosystemsEnrichment {
		t.Error("ecosystemsEnrichment still true after DisableEcosystems")
	}
}

func TestCreateOrTriageRepo_skipsPrefetchWhenEnrichmentDisabled(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DisableEcosystems()

	if _, _, err := s.createOrTriageRepo(context.Background(), RepoInput{
		CloneURL: "https://github.com/acme/widget", Owner: "acme", Name: "widget",
	}, "", true); err != nil {
		t.Fatalf("createOrTriageRepo with the prefetch seam removed: %v", err)
	}
}

func TestDepScan_refusesWhenEnrichmentDisabled(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DisableEcosystems()
	resolved := false
	s.resolvePURL = func(context.Context, string) string {
		resolved = true
		return "https://github.com/acme/widget"
	}
	repo := db.Repository{URL: "https://github.com/acme/app", Name: "app"}
	s.DB.Create(&repo)
	dep := db.Dependency{RepositoryID: repo.ID, Name: "widget", Ecosystem: "npm", PURL: "pkg:npm/widget"}
	s.DB.Create(&dep)

	r := localReq("POST", fmt.Sprintf("/dependencies/%d/scan", dep.ID))
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), ecosystemsDisabled) {
		t.Errorf("body = %q, want the disabled-enrichment reason", w.Body)
	}
	if resolved {
		t.Error("import still called the PURL lookup with enrichment disabled")
	}
}

func seedDependency(t *testing.T, s *Server, purl string) db.Dependency {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/app", Name: "app"}
	s.DB.Create(&repo)
	dep := db.Dependency{RepositoryID: repo.ID, Name: "widget", Ecosystem: "npm", PURL: purl}
	s.DB.Create(&dep)
	return dep
}

func depScanReq(t *testing.T, s *Server, depID uint) *httptest.ResponseRecorder {
	t.Helper()
	r := localReq("POST", fmt.Sprintf("/dependencies/%d/scan", depID))
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestDepScan_importsResolvedRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.resolvePURL = func(context.Context, string) string { return "https://github.com/acme/widget" }
	dep := seedDependency(t, s, "pkg:npm/widget")

	if code := depScanReq(t, s, dep.ID).Code; code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", code)
	}
	var imported db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/acme/widget").First(&imported).Error; err != nil {
		t.Fatalf("resolved repository was not created: %v", err)
	}
}

// A dependency carrying no PURL was unresolvable either way, so flipping the
// setting must not change the reason it gets.
func TestDepScan_noPURLKeeps422WhenEnrichmentDisabled(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DisableEcosystems()
	dep := seedDependency(t, s, "")

	w := depScanReq(t, s, dep.ID)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (not the enrichment 503); body=%s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), ecosystemsDisabled) {
		t.Errorf("body = %q, want the unresolvable reason, not the setting", w.Body)
	}
}

func TestCreateOrTriageRepo_skipsPrefetchForExistingRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	var got []uint
	s.prefetchEcosystems = func(id uint) { got = append(got, id) }

	in := RepoInput{CloneURL: "https://github.com/acme/widget", Owner: "acme", Name: "widget"}
	if _, _, err := s.createOrTriageRepo(context.Background(), in, "", true); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if _, _, err := s.createOrTriageRepo(context.Background(), in, "", true); err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("prefetch calls = %d, want 1 (only the new repo, not the re-add)", len(got))
	}
}
