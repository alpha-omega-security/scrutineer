package web

import (
	"context"
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
	}, "")
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
	}, ""); err != nil {
		t.Fatalf("createOrTriageRepo: %v", err)
	}
	if called {
		t.Error("prefetch fired for a local repo, want skipped")
	}
}

func TestCreateOrTriageRepo_skipsPrefetchForExistingRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	var got []uint
	s.prefetchEcosystems = func(id uint) { got = append(got, id) }

	in := RepoInput{CloneURL: "https://github.com/acme/widget", Owner: "acme", Name: "widget"}
	if _, _, err := s.createOrTriageRepo(context.Background(), in, ""); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if _, _, err := s.createOrTriageRepo(context.Background(), in, ""); err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("prefetch calls = %d, want 1 (only the new repo, not the re-add)", len(got))
	}
}
