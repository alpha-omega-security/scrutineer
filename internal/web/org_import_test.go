package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// orgRepoFixture is the canned org listing the stubbed fetcher returns: one
// plain repo, one fork, one archived repo. Default import keeps only the
// plain one.
var orgRepoFixture = []OrgRepo{
	{FullName: "acme/app", CloneURL: "https://github.com/acme/app.git"},
	{FullName: "acme/fork", CloneURL: "https://github.com/acme/fork.git", Fork: true},
	{FullName: "acme/old", CloneURL: "https://github.com/acme/old.git", Archived: true},
}

func postOrgImport(t *testing.T, s *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/repositories/org", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestOrgImport_skipsForksAndArchivedByDefault(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	triage := db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&triage)
	s.fetchOrgRepos = func(_ context.Context, org string) ([]OrgRepo, error) {
		if org != "acme" {
			t.Errorf("fetchOrgRepos got org %q, want acme", org)
		}
		return orgRepoFixture, nil
	}

	w := postOrgImport(t, s, url.Values{"org": {"acme"}, "confirm": {"1"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/orgs/acme" {
		t.Errorf("Location = %q, want /orgs/acme", loc)
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "1 added") || !strings.Contains(f.Title, "2 forks/archived/mirrors skipped") {
		t.Errorf("flash title = %q, want '1 added' and '2 forks/archived/mirrors skipped'", f.Title)
	}

	var repos []db.Repository
	s.DB.Find(&repos)
	if len(repos) != 1 || repos[0].URL != "https://github.com/acme/app" {
		t.Fatalf("want only acme/app imported, got %+v", repos)
	}
	var scans []db.Scan
	s.DB.Where("skill_id = ?", triage.ID).Find(&scans)
	if len(scans) != 1 {
		t.Fatalf("want 1 triage scan, got %d", len(scans))
	}
}

// TestOrgImport_previewDoesNotImport confirms the first POST (no confirm flag)
// only previews the count: it must not write any repos and must surface the
// post-filter count for the operator to confirm.
func TestOrgImport_previewDoesNotImport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) { return orgRepoFixture, nil }

	w := postOrgImport(t, s, url.Values{"org": {"acme"}})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (preview, not redirect); body=%s", w.Code, w.Body)
	}
	// Default filters keep only the one plain repo.
	if body := w.Body.String(); !strings.Contains(body, "add 1 repo") {
		t.Errorf("preview body missing 'add 1 repo' count; got %s", body)
	}
	var n int64
	s.DB.Model(&db.Repository{}).Count(&n)
	if n != 0 {
		t.Fatalf("preview wrote %d repos, want 0 (nothing imported until confirmed)", n)
	}
}

// TestOrgImport_previewHXSwapsConfirmStep confirms an htmx request gets the
// OOB confirmation panel (replacing the input form) rather than the full page.
func TestOrgImport_previewHXSwapsConfirmStep(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) { return orgRepoFixture, nil }

	req := httptest.NewRequest("POST", "/repositories/org", strings.NewReader(url.Values{"org": {"acme"}}.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	body := w.Body.String()
	for _, want := range []string{`id="org-import-step"`, `hx-swap-oob="outerHTML"`, `name="confirm"`, "add 1 repo"} {
		if !strings.Contains(body, want) {
			t.Errorf("htmx preview missing %q; got %s", want, body)
		}
	}
	var n int64
	s.DB.Model(&db.Repository{}).Count(&n)
	if n != 0 {
		t.Fatalf("htmx preview wrote %d repos, want 0", n)
	}
}

// TestOrgImport_previewCountReflectsToggles confirms the previewed count uses
// the fork/archived toggles: with both on, all three fixture repos qualify.
func TestOrgImport_previewCountReflectsToggles(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) { return orgRepoFixture, nil }

	w := postOrgImport(t, s, url.Values{
		"org":              {"acme"},
		"include_forks":    {"1"},
		"include_archived": {"1"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200; body=%s", w.Code, w.Body)
	}
	if body := w.Body.String(); !strings.Contains(body, "add 3 repos") {
		t.Errorf("preview body missing 'add 3 repos' count; got %s", body)
	}
}

func TestOrgImport_includeForksAndArchived(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) { return orgRepoFixture, nil }

	w := postOrgImport(t, s, url.Values{
		"org":              {"acme"},
		"include_forks":    {"1"},
		"include_archived": {"1"},
		"confirm":          {"1"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "3 added") {
		t.Errorf("flash title = %q, want '3 added'", f.Title)
	}
	if strings.Contains(f.Title, "skipped") {
		t.Errorf("flash title = %q, should not skip anything with both toggles on", f.Title)
	}
	var n int64
	s.DB.Model(&db.Repository{}).Count(&n)
	if n != 3 {
		t.Fatalf("want 3 repos imported, got %d", n)
	}
}

// TestOrgImport_skipsMirrors confirms mirrors are excluded unconditionally —
// there is no opt-in toggle, so even include_forks/include_archived leave them
// out.
func TestOrgImport_skipsMirrors(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) {
		return []OrgRepo{
			{FullName: "acme/app", CloneURL: "https://github.com/acme/app.git"},
			{FullName: "acme/mirror", CloneURL: "https://github.com/acme/mirror.git", MirrorURL: "https://upstream.example/repo.git"},
		}, nil
	}

	w := postOrgImport(t, s, url.Values{
		"org":              {"acme"},
		"include_forks":    {"1"},
		"include_archived": {"1"},
		"confirm":          {"1"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "1 added") || !strings.Contains(f.Title, "1 forks/archived/mirrors skipped") {
		t.Errorf("flash title = %q, want '1 added' and '1 forks/archived/mirrors skipped'", f.Title)
	}
	var repos []db.Repository
	s.DB.Find(&repos)
	if len(repos) != 1 || repos[0].URL != "https://github.com/acme/app" {
		t.Fatalf("want only acme/app imported (mirror skipped), got %+v", repos)
	}
}

func TestOrgImport_skipsExistingRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	// ParseRepoInput strips the .git suffix, so the existing row must use
	// the normalized URL for the dedup to recognize it.
	s.DB.Create(&db.Repository{URL: "https://github.com/acme/app", Name: "app"})
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) { return orgRepoFixture, nil }

	w := postOrgImport(t, s, url.Values{"org": {"acme"}, "confirm": {"1"}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "0 added") || !strings.Contains(f.Title, "1 already present") {
		t.Errorf("flash title = %q, want '0 added' and '1 already present'", f.Title)
	}
}

func TestOrgImport_requiresOrgName(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	called := false
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) {
		called = true
		return nil, nil
	}

	w := postOrgImport(t, s, url.Values{"org": {"  "}})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422", w.Code)
	}
	if called {
		t.Error("fetchOrgRepos should not run for a blank org name")
	}
}

func TestOrgImport_fetchError(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.fetchOrgRepos = func(context.Context, string) ([]OrgRepo, error) {
		return nil, errors.New("no GitHub organization or user named \"nope\"")
	}

	w := postOrgImport(t, s, url.Values{"org": {"nope"}})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502; body=%s", w.Code, w.Body)
	}
}

// TestOrgImport_stripsAtPrefix lets users paste an "@org" handle.
func TestOrgImport_stripsAtPrefix(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})
	var got string
	s.fetchOrgRepos = func(_ context.Context, org string) ([]OrgRepo, error) {
		got = org
		return nil, nil
	}

	postOrgImport(t, s, url.Values{"org": {"@acme"}})
	if got != "acme" {
		t.Errorf("fetchOrgRepos got org %q, want acme (leading @ stripped)", got)
	}
}

// TestOrgImport_dialogReachable confirms the org-import dialog ships in the
// primary (htmx) layout and is wired to a link in the bulk dialog, so the
// feature is reachable without falling back to the no-JS page.
func TestOrgImport_dialogReachable(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = testHost
	s.Handler().ServeHTTP(w, req)
	body := w.Body.String()
	for _, want := range []string{
		`id="org-add-repo"`,
		`action="/repositories/org"`,
		`data-dialog="org-add-repo"`,
		`name="include_forks"`,
		`name="include_archived"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("layout missing %q (org import not reachable from primary UI)", want)
		}
	}
}

func TestRepoNew_rendersOrgForm(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	req := httptest.NewRequest("GET", "/repositories/new?org=1", nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`action="/repositories/org"`, `name="org"`, `name="include_forks"`, `name="include_archived"`} {
		if !strings.Contains(body, want) {
			t.Errorf("org form missing %q", want)
		}
	}
}

// withGitHubAPI points the fetcher at a test server for the duration of a test.
func withGitHubAPI(t *testing.T, base string) {
	t.Helper()
	prev := githubAPI
	githubAPI = base
	t.Cleanup(func() { githubAPI = prev })
}

func makeRepos(prefix string, n int) []OrgRepo {
	repos := make([]OrgRepo, n)
	for i := range repos {
		name := prefix + "/r" + strconv.Itoa(i)
		repos[i] = OrgRepo{FullName: name, CloneURL: "https://github.com/" + name + ".git"}
	}
	return repos
}

// TestFetchGitHubOrgRepos_paginates confirms the fetcher walks every page and
// stops on the first short page.
func TestFetchGitHubOrgRepos_paginates(t *testing.T) {
	page1 := makeRepos("acme", orgPerPage) // full page -> fetch another
	page2 := makeRepos("acme", 5)          // short page -> stop
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path != "/orgs/acme/repos" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		batch := page2
		if r.URL.Query().Get("page") == "1" {
			batch = page1
		}
		_ = json.NewEncoder(w).Encode(batch)
	}))
	defer srv.Close()
	withGitHubAPI(t, srv.URL)

	repos, err := fetchGitHubOrgRepos(context.Background(), "acme")
	if err != nil {
		t.Fatalf("fetchGitHubOrgRepos: %v", err)
	}
	if want := orgPerPage + 5; len(repos) != want {
		t.Fatalf("got %d repos, want %d", len(repos), want)
	}
	if len(paths) != 2 {
		t.Errorf("made %d requests, want 2 (page 1 full, page 2 short): %v", len(paths), paths)
	}
}

// TestFetchGitHubOrgRepos_userFallback confirms a 404 on /orgs retries /users.
func TestFetchGitHubOrgRepos_userFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/orgs/"):
			http.Error(w, "not found", http.StatusNotFound)
		case r.URL.Path == "/users/octocat/repos":
			// We must not send type=all on the user path: GitHub's default of
			// type=owner is what we want, and type=all would pull in repos the
			// user only collaborates on.
			if got := r.URL.Query().Get("type"); got != "" {
				t.Errorf("/users request carried type=%q, want no type param", got)
			}
			_ = json.NewEncoder(w).Encode(makeRepos("octocat", 2))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	withGitHubAPI(t, srv.URL)

	repos, err := fetchGitHubOrgRepos(context.Background(), "octocat")
	if err != nil {
		t.Fatalf("fetchGitHubOrgRepos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("got %d repos, want 2 from the /users fallback", len(repos))
	}
}

// TestFetchGitHubOrgRepos_unknownOwner returns a friendly error when both
// /orgs and /users 404.
func TestFetchGitHubOrgRepos_unknownOwner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	withGitHubAPI(t, srv.URL)

	_, err := fetchGitHubOrgRepos(context.Background(), "nope")
	if err == nil || !strings.Contains(err.Error(), "no GitHub organization or user") {
		t.Fatalf("err = %v, want a friendly 'no GitHub organization or user' message", err)
	}
}

func TestOrgImportToastTitle(t *testing.T) {
	cases := []struct {
		created, skipped, filtered, invalid int
		want                                string
	}{
		{3, 0, 0, 0, "acme: 3 added"},
		{1, 2, 5, 0, "acme: 1 added, 2 already present, 5 forks/archived/mirrors skipped"},
		{0, 0, 0, 2, "acme: 0 added, 2 invalid"},
	}
	for _, c := range cases {
		got := orgImportToastTitle("acme", c.created, c.skipped, c.filtered, c.invalid)
		if got != c.want {
			t.Errorf("orgImportToastTitle(%d,%d,%d,%d) = %q, want %q",
				c.created, c.skipped, c.filtered, c.invalid, got, c.want)
		}
	}
}
