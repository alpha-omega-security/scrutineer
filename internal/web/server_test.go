package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func newTestServer(t *testing.T) (*Server, func()) {
	t.Helper()
	gdb, err := db.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	q, err := queue.New(sqldb, log, 0)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(gdb, q, log, NewBroker())
	if err != nil {
		t.Fatal(err)
	}
	return s, func() { _ = sqldb.Close() }
}

func localReq(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "127.0.0.1:8080"
	return r
}

func TestRepoSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Repository{URL: "https://github.com/rails/rails", Name: "rails", FullName: "rails/rails", Description: "Ruby on Rails"})
	s.DB.Create(&db.Repository{URL: "https://github.com/rubygems/rubygems", Name: "rubygems", FullName: "rubygems/rubygems", Description: "gem package manager"})
	s.DB.Create(&db.Repository{URL: "https://github.com/rails-api/jbuilder", Name: "jbuilder", FullName: "rails-api/jbuilder", Description: "JSON builder"})

	cases := []struct {
		query string
		match []string
		drop  []string
	}{
		{query: "rails", match: []string{"rails/rails", "rails-api/jbuilder"}, drop: []string{"rubygems/rubygems"}},
		{query: "package", match: []string{"rubygems/rubygems"}, drop: []string{"rails/rails", "rails-api/jbuilder"}},
		{query: "jbuilder", match: []string{"rails-api/jbuilder"}, drop: []string{"rails/rails", "rubygems/rubygems"}},
		{query: "NOPE_NOPE_NOPE", match: nil, drop: []string{"rails/rails", "rubygems/rubygems", "rails-api/jbuilder"}},
	}

	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/?q="+url.QueryEscape(tc.query)))
		if w.Code != 200 {
			t.Fatalf("q=%q status %d: %s", tc.query, w.Code, w.Body)
		}
		body := w.Body.String()
		for _, want := range tc.match {
			if !strings.Contains(body, want) {
				t.Errorf("q=%q: body missing %q", tc.query, want)
			}
		}
		for _, drop := range tc.drop {
			if strings.Contains(body, drop) {
				t.Errorf("q=%q: body should not contain %q", tc.query, drop)
			}
		}
		if len(tc.match) == 0 && !strings.Contains(body, "No matches") {
			t.Errorf("q=%q: empty-match body missing 'No matches' state", tc.query)
		}
	}
}

func TestRepoSearchPreservesOtherFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Repository{URL: "https://github.com/rails/rails", Name: "rails", Languages: "Ruby"})
	s.DB.Create(&db.Repository{URL: "https://github.com/go-rails/something", Name: "go-rails", Languages: "Go"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/?q=rails&language=Ruby"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "rails/rails") || strings.Contains(body, "go-rails/something") {
		t.Errorf("q=rails language=Ruby did not combine correctly. body=%s", body)
	}
}

func TestFindingsSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "SSRF in image fetcher",
		Severity: "High", Location: "fetch.go:42", CWE: "CWE-918"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "OS command injection",
		Severity: "Critical", Location: "shell.go:10", CWE: "CWE-78", CVEID: "CVE-2026-1"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "Stored XSS",
		Severity: "Medium", Location: "view.go:5", CWE: "CWE-79"})

	cases := map[string][]string{
		"SSRF":           {"SSRF in image fetcher"},
		"command":        {"OS command injection"},
		"shell.go":       {"OS command injection"},
		"CWE-79":         {"Stored XSS"},
		"CVE-2026-1":     {"OS command injection"},
		"NOPE_NOPE_NOPE": nil,
	}
	for q, want := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/findings?q="+url.QueryEscape(q)))
		if w.Code != 200 {
			t.Errorf("q=%q status %d", q, w.Code)
			continue
		}
		body := w.Body.String()
		for _, title := range want {
			if !strings.Contains(body, title) {
				t.Errorf("q=%q missing %q", q, title)
			}
		}
		if len(want) == 0 && !strings.Contains(body, "No matches") {
			t.Errorf("q=%q empty state missing", q)
		}
	}
}

func TestPackagesSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "lodash", Ecosystem: "npm", PURL: "pkg:npm/lodash"})
	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "express", Ecosystem: "npm", PURL: "pkg:npm/express", Licenses: "MIT"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/packages?q=lodash"))
	body := w.Body.String()
	if !strings.Contains(body, "lodash") || strings.Contains(body, "express") {
		t.Errorf("name search: %s", body)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/packages?q=MIT"))
	body = w.Body.String()
	if !strings.Contains(body, "express") {
		t.Errorf("license search did not find express: %s", body)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/packages?q=NOPE_NOPE_NOPE"))
	if !strings.Contains(w.Body.String(), "No matches") {
		t.Error("empty-match packages: no empty state")
	}
}

func TestAdvisoriesIndex(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	railsRepo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	s.DB.Create(&railsRepo)
	djangoRepo := db.Repository{URL: "https://github.com/django/django", Name: "django"}
	s.DB.Create(&djangoRepo)

	now := time.Now()
	s.DB.Create(&db.Advisory{RepositoryID: railsRepo.ID, UUID: "u1",
		URL: "https://example.com/a1", Title: "SQL injection in activerecord",
		Severity: "CRITICAL", CVSSScore: 9.8, Packages: "rails,activerecord",
		Classification: "CWE-89", PublishedAt: &now})
	s.DB.Create(&db.Advisory{RepositoryID: djangoRepo.ID, UUID: "u2",
		URL: "https://example.com/a2", Title: "XSS in admin",
		Severity: "MODERATE", CVSSScore: 5.4, Packages: "django",
		Classification: "CWE-79", PublishedAt: &now})

	// All advisories render.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"SQL injection in activerecord",
		"XSS in admin",
		"rails", "django",
		"9.8", "5.4",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}

	// Severity filter: only CRITICAL rows.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories?severity=CRITICAL"))
	body = w.Body.String()
	if !strings.Contains(body, "SQL injection") || strings.Contains(body, "XSS in admin") {
		t.Errorf("severity filter: %s", body)
	}

	// Search: classification match.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories?q=CWE-79"))
	body = w.Body.String()
	if !strings.Contains(body, "XSS in admin") || strings.Contains(body, "SQL injection") {
		t.Errorf("search: %s", body)
	}

	// Empty-match state.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories?q=NOPE_NOPE_NOPE"))
	if !strings.Contains(w.Body.String(), "No matches") {
		t.Error("empty-match advisories: no empty state")
	}
}

func TestMaintainersSortOptions(t *testing.T) {
	const (
		zeta    = "zeta"
		alpha   = "alpha"
		charlie = "charlie"
	)
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Maintainer{Login: zeta, Name: "Alice", Status: db.MaintainerActive})
	s.DB.Create(&db.Maintainer{Login: alpha, Name: "Zed", Status: db.MaintainerInactive})
	s.DB.Create(&db.Maintainer{Login: charlie, Name: "", Status: db.MaintainerUnknown})

	// logins returns the order the three seeded logins appear in a rendered body.
	logins := func(body string) []string {
		idx := map[string]int{}
		for _, want := range []string{alpha, charlie, zeta} {
			if i := strings.Index(body, want); i >= 0 {
				idx[want] = i
			}
		}
		out := []string{alpha, charlie, zeta}
		for i := 0; i < len(out); i++ {
			for j := i + 1; j < len(out); j++ {
				if idx[out[j]] < idx[out[i]] {
					out[i], out[j] = out[j], out[i]
				}
			}
		}
		return out
	}
	orderBy := func(path string) []string {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", path))
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		return logins(w.Body.String())
	}

	// sort=name (default): Alice(zeta) then Zed(alpha) then empty-name(charlie).
	nameOrder := orderBy("/maintainers?sort=name")
	if nameOrder[0] != zeta || nameOrder[1] != alpha || nameOrder[2] != charlie {
		t.Errorf("sort=name order: %v", nameOrder)
	}

	// sort=login: alpha, charlie, zeta
	loginOrder := orderBy("/maintainers?sort=login")
	if loginOrder[0] != alpha || loginOrder[1] != charlie || loginOrder[2] != zeta {
		t.Errorf("sort=login order: %v", loginOrder)
	}

	// sort=newest: most recently created first (charlie was inserted last).
	newestOrder := orderBy("/maintainers?sort=newest")
	if newestOrder[0] != charlie {
		t.Errorf("sort=newest expected charlie first, got %v", newestOrder)
	}
}

func TestMaintainersSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Maintainer{Login: "alice", Name: "Alice Example", Email: "alice@example.com", Company: "Acme"})
	s.DB.Create(&db.Maintainer{Login: "bob", Name: "Bob", Email: "bob@other.net", Notes: "has bus factor risk"})

	cases := map[string][]string{
		"alice":          {"alice"},
		"@example.com":   {"alice"},
		"Acme":           {"alice"},
		"bus factor":     {"bob"},
		"NOPE_NOPE_NOPE": nil,
	}
	for q, want := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/maintainers?q="+url.QueryEscape(q)))
		if w.Code != 200 {
			t.Errorf("q=%q status %d", q, w.Code)
			continue
		}
		body := w.Body.String()
		for _, login := range want {
			if !strings.Contains(body, login) {
				t.Errorf("q=%q missing %q", q, login)
			}
		}
		if len(want) == 0 && !strings.Contains(body, "No matches") {
			t.Errorf("q=%q empty state missing", q)
		}
	}
}

func TestIndexRenders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `name="url"`) {
		t.Error("missing form")
	}
}

func TestCreateRepoEnqueuesTriageSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	// Seed a triage skill; without it adding a repo is a no-op.
	triage := db.Skill{
		Name:        "triage",
		Description: "orchestrator",
		Body:        "body",
		Active:      true,
		Source:      "ui",
		Version:     1,
	}
	s.DB.Create(&triage)

	form := url.Values{"url": {"https://github.com/foo/bar.git"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("create status %d: %s", w.Code, w.Body)
	}
	if w.Header().Get("HX-Redirect") == "" {
		t.Error("expected HX-Redirect")
	}

	var repo db.Repository
	if err := s.DB.First(&repo).Error; err != nil {
		t.Fatal(err)
	}
	var scans []db.Scan
	s.DB.Where("repository_id = ?", repo.ID).Find(&scans)
	if len(scans) != 1 {
		t.Fatalf("expected one scan (triage), got %d", len(scans))
	}
	if scans[0].SkillID == nil || *scans[0].SkillID != triage.ID {
		t.Errorf("scan SkillID = %v, want %d", scans[0].SkillID, triage.ID)
	}
}

func TestScanShowRenders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "u", Name: "n"}
	s.DB.Create(&repo)
	now := time.Now()
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "claude", Status: db.ScanDone,
		StartedAt: &now, FinishedAt: &now, Report: "# hi", Log: "line1\n",
	}
	s.DB.Create(&scan)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans/1"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "# hi") || !strings.Contains(body, "line1") {
		t.Errorf("missing report/log: %s", body)
	}
}
