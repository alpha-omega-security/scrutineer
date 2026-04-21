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
	q, err := queue.New(sqldb, log)
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
