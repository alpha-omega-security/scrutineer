package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func subURL(repoID, subID uint, suffix string) string {
	return "/repositories/" + strconv.FormatUint(uint64(repoID), 10) +
		"/subprojects/" + strconv.FormatUint(uint64(subID), 10) + suffix
}

func TestSubprojectShow(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.MonorepoAttribution = true // show the attributed packages/advisories sections
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails", DisclosureChannel: "repo@example.org"}
	s.DB.Create(&repo)
	sub := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport", Kind: "ruby-gem"}
	s.DB.Create(&sub)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SubPath: "activesupport"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, SubPath: "activesupport",
		FindingID: "F1", Title: "XSS in ActiveSupport", Severity: "High", Status: db.FindingNew, Location: "lib/x.rb:1"})
	s.DB.Create(&db.Package{RepositoryID: repo.ID, SubprojectID: &sub.ID, Name: "activesupport", Ecosystem: "rubygems"})

	r := httptest.NewRequest("GET", subURL(repo.ID, sub.ID, ""), nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"activesupport", "XSS in ActiveSupport", "repo@example.org", "ruby-gem", "rubygems"} {
		if !strings.Contains(body, want) {
			t.Errorf("subproject page missing %q", want)
		}
	}
}

func TestSubprojectShow_wrongRepo404(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoA := db.Repository{URL: "https://github.com/a/a", Name: "a"}
	repoB := db.Repository{URL: "https://github.com/b/b", Name: "b"}
	s.DB.Create(&repoA)
	s.DB.Create(&repoB)
	sub := db.Subproject{RepositoryID: repoA.ID, Path: "x", Name: "x"}
	s.DB.Create(&sub)

	// Ask for repoB's page with repoA's subproject id: must 404, not leak.
	r := httptest.NewRequest("GET", subURL(repoB.ID, sub.ID, ""), nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("cross-repo subproject: status %d, want 404", w.Code)
	}
}

func TestSubprojectDisclosureChannel_setAndClearFallsBack(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails", DisclosureChannel: "repo@example.org"}
	s.DB.Create(&repo)
	sub := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport"}
	s.DB.Create(&sub)

	post := func(v string) {
		form := url.Values{"disclosure_channel": {v}}
		r := httptest.NewRequest("POST", subURL(repo.ID, sub.ID, "/disclosure-channel"), strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Host = testHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code >= 400 {
			t.Fatalf("post channel %q: status %d", v, w.Code)
		}
	}

	post("as@example.org")
	if ch := db.EffectiveDisclosureChannel(s.DB, repo.ID, "activesupport"); ch != "as@example.org" {
		t.Errorf("effective after set = %q, want as@example.org", ch)
	}
	post("") // clear -> falls back to the repo channel
	if ch := db.EffectiveDisclosureChannel(s.DB, repo.ID, "activesupport"); ch != "repo@example.org" {
		t.Errorf("effective after clear = %q, want repo@example.org fallback", ch)
	}
}

func TestApplyFindingFilters_subPath(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, SubPath: "activesupport", FindingID: "F1", Title: "a", Severity: "High", Status: db.FindingNew, Location: "a:1"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, SubPath: "actionpack", FindingID: "F2", Title: "b", Severity: "Low", Status: db.FindingNew, Location: "b:1"})

	r := httptest.NewRequest("GET", "/x?sub_path=activesupport", nil)
	q := applyFindingFilters(s.DB.Model(&db.Finding{}).Where("repository_id = ?", repo.ID), r)
	var got []db.Finding
	q.Find(&got)
	if len(got) != 1 || got[0].SubPath != "activesupport" {
		t.Errorf("sub_path filter returned %d rows, want 1 activesupport", len(got))
	}
}
