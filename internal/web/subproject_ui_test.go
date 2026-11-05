package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"

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
	sub := db.Subproject{RepositoryID: repo.ID, Path: "active support/core&next=all", Name: "activesupport", Kind: "ruby-gem"}
	s.DB.Create(&sub)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SubPath: sub.Path}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, SubPath: sub.Path,
		FindingID: "F1", Title: "XSS in ActiveSupport", Severity: "High", Status: db.FindingNew, Location: "lib/x.rb:1"})
	s.DB.Create(&db.Package{RepositoryID: repo.ID, SubprojectID: &sub.ID, Name: "activesupport", Ecosystem: "rubygems"})

	r := httptest.NewRequest("GET", subURL(repo.ID, sub.ID, ""), nil)
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"activesupport", "XSS in ActiveSupport", "repo@example.org", "ruby-gem", "rubygems", " Disclosure channel</dt>"} {
		if !strings.Contains(body, want) {
			t.Errorf("subproject page missing %q", want)
		}
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse subproject page: %v", err)
	}
	var exportHref string
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "a" {
			for _, attr := range node.Attr {
				if attr.Key == "href" && strings.HasPrefix(attr.Val, "/api/v1/repositories/") && strings.Contains(attr.Val, "/findings?") {
					exportHref = attr.Val
				}
			}
		}
		for child := node.FirstChild; child != nil && exportHref == ""; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	if exportHref == "" {
		t.Fatal("subproject page missing export findings link")
	}
	exportURL, err := url.Parse(exportHref)
	if err != nil {
		t.Fatalf("parse export URL: %v", err)
	}
	if exportURL.Scheme != "" || exportURL.Host != "" {
		t.Fatalf("export URL must be relative, got %q", exportHref)
	}
	wantPath := "/api/v1/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/findings"
	if exportURL.Path != wantPath {
		t.Errorf("export URL path = %q, want %q", exportURL.Path, wantPath)
	}
	if got := exportURL.Query().Get("sub_path"); got != sub.Path {
		t.Errorf("export URL sub_path = %q, want %q", got, sub.Path)
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
	asOperator(r)
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
		asOperator(r)
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
