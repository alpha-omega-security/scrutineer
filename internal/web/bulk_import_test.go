package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"scrutineer/internal/db"
)

func postBulkRescan(t *testing.T, s *Server, form url.Values, htmx bool) Flash {
	t.Helper()
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequest(http.MethodPost, server.URL+"/repositories/bulk", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	asOperator(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	wantStatus, redirectHeader := http.StatusSeeOther, "Location"
	if htmx {
		wantStatus, redirectHeader = http.StatusNoContent, "HX-Redirect"
	}
	if resp.StatusCode != wantStatus || resp.Header.Get(redirectHeader) != "/" {
		t.Fatalf("response: %d %v", resp.StatusCode, resp.Header)
	}
	flashReq := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range resp.Cookies() {
		flashReq.AddCookie(cookie)
	}
	flash := popFlash(httptest.NewRecorder(), flashReq)
	if flash == nil {
		t.Fatal("missing result toast")
	}
	return *flash
}

func newBulkRescanServer(t *testing.T) (*Server, db.Repository, db.Skill) {
	t.Helper()
	s, done := newTestServer(t)
	t.Cleanup(done)
	repo := db.Repository{URL: "https://github.com/foo/one", Name: "one"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "triage", Body: "triage", Active: true, Source: "ui", Version: 1}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	return s, repo, skill
}

func TestBulkRescanExisting(t *testing.T) {
	s, repo, skill := newBulkRescanServer(t)
	model := Models[len(Models)-1].ID
	old := db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, Status: db.ScanDone, SessionID: "prior-session", Report: "prior report"}
	if err := s.DB.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"urls":            {"https://github.com/foo/one\nhttps://github.com/Foo/One.git\nhttps://github.com/foo/two\nhttps://github.com/foo/two/\next::invalid"},
		"rescan_existing": {"1"},
		"model":           {model},
	}
	flash := postBulkRescan(t, s, form, false)
	if flash.Title != "1 added, 1 scan(s) queued, 2 already present, 1 invalid" {
		t.Fatalf("toast: %+v", flash)
	}
	var scans []db.Scan
	if err := s.DB.Where("id <> ?", old.ID).Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 {
		t.Fatalf("new scans: %+v", scans)
	}
	for _, scan := range scans {
		if scan.Status != db.ScanQueued || scan.SkillID == nil || *scan.SkillID != skill.ID || scan.Model != model || scan.SessionID != "" || scan.ResumedFromScanID != nil || scan.RescanMode != db.ScanRescanModeFull {
			t.Errorf("fresh triage: %+v", scan)
		}
	}
	var persisted db.Scan
	if err := s.DB.First(&persisted, old.ID).Error; err != nil {
		t.Fatal(err)
	}
	if persisted.Status != db.ScanDone || persisted.Report != old.Report || persisted.SessionID != old.SessionID {
		t.Fatalf("prior scan changed: %+v", persisted)
	}
	var jobs int64
	if err := s.DB.Table("goqite").Count(&jobs).Error; err != nil {
		t.Fatal(err)
	}
	if jobs != 2 {
		t.Fatalf("queue jobs = %d, want 2", jobs)
	}
	t.Logf("HTTP result: %s; persisted %d fresh scans and %d queue jobs", flash.Title, len(scans), jobs)
}

func TestBulkRescanRequiresOptIn(t *testing.T) {
	s, _, _ := newBulkRescanServer(t)
	for _, opt := range []string{"", "0", "1"} {
		flash := postBulkRescan(t, s, url.Values{"urls": {"https://github.com/foo/one"}, "rescan_existing": {opt}}, true)
		want := "0 added, 1 already present"
		if opt == "1" {
			want = "0 added, 1 scan(s) queued"
		}
		if flash.Title != want {
			t.Fatalf("opt=%q toast=%+v", opt, flash)
		}
	}
	var count int64
	if err := s.DB.Model(&db.Scan{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("scan count = %d, want 1", count)
	}
}

func TestBulkRescanDeduplicatesScopes(t *testing.T) {
	for _, opt := range []string{"", "1"} {
		t.Run("rescan="+opt, func(t *testing.T) {
			s, _, _ := newBulkRescanServer(t)
			urls := []string{
				"https://github.com/foo/one#core", "https://github.com/Foo/One.git#./core/",
				"https://github.com/foo/one/tree/main/core", "https://github.com/foo/one/tree/main/./core",
				"https://github.com/foo/one/tree/release/core", "https://github.com/foo/one#Core",
				"https://github.com/foo/one#../escape",
			}
			flash := postBulkRescan(t, s, url.Values{"urls": {strings.Join(urls, "\n")}, "rescan_existing": {opt}}, false)
			if flash.Title != "0 added, 4 scan(s) queued, 2 already present, 1 invalid" {
				t.Fatalf("toast: %+v", flash)
			}
			var scans []db.Scan
			if err := s.DB.Find(&scans).Error; err != nil {
				t.Fatal(err)
			}
			want := map[[2]string]bool{{"", "core"}: true, {"main", "core"}: true, {"release", "core"}: true, {"", "Core"}: true}
			for _, scan := range scans {
				key := [2]string{scan.Ref, scan.SubPath}
				if !want[key] {
					t.Fatalf("unexpected or duplicate scope: %v", key)
				}
				delete(want, key)
			}
			if len(want) != 0 {
				t.Fatalf("missing scopes: %v", want)
			}
		})
	}
}

func TestBulkRescanWithoutActiveTriage(t *testing.T) {
	s, _, skill := newBulkRescanServer(t)
	if err := s.DB.Model(&skill).Update("active", false).Error; err != nil {
		t.Fatal(err)
	}
	flash := postBulkRescan(t, s, url.Values{"urls": {"https://github.com/foo/one"}, "rescan_existing": {"1"}}, false)
	if flash.Title != "0 added, 1 already present" {
		t.Fatalf("toast: %+v", flash)
	}
	var count int64
	if err := s.DB.Model(&db.Scan{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unexpected scans: %d", count)
	}
}

func TestBulkRescanForms(t *testing.T) {
	s, _, _ := newBulkRescanServer(t)
	for path, want := range map[string]int{"/": 1, "/repositories/new?bulk=1": 2} {
		doc, err := html.Parse(strings.NewReader(pageBody(t, s, path)))
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		walkHTML(doc, func(n *html.Node) {
			name, _ := htmlAttr(n, "name")
			if n.Type != html.ElementNode || n.Data != "input" || name != "rescan_existing" {
				return
			}
			count++
			typ, _ := htmlAttr(n, "type")
			value, _ := htmlAttr(n, "value")
			_, checked := htmlAttr(n, "checked")
			if typ != "checkbox" || value != "1" || checked {
				t.Errorf("checkbox on %s: %+v", path, n.Attr)
			}
		})
		if count != want {
			t.Errorf("%s has %d checkboxes, want %d", path, count, want)
		}
	}
}
