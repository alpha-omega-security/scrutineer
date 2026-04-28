package web

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/git-pkgs/sbom"

	"scrutineer/internal/db"
)

const cdxFixture = `{
  "bomFormat":"CycloneDX","specVersion":"1.5",
  "metadata":{"component":{"type":"application","name":"demo","version":"1.0.0"}},
  "components":[
    {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21",
     "licenses":[{"license":{"id":"MIT"}}]},
    {"type":"library","name":"nopurl","version":"1.0.0"}
  ]
}`

func multipartReq(t *testing.T, path, field, filename, content string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	_ = mw.Close()
	r := httptest.NewRequest("POST", path, &buf)
	r.Host = testHost
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

func TestSBOMUpload_parsesAndStores(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, multipartReq(t, "/sboms", "file", "demo.cdx.json", cdxFixture))
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.HasPrefix(w.Header().Get("HX-Redirect"), "/sboms/") {
		t.Errorf("missing HX-Redirect, got %q", w.Header().Get("HX-Redirect"))
	}

	var up db.SBOMUpload
	if err := s.DB.Preload("Packages").First(&up).Error; err != nil {
		t.Fatalf("upload not created: %v", err)
	}
	if up.Name != "demo" {
		t.Errorf("Name = %q, want demo (from metadata.component)", up.Name)
	}
	if up.Format != "cyclonedx" || up.SpecVersion != "1.5" {
		t.Errorf("format = %s/%s", up.Format, up.SpecVersion)
	}
	if up.PackageCount != 2 || len(up.Packages) != 2 {
		t.Fatalf("packages = %d (%d rows)", up.PackageCount, len(up.Packages))
	}
	var lodash db.SBOMPackage
	for _, p := range up.Packages {
		if p.Name == "lodash" {
			lodash = p
		}
	}
	if lodash.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("lodash purl = %q", lodash.PURL)
	}
	if lodash.Ecosystem != "npm" {
		t.Errorf("lodash ecosystem = %q", lodash.Ecosystem)
	}
	if lodash.License != "MIT" {
		t.Errorf("lodash license = %q", lodash.License)
	}
}

func TestSBOMUpload_rejectsUnrecognized(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, multipartReq(t, "/sboms", "file", "x.json", `{"foo":1}`))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d, want 422: %s", w.Code, w.Body)
	}
}

func TestSBOMResolve_linksRepoAndEnqueuesTriage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// Stub the ecosyste.ms lookup so lodash resolves to a fake repo URL.
	s.resolvePURL = func(_ context.Context, purl string) string {
		if strings.Contains(purl, "lodash") {
			return "https://github.com/lodash/lodash"
		}
		return ""
	}
	triage := db.Skill{Name: defaultSkillName, Body: "b", Active: true}
	s.DB.Create(&triage)

	up := db.SBOMUpload{Name: "demo", Packages: []db.SBOMPackage{
		{Name: "lodash", PURL: "pkg:npm/lodash@4.17.21"},
		{Name: "nopurl"},
		{Name: "noresolve", PURL: "pkg:npm/ghost@1.0.0"},
	}}
	s.DB.Create(&up)

	s.resolveSBOMPackages(up.ID)

	var pkgs []db.SBOMPackage
	s.DB.Where("sbom_upload_id = ?", up.ID).Order("id").Find(&pkgs)

	if pkgs[0].RepositoryID == nil {
		t.Fatalf("lodash not linked: %+v", pkgs[0])
	}
	var repo db.Repository
	s.DB.First(&repo, *pkgs[0].RepositoryID)
	if repo.URL != "https://github.com/lodash/lodash.git" {
		t.Errorf("repo url = %q", repo.URL)
	}
	var scans int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).Count(&scans)
	if scans != 1 {
		t.Errorf("triage scan not enqueued, scans = %d", scans)
	}

	if pkgs[1].ResolveError != "no purl" {
		t.Errorf("nopurl error = %q", pkgs[1].ResolveError)
	}
	if pkgs[2].ResolveError != "no repository_url for purl" {
		t.Errorf("noresolve error = %q", pkgs[2].ResolveError)
	}
}

func TestSBOMShow_aggregatesFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rce-in-r", Severity: "High", Status: db.FindingTriaged})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "noise", Severity: "Low", Status: db.FindingRejected})

	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	s.DB.Create(&other)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: other.ID, Title: "unrelated", Severity: "High"})

	up := db.SBOMUpload{Name: "demo", PackageCount: 1, Packages: []db.SBOMPackage{
		{Name: "r-pkg", PURL: "pkg:npm/r", RepositoryID: &repo.ID},
	}}
	s.DB.Create(&up)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/sboms/%d", up.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "rce-in-r") {
		t.Errorf("finding from linked repo not shown")
	}
	if strings.Contains(body, "noise") {
		t.Errorf("rejected finding should be hidden")
	}
	if strings.Contains(body, "unrelated") {
		t.Errorf("finding from unlinked repo should not be shown")
	}
	if !strings.Contains(body, "triaged") {
		t.Errorf("finding status badge not rendered")
	}
}

func TestSBOMShow_listsAdvisories(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/adv", Name: "adv"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Advisory{RepositoryID: repo.ID, Title: "CVE-2026-9999 prototype pollution",
		Severity: "High", CVSSScore: 7.5, URL: "https://osv.dev/CVE-2026-9999"})
	withdrawn := time.Now()
	s.DB.Create(&db.Advisory{RepositoryID: repo.ID, Title: "withdrawn-one", WithdrawnAt: &withdrawn})

	up := db.SBOMUpload{Name: "demo", PackageCount: 1, Packages: []db.SBOMPackage{
		{Name: "adv-pkg", PURL: "pkg:npm/adv", RepositoryID: &repo.ID},
	}}
	s.DB.Create(&up)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/sboms/%d", up.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "CVE-2026-9999 prototype pollution") {
		t.Errorf("advisory not listed")
	}
	if strings.Contains(body, "withdrawn-one") {
		t.Errorf("withdrawn advisory should be hidden")
	}
}

func TestSBOMList_renders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.SBOMUpload{Name: "first.cdx", Format: "cyclonedx", PackageCount: 5})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/sboms"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "first.cdx") {
		t.Errorf("upload not listed")
	}
}

func TestClassifyScope(t *testing.T) {
	t.Run("cyclonedx graph", func(t *testing.T) {
		// root → a, b; a → c. Root is identified by having no inbound edge.
		doc := &sbom.SBOM{Relationships: []sbom.Relationship{
			{SourceID: "root", TargetID: "a", Type: "DEPENDS_ON"},
			{SourceID: "root", TargetID: "b", Type: "DEPENDS_ON"},
			{SourceID: "a", TargetID: "c", Type: "DEPENDS_ON"},
		}}
		got := classifyScope(doc)
		want := map[string]string{"a": scopeDirect, "b": scopeDirect, "c": scopeTransitive}
		for id, s := range want {
			if got[id] != s {
				t.Errorf("%s = %q, want %q", id, got[id], s)
			}
		}
	})
	t.Run("spdx with DESCRIBES", func(t *testing.T) {
		// DOCUMENT --DESCRIBES--> root; root --DEPENDS_ON--> a; a --DEPENDS_ON--> b.
		doc := &sbom.SBOM{Relationships: []sbom.Relationship{
			{SourceID: "SPDXRef-DOCUMENT", TargetID: "root", Type: "DESCRIBES"},
			{SourceID: "root", TargetID: "a", Type: "DEPENDS_ON"},
			{SourceID: "a", TargetID: "b", Type: "DEPENDS_ON"},
		}}
		got := classifyScope(doc)
		if got["a"] != scopeDirect || got["b"] != scopeTransitive {
			t.Errorf("got %v", got)
		}
	})
	t.Run("direct wins over transitive", func(t *testing.T) {
		// root → a, a → b, root → b. b should still be direct.
		doc := &sbom.SBOM{Relationships: []sbom.Relationship{
			{SourceID: "root", TargetID: "a", Type: "DEPENDS_ON"},
			{SourceID: "a", TargetID: "b", Type: "DEPENDS_ON"},
			{SourceID: "root", TargetID: "b", Type: "DEPENDS_ON"},
		}}
		if got := classifyScope(doc); got["b"] != scopeDirect {
			t.Errorf("b = %q, want direct", got["b"])
		}
	})
	t.Run("no graph", func(t *testing.T) {
		if got := classifyScope(&sbom.SBOM{}); got != nil {
			t.Errorf("expected nil for empty relationships, got %v", got)
		}
	})
}

func TestSBOMShow_scopeFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repoA := db.Repository{URL: "https://example.com/direct-repo", Name: "direct-repo"}
	s.DB.Create(&repoA)
	repoB := db.Repository{URL: "https://example.com/trans-repo", Name: "trans-repo"}
	s.DB.Create(&repoB)
	scan := db.Scan{RepositoryID: repoA.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repoA.ID, Title: "direct-dep-finding", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repoB.ID, Title: "trans-dep-finding", Severity: "High"})

	up := db.SBOMUpload{Name: "demo", PackageCount: 2, Packages: []db.SBOMPackage{
		{Name: "pkg-direct", Scope: scopeDirect, RepositoryID: &repoA.ID},
		{Name: "pkg-trans", Scope: scopeTransitive, RepositoryID: &repoB.ID},
	}}
	s.DB.Create(&up)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/sboms/%d?scope=direct", up.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "pkg-direct") || strings.Contains(body, "pkg-trans") {
		t.Errorf("scope filter not applied to packages table")
	}
	if !strings.Contains(body, "direct-dep-finding") {
		t.Errorf("findings from direct-dep repo missing")
	}
	if strings.Contains(body, "trans-dep-finding") {
		t.Errorf("scope filter should also scope findings")
	}
}

func TestPURLType(t *testing.T) {
	tests := []struct{ in, want string }{
		{"pkg:npm/lodash@4.17.21", "npm"},
		{"pkg:golang/github.com/gorilla/mux@v1.8.0", "golang"},
		{"pkg:gem/rails", "gem"},
		{"", ""},
		{"not-a-purl", ""},
	}
	for _, tt := range tests {
		if got := purlType(tt.in); got != tt.want {
			t.Errorf("purlType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
