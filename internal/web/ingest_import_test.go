package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func postImport(t *testing.T, s *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestHandleImportSARIF(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	body, err := os.ReadFile("../ingest/testdata/codeql.sarif")
	if err != nil {
		t.Fatal(err)
	}
	w := postImport(t, s, "/api/v1/import", string(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp struct {
		Format  string `json:"format"`
		Results []struct {
			RepositoryID uint   `json:"repository_id"`
			ScanID       uint   `json:"scan_id"`
			Tool         string `json:"tool"`
			Created      int    `json:"created"`
			Observed     int    `json:"observed"`
			FindingIDs   []uint `json:"finding_ids"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Format != "sarif" {
		t.Errorf("format = %q", resp.Format)
	}
	if len(resp.Results) != 1 || resp.Results[0].Created != 2 {
		t.Fatalf("results = %+v", resp.Results)
	}
	res := resp.Results[0]
	if res.Tool != "CodeQL" {
		t.Errorf("tool = %q", res.Tool)
	}

	var repo db.Repository
	if err := s.DB.First(&repo, res.RepositoryID).Error; err != nil {
		t.Fatalf("repo not created: %v", err)
	}
	if repo.URL != "https://github.com/example/widget" {
		t.Errorf("repo.URL = %q (want .git suffix stripped)", repo.URL)
	}

	var scan db.Scan
	s.DB.First(&scan, res.ScanID)
	if scan.Kind != "import" || scan.SkillName != "CodeQL" || scan.Status != db.ScanDone {
		t.Errorf("scan = kind=%q skill=%q status=%q", scan.Kind, scan.SkillName, scan.Status)
	}
	if scan.Commit != "abc123" {
		t.Errorf("scan.Commit = %q", scan.Commit)
	}

	var findings []db.Finding
	s.DB.Where("scan_id = ?", scan.ID).Order("id").Find(&findings)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].ImportedFrom != "CodeQL" {
		t.Errorf("ImportedFrom = %q", findings[0].ImportedFrom)
	}
	if findings[0].CWE != "CWE-79" || findings[0].Severity != "High" {
		t.Errorf("finding[0] = cwe=%q sev=%q", findings[0].CWE, findings[0].Severity)
	}
	if findings[0].Confidence != "high" {
		t.Errorf("finding[0].Confidence = %q (want high from precision)", findings[0].Confidence)
	}
	if findings[0].Fingerprint == "" {
		t.Error("finding[0].Fingerprint empty")
	}
	if findings[1].Confidence != "medium" {
		t.Errorf("finding[1].Confidence = %q", findings[1].Confidence)
	}
}

func TestHandleImportDedupesOnReimport(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	body, _ := os.ReadFile("../ingest/testdata/codeql.sarif")

	w1 := postImport(t, s, "/api/v1/import", string(body))
	if w1.Code != http.StatusCreated {
		t.Fatalf("first import: status = %d", w1.Code)
	}
	w2 := postImport(t, s, "/api/v1/import", string(body))
	if w2.Code != http.StatusCreated {
		t.Fatalf("second import: status = %d, body = %s", w2.Code, w2.Body.String())
	}

	var n int64
	s.DB.Model(&db.Finding{}).Count(&n)
	if n != 2 {
		t.Fatalf("after two imports got %d findings, want 2 (deduped)", n)
	}
	var f db.Finding
	s.DB.Order("id").First(&f)
	if f.SeenCount != 2 {
		t.Errorf("SeenCount = %d, want 2", f.SeenCount)
	}

	var scans int64
	s.DB.Model(&db.Scan{}).Where("kind = ?", "import").Count(&scans)
	if scans != 2 {
		t.Errorf("import scans = %d, want 2", scans)
	}
}

func TestHandleImportRepoOverride(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	body := `{"findings":[{"title":"x","cwe":"CWE-1","location":"a.go:1"}]}`
	w := postImport(t, s, "/api/v1/import?repo=https://github.com/acme/thing", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var repo db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/acme/thing").First(&repo).Error; err != nil {
		t.Fatalf("repo not created: %v", err)
	}
	var f db.Finding
	s.DB.First(&f)
	if f.ImportedFrom != "manual" || f.Confidence != "low" {
		t.Errorf("finding = imported_from=%q confidence=%q", f.ImportedFrom, f.Confidence)
	}
}

func TestHandleImportRejectsNoRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := postImport(t, s, "/api/v1/import", `{"findings":[{"title":"x"}]}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "repository unknown") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestHandleImportRejectsUnknownFormatWithoutRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := postImport(t, s, "/api/v1/import", `{"hello":"world"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "ingest skill") {
		t.Errorf("body should hint at the ingest route, got %q", w.Body.String())
	}
}

func TestHandleImportRejectsUnknownFormatWithoutIngestSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := postImport(t, s, "/api/v1/import?repo=https://github.com/acme/widget", `{"hello":"world"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not available") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestHandleImportRoutesUnknownFormatToIngestSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	skill := db.Skill{
		Name:       "ingest",
		OutputFile: "report.json",
		OutputKind: "findings",
		Version:    1,
		Active:     true,
	}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}

	body := `weird scanner output, line 12 of main.go looks bad`
	w := postImport(t, s, "/api/v1/import?repo=https://github.com/acme/widget", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp struct {
		Format       string `json:"format"`
		RepositoryID uint   `json:"repository_id"`
		ScanID       uint   `json:"scan_id"`
		Skill        string `json:"skill"`
		Status       string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Format != "unrecognised" || resp.Skill != "ingest" || resp.Status != "queued" {
		t.Errorf("response = %+v", resp)
	}

	var scan db.Scan
	if err := s.DB.First(&scan, resp.ScanID).Error; err != nil {
		t.Fatal(err)
	}
	if scan.SkillName != "ingest" || scan.Kind != "skill" || scan.Status != db.ScanQueued {
		t.Errorf("scan = kind %q skill %q status %q", scan.Kind, scan.SkillName, scan.Status)
	}
	if string(scan.ImportPayload) != body {
		t.Errorf("payload = %q", string(scan.ImportPayload))
	}
	if scan.RepositoryID != resp.RepositoryID {
		t.Errorf("repository id = %d, want %d", scan.RepositoryID, resp.RepositoryID)
	}
}

func TestHandleImportRejectsOversizedBody(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	body := strings.Repeat("a", 17<<20)
	w := postImport(t, s, "/api/v1/import", body)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", w.Code)
	}
}
