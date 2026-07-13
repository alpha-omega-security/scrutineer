package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// seedFindingForAPI returns a finding plus the bearer token a skill running
// against the same repo would present. A second repo+scan provides a token
// that must NOT be allowed to act on the finding.
func seedFindingForAPI(t *testing.T, s *Server) (db.Finding, string, string) {
	t.Helper()
	repo, scan := seedRunningScan(t, s)
	skID := uint(1)
	s.DB.Model(&scan).Update("skill_id", &skID)
	scan.SkillID = &skID
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t",
		Severity: "High", Status: db.FindingNew}
	s.DB.Create(&f)

	other := db.Repository{URL: "https://example.com/other", Name: "other"}
	s.DB.Create(&other)
	otherScan := db.Scan{RepositoryID: other.ID, Kind: "skill", Status: db.ScanRunning,
		APIToken: "tok-other"}
	s.DB.Create(&otherScan)
	return f, scan.APIToken, otherScan.APIToken
}

func apiReq(t *testing.T, s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+token)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestAPIPatchFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok, otherTok := seedFindingForAPI(t, s)
	path := fmt.Sprintf("/api/findings/%d", f.ID)

	w := apiReq(t, s, "PATCH", path, tok,
		`{"fields":{"severity":"Critical","cve_id":"CVE-2026-12345"},"by":"disclose"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body)
	}
	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.Severity != "Critical" || got.CVEID != "CVE-2026-12345" {
		t.Errorf("finding = severity=%q cve=%q after patch", got.Severity, got.CVEID)
	}
	var hist []db.FindingHistory
	s.DB.Where("finding_id = ? AND source = ?", f.ID, db.SourceModel).Find(&hist)
	if len(hist) != 2 {
		t.Errorf("history rows = %d, want 2 with source=model_suggested", len(hist))
	}

	// validateFindingField surfaces as 422.
	w = apiReq(t, s, "PATCH", path, tok, `{"fields":{"ghsa_id":"not-a-ghsa"}}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid ghsa_id: status = %d, want 422", w.Code)
	}

	// Unknown field rejected.
	w = apiReq(t, s, "PATCH", path, tok, `{"fields":{"nope":"x"}}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("unknown field: status = %d, want 422", w.Code)
	}

	// Bad JSON.
	w = apiReq(t, s, "PATCH", path, tok, `not json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad json: status = %d, want 400", w.Code)
	}

	// A scan on a different repo cannot edit this finding.
	w = apiReq(t, s, "PATCH", path, otherTok, `{"fields":{"severity":"Low"}}`)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-repo: status = %d, want 403", w.Code)
	}

	// Missing finding.
	w = apiReq(t, s, "PATCH", "/api/findings/999999", tok, `{"fields":{"severity":"Low"}}`)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing finding: status = %d, want 404", w.Code)
	}
}

func TestAPIPatchFindingAtomicRollback(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok, _ := seedFindingForAPI(t, s)
	path := fmt.Sprintf("/api/findings/%d", f.ID)

	w := apiReq(t, s, "PATCH", path, tok,
		`{"fields":{"cve_id":"CVE-2026-12345","ghsa_id":"not-a-ghsa"},"by":"disclose"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body)
	}

	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.CVEID != "" || got.GHSAID != "" {
		t.Fatalf("finding fields committed despite failed patch: cve=%q ghsa=%q", got.CVEID, got.GHSAID)
	}
	var hist []db.FindingHistory
	s.DB.Where("finding_id = ?", f.ID).Find(&hist)
	if len(hist) != 0 {
		t.Fatalf("history rows = %d, want 0 after rollback: %+v", len(hist), hist)
	}
}

func TestAPIPatchFindingCVSSSyncsInsideTransaction(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok, _ := seedFindingForAPI(t, s)
	path := fmt.Sprintf("/api/findings/%d", f.ID)
	const vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	w := apiReq(t, s, "PATCH", path, tok,
		`{"fields":{"cvss_vector":"`+vec+`","severity":"Critical"},"by":"disclose"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body)
	}

	var got db.Finding
	s.DB.First(&got, f.ID)
	if got.CVSSVector != vec || got.CVSSScore != 9.8 || got.Severity != "Critical" {
		t.Fatalf("finding after patch: vector=%q score=%v severity=%q", got.CVSSVector, got.CVSSScore, got.Severity)
	}
	var hist []db.FindingHistory
	s.DB.Where("finding_id = ?", f.ID).Order("field").Find(&hist)
	fields := make([]string, 0, len(hist))
	for _, h := range hist {
		fields = append(fields, h.Field)
	}
	want := []string{"cvss_score", "cvss_vector", "severity"}
	if fmt.Sprint(fields) != fmt.Sprint(want) {
		t.Fatalf("history fields = %v, want %v", fields, want)
	}
}

// TestAPIFindingChildCollections covers the POST-then-GET round trip for the
// three sibling child collections (notes, communications, references). They
// share findingScoped and the same JSON-body shape, so a table keeps the
// per-collection differences (path, body, the field that proves the row
// landed) in one place.
func TestAPIFindingChildCollections(t *testing.T) {
	cases := []struct {
		name, suffix, createBody, listField, want string
	}{
		{
			name:       "notes",
			suffix:     "notes",
			createBody: `{"body":"triaged: real bug","by":"disclose"}`,
			listField:  "Body", want: "triaged: real bug",
		},
		{
			name:       "communications",
			suffix:     "communications",
			createBody: `{"channel":"email","direction":"outbound","actor":"alice","body":"sent disclosure","at":"2026-06-01T09:00:00Z"}`,
			listField:  "Channel", want: "email",
		},
		{
			name:       "references",
			suffix:     "references",
			createBody: `{"url":"https://example.com/advisory","tags":"advisory","summary":"upstream advisory"}`,
			listField:  "URL", want: "https://example.com/advisory",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			f, tok, otherTok := seedFindingForAPI(t, s)
			path := fmt.Sprintf("/api/findings/%d/%s", f.ID, tc.suffix)

			w := apiReq(t, s, "POST", path, tok, tc.createBody)
			if w.Code != http.StatusCreated {
				t.Fatalf("create status = %d, want 201; body=%s", w.Code, w.Body)
			}

			if w := apiReq(t, s, "POST", path, tok, `not json`); w.Code != http.StatusBadRequest {
				t.Errorf("bad json: status = %d, want 400", w.Code)
			}

			w = apiReq(t, s, "GET", path, tok, "")
			if w.Code != http.StatusOK {
				t.Fatalf("list status = %d", w.Code)
			}
			var rows []map[string]any
			_ = json.NewDecoder(w.Body).Decode(&rows)
			if len(rows) != 1 || rows[0][tc.listField] != tc.want {
				t.Errorf("list = %+v, want 1 row with %s=%q", rows, tc.listField, tc.want)
			}

			if w := apiReq(t, s, "GET", path, otherTok, ""); w.Code != http.StatusForbidden {
				t.Errorf("cross-repo list: status = %d, want 403", w.Code)
			}
			if w := apiReq(t, s, "GET", fmt.Sprintf("/api/findings/999999/%s", tc.suffix), tok, ""); w.Code != http.StatusNotFound {
				t.Errorf("missing finding: status = %d, want 404", w.Code)
			}
		})
	}
}

// The 422 paths differ per collection (notes reject empty body, references
// reject empty url, communications accept anything), so they get their own
// targeted checks.
func TestAPIFindingChildCollections_validation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok, _ := seedFindingForAPI(t, s)

	if w := apiReq(t, s, "POST", fmt.Sprintf("/api/findings/%d/notes", f.ID), tok, `{"body":"  "}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty note body: status = %d, want 422", w.Code)
	}
	if w := apiReq(t, s, "POST", fmt.Sprintf("/api/findings/%d/references", f.ID), tok, `{"url":""}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty reference url: status = %d, want 422", w.Code)
	}
}

func TestAPISetFindingLabels(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok, _ := seedFindingForAPI(t, s)
	path := fmt.Sprintf("/api/findings/%d/labels", f.ID)

	w := apiReq(t, s, "PUT", path, tok, `{"labels":["wontfix","needs-info"]}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body)
	}
	var got db.Finding
	s.DB.Preload("Labels").First(&got, f.ID)
	if len(got.Labels) != 2 {
		t.Errorf("labels = %+v, want 2", got.Labels)
	}

	// Clearing.
	w = apiReq(t, s, "PUT", path, tok, `{"labels":[]}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("clear status = %d", w.Code)
	}
	s.DB.Preload("Labels").First(&got, f.ID)
	if len(got.Labels) != 0 {
		t.Errorf("labels after clear = %+v, want 0", got.Labels)
	}

	if w := apiReq(t, s, "PUT", path, tok, `not json`); w.Code != http.StatusBadRequest {
		t.Errorf("bad json: status = %d, want 400", w.Code)
	}
}

func TestAPIListFindingHistory(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok, _ := seedFindingForAPI(t, s)
	if err := db.WriteFindingField(s.DB, f.ID, "severity", "Critical", db.SourceAnalyst, ""); err != nil {
		t.Fatalf("seed history: %v", err)
	}

	w := apiReq(t, s, "GET", fmt.Sprintf("/api/findings/%d/history", f.ID), tok, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var rows []map[string]any
	_ = json.NewDecoder(w.Body).Decode(&rows)
	if len(rows) != 1 || rows[0]["Field"] != "severity" {
		t.Errorf("history = %+v, want 1 severity row", rows)
	}
}

func TestSourceFromRequest(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, scan := seedRunningScan(t, s)

	mk := func(tok string) *http.Request {
		r := httptest.NewRequest("GET", "/api/findings/1", nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}

	// Scan without a SkillID -> analyst.
	if got := sourceForToken(t, s, mk(scan.APIToken)); got != db.SourceAnalyst {
		t.Errorf("no-skill scan source = %q, want analyst", got)
	}

	// With a SkillID -> model_suggested.
	skID := uint(1)
	s.DB.Model(&scan).Update("skill_id", &skID)
	if got := sourceForToken(t, s, mk(scan.APIToken)); got != db.SourceModel {
		t.Errorf("skill scan source = %q, want model_suggested", got)
	}
}

// sourceForToken routes a request through the API auth middleware so the
// scan context is populated, then reports what sourceFromRequest sees.
func sourceForToken(t *testing.T, s *Server, r *http.Request) db.FindingSource {
	t.Helper()
	var got db.FindingSource
	h := s.apiAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = sourceFromRequest(r)
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	return got
}
