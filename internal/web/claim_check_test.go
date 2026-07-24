package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
	"scrutineer/internal/worker"
)

func postClaimCheck(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/claim-check", strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func seedClaimCheckFinding(t *testing.T, s *Server, status db.FindingLifecycle) string {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/acme/lib", Name: "lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Title: "sqli", Status: status,
		CWE: "CWE-89", Location: "src/db.go:42", SubPath: "backend",
	})
	return interchange.FindingHash(s.FederationSalt, repo.URL, "backend", "src/db.go:42", "CWE-89")
}

func TestClaimCheck_matchReturnsContact(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = "s3cret"
	s.FederationContact = "security@example.com"
	hash := seedClaimCheckFinding(t, s, db.FindingTriaged)

	w := postClaimCheck(t, s, `{"hash":"`+hash+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp struct {
		Match   bool   `json:"match"`
		Contact string `json:"contact"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Match || resp.Contact != "security@example.com" {
		t.Fatalf("expected match with contact, got %s", w.Body)
	}
}

func TestClaimCheck_noMatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = "s3cret"
	s.FederationContact = "security@example.com"
	seedClaimCheckFinding(t, s, db.FindingTriaged)

	w := postClaimCheck(t, s, `{"hash":"`+strings.Repeat("ab", 32)+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := strings.TrimSpace(w.Body.String())
	if body != `{"match":false}` {
		t.Fatalf("a miss must reveal nothing but match:false, got %s", body)
	}
}

func TestClaimCheck_ignoresRejectedAndDuplicate(t *testing.T) {
	for _, status := range []db.FindingLifecycle{db.FindingRejected, db.FindingDuplicate} {
		t.Run(string(status), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.FederationSalt = "s3cret"
			hash := seedClaimCheckFinding(t, s, status)

			w := postClaimCheck(t, s, `{"hash":"`+hash+`"}`)
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), `"match":false`) {
				t.Fatalf("%s finding must not be claimed, got %s", status, w.Body)
			}
		})
	}
}

func TestClaimCheck_disabledWithoutSalt(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	hash := seedClaimCheckFinding(t, s, db.FindingTriaged)

	if w := postClaimCheck(t, s, `{"hash":"`+hash+`"}`); w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when federation_salt is unset, got %d: %s", w.Code, w.Body)
	}
}

func TestClaimCheck_badRequests(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.FederationSalt = "s3cret"

	for name, body := range map[string]string{
		"invalid json":  `{`,
		"missing hash":  `{}`,
		"short hash":    `{"hash":"abc123"}`,
		"non-hex hash":  `{"hash":"` + strings.Repeat("zz", 32) + `"}`,
		"oversize body": `{"hash":"` + strings.Repeat("a", 1<<20) + `"}`,
	} {
		if w := postClaimCheck(t, s, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", name, w.Code, w.Body)
		}
	}
}
