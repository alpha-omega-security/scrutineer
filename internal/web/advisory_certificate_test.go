package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"scrutineer/internal/db"
)

func getCertificate(t *testing.T, s *Server, advisoryID uint) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories/"+strconv.FormatUint(uint64(advisoryID), 10)+"/certificate.json"))
	return w
}

func seedAdvisory(t *testing.T, s *Server, repoID uint) db.Advisory {
	t.Helper()
	adv := db.Advisory{RepositoryID: repoID, UUID: "GHSA-abc", URL: "https://x", Title: "boom", Severity: "High", CVSSScore: 7.5}
	s.DB.Create(&adv)
	return adv
}

func TestAdvisoryCertificate_servedForFixedVerdict(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r", FullName: "o/r"}
	s.DB.Create(&repo)
	adv := seedAdvisory(t, s, repo.ID)
	s.DB.Create(&db.AdvisoryAudit{
		RepositoryID: repo.ID, AdvisoryUUID: adv.UUID, ScanID: 42,
		Status: "fixed", Evidence: "Repro fails at HEAD.", Commit: "deadbeef",
	})

	w := getCertificate(t, s, adv.ID)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}

	var cert advisoryCertificate
	if err := json.Unmarshal(w.Body.Bytes(), &cert); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cert.Advisory.UUID != adv.UUID || cert.Audit.Status != "fixed" {
		t.Errorf("cert = %+v", cert)
	}
	if cert.Audit.Evidence != "Repro fails at HEAD." || cert.Audit.Commit != "deadbeef" {
		t.Errorf("audit body = %+v", cert.Audit)
	}
	if cert.Repository.FullName != "o/r" {
		t.Errorf("repo = %+v", cert.Repository)
	}
}

func TestAdvisoryCertificate_absentWhenNotFixed(t *testing.T) {
	cases := []struct {
		name   string
		status string // empty means "no audit at all"
	}{
		{"no audit", ""},
		{"bypass verdict", "bypass"},
		{"regressed verdict", "regressed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := db.Repository{URL: "https://example.com/r", Name: "r"}
			s.DB.Create(&repo)
			adv := seedAdvisory(t, s, repo.ID)
			if tc.status != "" {
				s.DB.Create(&db.AdvisoryAudit{
					RepositoryID: repo.ID, AdvisoryUUID: adv.UUID,
					Status: tc.status, Evidence: "e",
				})
			}

			if w := getCertificate(t, s, adv.ID); w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", w.Code)
			}
		})
	}
}

func TestLatestAdvisoryAuditStatuses_newestWinsPerAdvisory(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	adv := seedAdvisory(t, s, repo.ID)
	// Two runs for the same advisory: the older said fixed, the newer bypass.
	s.DB.Create(&db.AdvisoryAudit{RepositoryID: repo.ID, AdvisoryUUID: adv.UUID, Status: "fixed", Evidence: "held"})
	s.DB.Create(&db.AdvisoryAudit{RepositoryID: repo.ID, AdvisoryUUID: adv.UUID, Status: "bypass", Evidence: "broke"})

	got := s.latestAdvisoryAuditStatuses([]db.Advisory{adv})
	if got[adv.ID] != "bypass" {
		t.Errorf("badge status = %q, want bypass (newest verdict wins)", got[adv.ID])
	}
}

func TestAdvisoryCertificate_usesLatestVerdict(t *testing.T) {
	// An older fixed verdict must not resurrect a certificate once a newer
	// run found a regression.
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	adv := seedAdvisory(t, s, repo.ID)
	s.DB.Create(&db.AdvisoryAudit{RepositoryID: repo.ID, AdvisoryUUID: adv.UUID, Status: "fixed", Evidence: "held"})
	s.DB.Create(&db.AdvisoryAudit{RepositoryID: repo.ID, AdvisoryUUID: adv.UUID, Status: "regressed", Evidence: "reopened"})

	if w := getCertificate(t, s, adv.ID); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (latest verdict is regressed)", w.Code)
	}
}
