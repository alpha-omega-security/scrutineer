package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestAuditPage_listsQueueAndAgreementRate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	low := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "audit me", Severity: "Low"}
	s.DB.Create(&low)
	if _, err := db.AddFindingReview(s.DB, low.ID, "false_positive", "fixture", "false_positive", "andrew"); err != nil {
		t.Fatal(err)
	}
	other := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "still to review", Severity: "Low"}
	s.DB.Create(&other)

	r := httptest.NewRequest(http.MethodGet, "/audit", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "still to review") {
		t.Errorf("body missing un-reviewed queue row: %q", body)
	}
	if strings.Contains(body, "audit me") {
		t.Errorf("body included already-reviewed finding")
	}
	if !strings.Contains(body, "100%") {
		t.Errorf("body missing 100%% agreement (1 review, agreed): %q", body)
	}
}

func TestApiAddFindingReview_snapshotsLatestRevalidate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	authScan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, APIToken: "T1"}
	s.DB.Create(&authScan)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: "High"}
	s.DB.Create(&f)
	if _, err := db.AddFindingNote(s.DB, f.ID, "revalidate: false_positive\n\ntest fixture", "revalidate"); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost,
		"/api/findings/"+strconv.Itoa(int(f.ID))+"/reviews",
		strings.NewReader(`{"verdict":"true_positive","reason":"actually exploitable","reviewer":"andrew"}`))
	r.Host = "127.0.0.1:8080"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer T1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var rev db.FindingReview
	if err := json.Unmarshal(w.Body.Bytes(), &rev); err != nil {
		t.Fatal(err)
	}
	if rev.AutomatedOutcome != "false_positive" {
		t.Errorf("automated_outcome = %q, want false_positive (snapshotted from latest revalidate note)", rev.AutomatedOutcome)
	}
	if rev.Verdict != "true_positive" {
		t.Errorf("verdict = %q, want true_positive", rev.Verdict)
	}
}

func TestApiAuditMetrics_returnsAggregate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	authScan := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, APIToken: "T2"}
	s.DB.Create(&authScan)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	mk := func(id string) db.Finding {
		f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: id, Severity: "Low"}
		s.DB.Create(&f)
		return f
	}
	a, b := mk("F1"), mk("F2")
	_, _ = db.AddFindingReview(s.DB, a.ID, "false_positive", "", "false_positive", "andrew")
	_, _ = db.AddFindingReview(s.DB, b.ID, "true_positive", "", "false_positive", "andrew")

	r := httptest.NewRequest(http.MethodGet, "/api/audit/metrics", nil)
	r.Host = "127.0.0.1:8080"
	r.Header.Set("Authorization", "Bearer T2")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var m db.AuditMetrics
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.TotalReviews != 2 || m.WithAutomatedOutcome != 2 || m.Agreements != 1 {
		t.Errorf("metrics = %+v, want total=2 auto=2 agree=1", m)
	}
}
