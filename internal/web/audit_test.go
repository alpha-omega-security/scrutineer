package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// seedAuditFixture creates a repo with a running scan (for the bearer token)
// and a Low-severity finding so it lands in the audit queue.
func seedAuditFixture(t *testing.T, s *Server) (db.Finding, string) {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/audit", Name: "audit"}
	s.DB.Create(&repo)
	auth := db.Scan{RepositoryID: repo.ID, Status: db.ScanRunning, APIToken: "tok-audit"}
	s.DB.Create(&auth)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "low-sev", Severity: "Low"}
	s.DB.Create(&f)
	return f, auth.APIToken
}

// decodeJSON unmarshals a recorded response body into out, failing the test
// with the body on error so a non-JSON response (e.g. an error page) shows up
// as the real failure rather than a confusing downstream assertion.
func decodeJSON(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("decode response: %v; status=%d body=%s", err, w.Code, w.Body)
	}
}

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

	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/metrics", nil)
	r.Host = "127.0.0.1:8080"
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

func TestApiAddFindingReview_validation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok := seedAuditFixture(t, s)
	path := "/api/findings/" + strconv.Itoa(int(f.ID)) + "/reviews"

	if w := apiReq(t, s, "POST", path, tok, `{"verdict":"not-a-verdict"}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid verdict: status = %d, want 422", w.Code)
	}
	if w := apiReq(t, s, "POST", path, tok, `not json`); w.Code != http.StatusBadRequest {
		t.Errorf("bad json: status = %d, want 400", w.Code)
	}

	// Explicit automated_outcome wins over the revalidate snapshot.
	if _, err := db.AddFindingNote(s.DB, f.ID, "revalidate: false_positive\n\nfixture", "revalidate"); err != nil {
		t.Fatalf("seed revalidate note: %v", err)
	}
	w := apiReq(t, s, "POST", path, tok, `{"verdict":"true_positive","automated_outcome":"uncertain"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	var rev db.FindingReview
	decodeJSON(t, w, &rev)
	if rev.AutomatedOutcome != "uncertain" {
		t.Errorf("automated_outcome = %q, want explicit value to win over snapshot", rev.AutomatedOutcome)
	}
}

func TestApiListFindingReviews(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok := seedAuditFixture(t, s)
	if _, err := db.AddFindingReview(s.DB, f.ID, "false_positive", "noise", "", "andrew"); err != nil {
		t.Fatal(err)
	}

	w := apiReq(t, s, "GET", "/api/findings/"+strconv.Itoa(int(f.ID))+"/reviews", tok, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	var rows []db.FindingReview
	decodeJSON(t, w, &rows)
	if len(rows) != 1 || rows[0].Verdict != "false_positive" {
		t.Errorf("reviews = %+v, want 1 false_positive row", rows)
	}
}

// The audit endpoints return findings across every repository on the
// instance, so a per-repo scan token must not reach them (#454). They are
// on the host-only /api/v1 mux, which rejects non-localhost Host headers,
// and the per-scan /api mux no longer routes them at all.
func TestApiAudit_notReachableFromScanContainer(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, tok := seedAuditFixture(t, s)

	// The host-only mux rejects the Host header a runner container uses.
	for _, path := range []string{"/api/v1/audit/queue", "/api/v1/audit/metrics"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "host.docker.internal:8080"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s with non-localhost Host: status = %d, want 403", path, w.Code)
		}
	}

	// The per-scan bearer API no longer routes these at all, so a valid
	// scan token gets a 404 rather than instance-wide findings.
	for _, path := range []string{"/api/audit/queue", "/api/audit/metrics"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s on scan-token mux: status = %d, want 404", path, w.Code)
		}
	}
}

func TestApiAuditQueue(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok := seedAuditFixture(t, s)

	// A High-severity finding with no other audit signal does not qualify.
	high := db.Finding{ScanID: f.ScanID, RepositoryID: f.RepositoryID, Title: "high", Severity: "High"}
	s.DB.Create(&high)
	// A High-severity finding marked false_positive by revalidate qualifies.
	revalidated := db.Finding{ScanID: f.ScanID, RepositoryID: f.RepositoryID, Title: "fp",
		Severity: "High", LastRevalidateVerdict: "false_positive"}
	s.DB.Create(&revalidated)
	// A Low finding that already has a review is excluded.
	reviewed := db.Finding{ScanID: f.ScanID, RepositoryID: f.RepositoryID, Title: "done", Severity: "Low"}
	s.DB.Create(&reviewed)
	if _, err := db.AddFindingReview(s.DB, reviewed.ID, "false_positive", "", "", ""); err != nil {
		t.Fatalf("seed review: %v", err)
	}

	w := apiReq(t, s, "GET", "/api/v1/audit/queue", tok, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	var rows []db.Finding
	decodeJSON(t, w, &rows)
	ids := map[uint]bool{}
	for _, r := range rows {
		ids[r.ID] = true
	}
	if !ids[f.ID] || !ids[revalidated.ID] {
		t.Errorf("queue missing eligible findings: got ids=%v", ids)
	}
	if ids[high.ID] {
		t.Errorf("queue included High-severity finding with no audit signal")
	}
	if ids[reviewed.ID] {
		t.Errorf("queue included already-reviewed finding")
	}

	// limit applies.
	w = apiReq(t, s, "GET", "/api/v1/audit/queue?limit=1", tok, "")
	if w.Code != http.StatusOK {
		t.Fatalf("limit=1 status = %d; body=%s", w.Code, w.Body)
	}
	rows = nil
	decodeJSON(t, w, &rows)
	if len(rows) != 1 {
		t.Errorf("limit=1 returned %d rows", len(rows))
	}

	// since is wired through. SQLite stores created_at as text with the local
	// TZ offset and compares it lexically against the bound parameter, so
	// sub-day cutoffs across timezones are unreliable; use date-level
	// boundaries here so the comparison holds regardless of encoding.
	countAt := func(since string) int {
		w := apiReq(t, s, "GET", "/api/v1/audit/queue?since="+url.QueryEscape(since), tok, "")
		if w.Code != http.StatusOK {
			t.Fatalf("since=%s status = %d; body=%s", since, w.Code, w.Body)
		}
		var got []db.Finding
		decodeJSON(t, w, &got)
		return len(got)
	}
	if n := countAt("2099-01-01T00:00:00Z"); n != 0 {
		t.Errorf("since=2099 returned %d rows, want 0", n)
	}
	if n := countAt("2000-01-01T00:00:00Z"); n != 2 {
		t.Errorf("since=2000 returned %d rows, want 2", n)
	}
}

func TestFindingReviewCreate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, _ := seedAuditFixture(t, s)
	if _, err := db.AddFindingNote(s.DB, f.ID, "revalidate: already_fixed\n\nfixture", "revalidate"); err != nil {
		t.Fatalf("seed revalidate note: %v", err)
	}
	path := "/findings/" + strconv.Itoa(int(f.ID)) + "/reviews"

	w := postForm(t, s, path, url.Values{
		"verdict":  {"true_positive"},
		"reason":   {"reproduced locally"},
		"reviewer": {"andrew"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/findings/"+strconv.Itoa(int(f.ID)) {
		t.Errorf("Location = %q", loc)
	}
	var rows []db.FindingReview
	s.DB.Where("finding_id = ?", f.ID).Find(&rows)
	if len(rows) != 1 || rows[0].Verdict != "true_positive" || rows[0].AutomatedOutcome != "already_fixed" {
		t.Errorf("review = %+v, want true_positive snapshotting already_fixed", rows)
	}

	// Explicit automated_outcome wins over the snapshot.
	w = postForm(t, s, path, url.Values{
		"verdict":           {"uncertain"},
		"automated_outcome": {"false_positive"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("explicit-outcome status = %d", w.Code)
	}
	s.DB.Where("finding_id = ?", f.ID).Order("id").Find(&rows)
	if len(rows) != 2 || rows[1].AutomatedOutcome != "false_positive" {
		t.Errorf("second review = %+v, want explicit automated_outcome", rows)
	}

	if w := postForm(t, s, path, url.Values{"verdict": {"not-a-verdict"}}); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid verdict: status = %d, want 422", w.Code)
	}
	if w := postForm(t, s, "/findings/999999/reviews", url.Values{"verdict": {"uncertain"}}); w.Code != http.StatusNotFound {
		t.Errorf("missing finding: status = %d, want 404", w.Code)
	}
}

func TestAuditQueueOptionsFromQuery(t *testing.T) {
	at := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		query     string
		wantLimit int
		wantSince time.Time
	}{
		{"", 0, time.Time{}},
		{"?limit=10", 10, time.Time{}},
		{"?limit=999999", auditMaxLimit, time.Time{}},
		{"?limit=0", 0, time.Time{}},
		{"?limit=-5", 0, time.Time{}},
		{"?limit=notanumber", 0, time.Time{}},
		{"?since=" + at.Format(time.RFC3339), 0, at},
		{"?since=not-a-date", 0, time.Time{}},
		{"?limit=3&since=" + at.Format(time.RFC3339), 3, at},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/api/v1/audit/queue"+tc.query, nil)
		got := auditQueueOptionsFromQuery(r)
		if got.Limit != tc.wantLimit {
			t.Errorf("%q: Limit = %d, want %d", tc.query, got.Limit, tc.wantLimit)
		}
		if !got.Since.Equal(tc.wantSince) {
			t.Errorf("%q: Since = %v, want %v", tc.query, got.Since, tc.wantSince)
		}
	}
}
