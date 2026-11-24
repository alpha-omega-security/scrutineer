package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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
	asOperator(r)
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

func TestApiAddFindingReview_notReachableWithScanToken(t *testing.T) {
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
	r := httptest.NewRequest(http.MethodPost,
		"/api/findings/"+strconv.Itoa(int(f.ID))+"/reviews",
		strings.NewReader(`{"verdict":"true_positive","reason":"actually exploitable","reviewer":"andrew"}`))
	asOperator(r)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer T1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	// The GET reviews route still exists, so net/http reports 405 rather than
	// 404 for the removed POST route.
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405; body = %s", w.Code, w.Body.String())
	}
	var count int64
	s.DB.Model(&db.FindingReview{}).Where("finding_id = ?", f.ID).Count(&count)
	if count != 0 {
		t.Errorf("scan-token request created %d reviews, want 0", count)
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
	_, _ = db.AddFindingReview(s.DB, a.ID, "false_positive", "guarded", "false_positive", "andrew")
	_, _ = db.AddFindingReview(s.DB, b.ID, "true_positive", "", "false_positive", "andrew")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/metrics", nil)
	asOperator(r)
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

func TestApiListFindingReviews(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f, tok := seedAuditFixture(t, s)
	f.Commit = "reviewed-commit"
	f.Fingerprint = "reviewed-fingerprint"
	f.SubPath = "lib"
	f.Location = "parser.go:10"
	f.CWE = "CWE-20"
	if err := s.DB.Save(&f).Error; err != nil {
		t.Fatal(err)
	}
	review, err := db.AddFindingReview(s.DB, f.ID, "false_positive", "noise", "uncertain", "andrew")
	if err != nil {
		t.Fatal(err)
	}

	w := apiReq(t, s, "GET", "/api/findings/"+strconv.Itoa(int(f.ID))+"/reviews", tok, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	// Check wire keys directly: decoding back into the model can hide tag bugs.
	var rows []map[string]any
	decodeJSON(t, w, &rows)
	if len(rows) != 1 {
		t.Fatalf("reviews = %+v, want one row", rows)
	}
	want := map[string]any{
		"id": float64(review.ID), "finding_id": float64(f.ID),
		"verdict": "false_positive", "reason": "noise", "automated_outcome": "uncertain", "reviewer": "andrew",
		"source_scan_id": float64(f.ScanID), "source_commit": "reviewed-commit",
		"finding_fingerprint": "reviewed-fingerprint", "finding_path": "lib/parser.go", "cwe": "CWE-20",
		"created_at": review.CreatedAt.Format(time.RFC3339Nano),
	}
	if len(rows[0]) != len(want) {
		t.Errorf("unexpected response keys: %v", rows[0])
	}
	for key, value := range want {
		if got := rows[0][key]; got != value {
			t.Errorf("%s = %v, want %v", key, got, value)
		}
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
	for _, path := range []string{"/api/v1/audit/queue", "/api/v1/audit/metrics", "/api/v1/audit/queue-depth"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = "host.docker.internal:8080"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s with non-localhost Host: status = %d, want 403", path, w.Code)
		}
	}

	// A scan that forges a loopback Host still holds only its own bearer,
	// which the operator gate refuses.
	for _, path := range []string{"/api/v1/audit/queue", "/api/v1/audit/queue-depth", "/api/v1/findings", "/api/v1/repositories"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s with a scan token and loopback Host: status = %d, want 401", path, w.Code)
		}
	}

	// The per-scan bearer API no longer routes these at all, so a valid
	// scan token gets a 404 rather than instance-wide findings.
	for _, path := range []string{"/api/audit/queue", "/api/audit/metrics", "/api/audit/queue-depth"} {
		r := httptest.NewRequest("GET", path, nil)
		asOperator(r)
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
	f, _ := seedAuditFixture(t, s)

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
	if _, err := db.AddFindingReview(s.DB, reviewed.ID, "false_positive", "guarded", "", ""); err != nil {
		t.Fatalf("seed review: %v", err)
	}

	w := apiReq(t, s, "GET", "/api/v1/audit/queue", testOperatorToken, "")
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
	w = apiReq(t, s, "GET", "/api/v1/audit/queue?limit=1", testOperatorToken, "")
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
		w := apiReq(t, s, "GET", "/api/v1/audit/queue?since="+url.QueryEscape(since), testOperatorToken, "")
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
	if loc := w.Header().Get("Location"); loc != "/findings/"+strconv.Itoa(int(f.ID))+"#reviews" {
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

func getQueueDepth(t *testing.T, s *Server, query string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/audit/queue-depth?"+query, nil)
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// TestApiAuditQueueDepth pins the explicit window, the 24-hour default and the
// wire keys of each point.
func TestApiAuditQueueDepth(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/queue-depth", Name: "queue-depth"}
	s.DB.Create(&repo)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, CreatedAt: t0, StartedAt: new(t0.Add(time.Hour)), FinishedAt: new(t0.Add(2 * time.Hour))})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Status: db.ScanQueued, CreatedAt: time.Now().Add(-2 * time.Hour)})

	w := getQueueDepth(t, s, url.Values{"from": {t0.Format(time.RFC3339)}, "to": {t0.Add(time.Hour).Format(time.RFC3339)}, "step": {"30m"}}.Encode())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body)
	}
	var rows []map[string]any
	decodeJSON(t, w, &rows)
	want := []map[string]any{
		{"at": "2026-11-01T00:00:00Z", "queued": float64(1)},
		{"at": "2026-11-01T00:30:00Z", "queued": float64(1)},
		{"at": "2026-11-01T01:00:00Z", "queued": float64(0)},
	}
	if len(rows) != len(want) {
		t.Fatalf("points = %v, want %v", rows, want)
	}
	for i := range want {
		if len(rows[i]) != len(want[i]) || rows[i]["at"] != want[i]["at"] || rows[i]["queued"] != want[i]["queued"] {
			t.Errorf("point %d = %v, want %v", i, rows[i], want[i])
		}
	}

	w = getQueueDepth(t, s, "")
	if w.Code != http.StatusOK {
		t.Fatalf("default window status = %d; body=%s", w.Code, w.Body)
	}
	var points []db.QueueDepthPoint
	decodeJSON(t, w, &points)
	if len(points) != 25 || points[0].Queued != 0 || points[24].Queued != 1 {
		t.Errorf("default window = %+v, want 25 hourly points ending on the queued scan", points)
	}
}

func TestApiAuditQueueDepthRejectsInvalidWindows(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	for _, query := range []string{
		"from=yesterday",
		"to=2026-11-01",
		"step=1d",
		"step=0s",
		"from=2026-11-02T00:00:00Z&to=2026-11-01T00:00:00Z",
		"from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z&step=1s",
	} {
		w := getQueueDepth(t, s, query)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400; body=%s", query, w.Code, w.Body)
		}
	}
}

// TestApiAuditQueueDepthAcrossUserPause pins that a user pause reads as not
// queued until the resume, and that the resume leaves the hours before the
// pause unchanged.
func TestApiAuditQueueDepthAcrossUserPause(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	t0 := time.Now().UTC().Truncate(time.Hour).Add(-24 * time.Hour)
	clock := t0
	s.DB.NowFunc = func() time.Time { return clock }
	repo := db.Repository{URL: "https://example.com/queue-depth", Name: "queue-depth"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanQueued})
	window := url.Values{"from": {t0.Format(time.RFC3339)}, "to": {t0.Add(5 * time.Hour).Format(time.RFC3339)}}.Encode()
	queuedPerHour := func() []int {
		t.Helper()
		w := getQueueDepth(t, s, window)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", w.Code, w.Body)
		}
		var points []db.QueueDepthPoint
		decodeJSON(t, w, &points)
		var queued []int
		for _, p := range points {
			queued = append(queued, p.Queued)
		}
		return queued
	}

	clock = t0.Add(2 * time.Hour)
	if w := postForm(t, s, "/scans/pause-queued", url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("pause status = %d; body=%s", w.Code, w.Body)
	}
	before := queuedPerHour()
	clock = t0.Add(4 * time.Hour)
	if w := postForm(t, s, "/scans/resume-paused", url.Values{}); w.Code != http.StatusSeeOther {
		t.Fatalf("resume status = %d; body=%s", w.Code, w.Body)
	}
	after := queuedPerHour()

	if want := []int{1, 1, 0, 0, 0, 0}; !slices.Equal(before, want) {
		t.Errorf("while paused = %v, want %v", before, want)
	}
	if want := []int{1, 1, 0, 0, 1, 1}; !slices.Equal(after, want) {
		t.Errorf("after resume = %v, want %v", after, want)
	}
}
