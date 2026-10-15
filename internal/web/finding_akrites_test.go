package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/akrites"
	"scrutineer/internal/db"
)

func akritesForm(endpoint string) url.Values {
	return url.Values{
		"software": {"widget"}, "purl": {"pkg:npm/widget@1.0.0"}, "ecosystem": {"npm"},
		"raw": {"Reviewed command injection report"}, "exploit": {"Crafted input reaches a shell"},
		"versions": {"1.0.0\n1.0.1"}, "notify": {"off"}, "discovery_method": {"ai-assisted"},
		"symbol_file": {"cmd/run.go"}, "symbol_function": {"buildCommand"}, "symbol_line": {"42"},
		"confirm": {"yes"}, "endpoint": {endpoint},
	}
}

func postAkrites(s *Server, path string, form url.Values) *httptest.ResponseRecorder {
	r := localReq(http.MethodPost, path)
	r.Body = io.NopCloser(strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func akritesRequestMatchesForm(r *http.Request, report akrites.Report) bool {
	return len(report.Attachments) == 2 && len(report.Versions) == 2 &&
		report.Attachments[0].Data == "Reviewed command injection report" && report.Attachments[0].ContentType == "text/markdown" &&
		report.Attachments[1].Type == "exploit-proof-of-concept" && report.Attachments[1].ContentType == "text/plain" &&
		report.AffectedSymbol != nil && *report.AffectedSymbol == akrites.Symbol{File: "cmd/run.go", Function: "buildCommand", Line: 42} &&
		r.Header.Get("Authorization") == "Bearer private-token" && r.Header.Get("TAP-SUBMISSION-TOKEN") == ""
}

func signInOperatorClient(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	login, err := client.Get(baseURL + "/login?token=" + testOperatorToken)
	if err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	if login.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status=%d", login.StatusCode)
	}
}

func TestAkritesSubmissionThroughHTTP(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := seedVINCEFinding(t, s).Finding
	var posts, polls atomic.Int32
	intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/reports":
			posts.Add(1)
			var report akrites.Report
			if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
				t.Error(err)
			}
			if !akritesRequestMatchesForm(r, report) {
				t.Errorf("incorrect report or token: %+v", report)
			}
			w.Header().Set("Link", `</v1/submissions/SUB-persisted>; rel="monitor"`)
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprint(w, `{"receipt":"SUB-persisted"}`)
		case "GET /v1/submissions/SUB-persisted":
			polls.Add(1)
			if r.Header.Get("Authorization") != "" || r.Header.Get("TAP-SUBMISSION-TOKEN") != "" {
				t.Error("token sent with status GET")
			}
			_, _ = fmt.Fprint(w, `{"receipt":"SUB-persisted","status":"done","at":"2026-10-01T12:00:00Z"}`)
		default:
			t.Errorf("unexpected intake path: %s", r.URL.Path)
		}
	}))
	defer intake.Close()
	s.Akrites = akrites.Config{BaseURL: intake.URL, SubmissionToken: "private-token"}
	s.akritesHTTPClient = intake.Client()
	webServer := httptest.NewServer(s.Handler())
	defer webServer.Close()
	client := webServer.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	signInOperatorClient(t, client, webServer.URL)
	path := fmt.Sprintf("/findings/%d/akrites", finding.ID)
	resp, err := client.Get(webServer.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	preview, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(preview), finding.DisclosureDraft) || strings.Contains(string(preview), "private-token") ||
		!strings.Contains(string(preview), `name="symbol_file" class="input" value="cmd/run.go"`) || !strings.Contains(string(preview), `value="42"`) {
		t.Fatalf("preview status=%d body=%s", resp.StatusCode, preview)
	}
	endpoint, _ := s.Akrites.Endpoint()
	resp, err = client.PostForm(webServer.URL+path, akritesForm(endpoint))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("submit status=%d", resp.StatusCode)
	}
	var submission db.DisclosureSubmission
	if err := s.DB.Where("finding_id = ?", finding.ID).First(&submission).Error; err != nil {
		t.Fatal(err)
	}
	if submission.ExternalID != "SUB-persisted" || submission.Status != "queued" || submission.NextPollAt == nil {
		t.Fatalf("saved submission = %+v", submission)
	}
	if err := s.DB.First(&finding, finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if finding.Status != db.FindingReported {
		t.Fatalf("finding status = %s", finding.Status)
	}
	if w := postAkrites(s, path, akritesForm(endpoint)); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unconfirmed duplicate status=%d", w.Code)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts=%d", posts.Load())
	}
	var comms []db.FindingCommunication
	if err := s.DB.Where("finding_id = ? AND channel = ?", finding.ID, "akrites").Find(&comms).Error; err != nil {
		t.Fatal(err)
	}
	if len(comms) != 1 || strings.Contains(comms[0].Body, submission.ExternalID) {
		t.Fatalf("communications=%+v", comms)
	}
	// A new server without a submission token still resumes persisted work
	// against the original intake origin.
	restarted, err := New(s.DB, s.Queue, s.Log, NewBroker(), s.Worker)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Akrites = akrites.Config{}
	restarted.akritesHTTPClient = intake.Client()
	if err := s.DB.Model(&submission).Update("next_poll_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pollerDone := make(chan struct{})
	go func() { defer close(pollerDone); restarted.StartAkritesPoller(ctx) }()
	t.Cleanup(func() { cancel(); <-pollerDone })
	waitForAkritesDone(t, s, submission.ID)
	cancel()
	<-pollerDone
	// Removing the token disables new submissions but keeps the receipt visible.
	s.Akrites = akrites.Config{}
	checkAkritesPages(t, client, webServer.URL, finding.ID)
	if polls.Load() != 1 {
		t.Fatalf("polls=%d", polls.Load())
	}
	t.Logf("HTTP submission saved %s; restarted poller saved done; status page renders receipt and done", submission.ExternalID)
}

func getBody(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func checkAkritesPages(t *testing.T, client *http.Client, base string, findingID uint) {
	t.Helper()
	path := fmt.Sprintf("/findings/%d/akrites", findingID)
	if !strings.Contains(getBody(t, client, base+fmt.Sprintf("/findings/%d", findingID)), `href="`+path+`"`) {
		t.Fatal("finding page hides the Akrites submission once the token is removed")
	}
	if statusPage := getBody(t, client, base+path); !strings.Contains(statusPage, "SUB-persisted") || !strings.Contains(statusPage, "<strong>done</strong>") {
		t.Fatalf("status page=%s", statusPage)
	}
}

func waitForAkritesDone(t *testing.T, s *Server, id uint) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var saved db.DisclosureSubmission
		if err := s.DB.First(&saved, id).Error; err != nil {
			t.Fatal(err)
		}
		if saved.Status == "done" {
			if saved.NextPollAt != nil || saved.StatusAt == nil {
				t.Fatalf("completed submission=%+v", saved)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("poller did not finish: %+v", saved)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAkritesSubmissionGuards(t *testing.T) {
	for _, tc := range []string{"disabled", "unreviewed", "nonviable", "subsumed", "confirmation", "recipient", "invalid report", "empty report", "reserved", "fixed"} {
		t.Run(tc, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			ctx := seedVINCEFinding(t, s)
			var requests atomic.Int32
			intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer intake.Close()
			s.Akrites = akrites.Config{BaseURL: intake.URL, SubmissionToken: "secret"}
			s.akritesHTTPClient = intake.Client()
			endpoint, _ := s.Akrites.Endpoint()
			form := akritesForm(endpoint)
			var err error
			switch tc {
			case "disabled":
				s.Akrites.SubmissionToken = ""
			case "unreviewed":
				err = s.DB.Model(&ctx.Finding).Update("disclosure_draft", "").Error
			case "nonviable":
				err = s.DB.Model(&ctx.Finding).Update("production_viability", db.ProductionViabilityNonViable).Error
			case "subsumed":
				err = s.DB.Create(&db.FindingNote{FindingID: ctx.Finding.ID, Body: "finding-dedup: subsumed by finding #2"}).Error
			case "confirmation":
				form.Del("confirm")
			case "recipient":
				form.Set("endpoint", "https://different.example/v1/reports")
			case "invalid report":
				form.Set("purl", "")
				form.Set("ecosystem", "")
			case "empty report":
				form.Set("raw", " ")
			case "reserved":
				err = s.DB.Create(&db.DisclosureSubmission{FindingID: ctx.Finding.ID, Channel: db.DisclosureChannelAkrites, Status: "uncertain"}).Error
			case "fixed":
				err = s.DB.Model(&ctx.Finding).Update("status", db.FindingFixed).Error
			}
			if err != nil {
				t.Fatal(err)
			}
			w := postAkrites(s, fmt.Sprintf("/findings/%d/akrites", ctx.Finding.ID), form)
			if w.Code < 400 || requests.Load() != 0 {
				t.Fatalf("status=%d requests=%d body=%s", w.Code, requests.Load(), w.Body.String())
			}
		})
	}
}

func TestAkritesSubmissionFailurePersistence(t *testing.T) {
	for _, tc := range []struct {
		code, want int
		retained   bool
	}{
		{http.StatusUnauthorized, http.StatusBadGateway, false},
		{http.StatusForbidden, http.StatusBadGateway, false},
		{http.StatusBadRequest, http.StatusUnprocessableEntity, false},
		{http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, false},
		{http.StatusTooManyRequests, http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, http.StatusBadGateway, false},
		{http.StatusInternalServerError, http.StatusBadGateway, true},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			finding := seedVINCEFinding(t, s).Finding
			intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.code == http.StatusServiceUnavailable {
					w.Header().Set("Retry-After", "120")
				}
				w.WriteHeader(tc.code)
			}))
			defer intake.Close()
			s.Akrites = akrites.Config{BaseURL: intake.URL, SubmissionToken: "secret"}
			s.akritesHTTPClient = intake.Client()
			endpoint, _ := s.Akrites.Endpoint()
			form := akritesForm(endpoint)
			form.Set("raw", "Analyst-edited report")
			w := postAkrites(s, fmt.Sprintf("/findings/%d/akrites", finding.ID), form)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var rows []db.DisclosureSubmission
			if err := s.DB.Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			if !tc.retained {
				// Nothing was stored at Akrites, so the form comes back with the
				// analyst's edits and no reservation blocks a later submission.
				if len(rows) != 0 || !strings.Contains(w.Body.String(), "Analyst-edited report") {
					t.Fatalf("rows=%+v body=%s", rows, w.Body.String())
				}
				if (tc.code == http.StatusTooManyRequests || tc.code == http.StatusServiceUnavailable) && !strings.Contains(w.Body.String(), "submit again after") {
					t.Fatalf("missing retry time: %s", w.Body.String())
				}
				return
			}
			if len(rows) != 1 || rows[0].Status != "uncertain" || rows[0].NextPollAt != nil {
				t.Fatalf("uncertain submission=%+v", rows)
			}
		})
	}
}

func TestAkritesPreviewPackageIdentity(t *testing.T) {
	for _, tc := range []struct{ name, purl, ecosystem, want string }{
		{"package URL", "pkg:golang/github.com/acme/widget/v2@v2.0.0", "golang", ""},
		{"OSV ecosystem", "", "Go", "Go"},
		{"no OSV ecosystem", "", "docker", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			finding := seedVINCEFinding(t, s).Finding
			if err := s.DB.Model(&db.Package{}).Where("repository_id = ?", finding.RepositoryID).Updates(map[string]any{"p_url": tc.purl, "ecosystem": tc.ecosystem}).Error; err != nil {
				t.Fatal(err)
			}
			s.Akrites = akrites.Config{SubmissionToken: "secret"}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/findings/%d/akrites", finding.ID)))
			if want := `name="ecosystem" class="input" value="` + tc.want + `"`; w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
				t.Fatalf("status=%d, missing %s in %s", w.Code, want, w.Body.String())
			}
		})
	}
}

func TestAkritesShowsRejectedFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := seedVINCEFinding(t, s).Finding
	intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, `{"type":"tag:akrites.dev,2026-07:problem/validation","title":"Report failed validation","status":400,"errors":[{"code":"unknown_ecosystem","field":"ecosystem","reason":"not a recognized ecosystem"}]}`)
	}))
	defer intake.Close()
	s.Akrites = akrites.Config{BaseURL: intake.URL, SubmissionToken: "secret"}
	s.akritesHTTPClient = intake.Client()
	endpoint, _ := s.Akrites.Endpoint()
	w := postAkrites(s, fmt.Sprintf("/findings/%d/akrites", finding.ID), akritesForm(endpoint))
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "ecosystem (unknown_ecosystem)") || !strings.Contains(w.Body.String(), "Reviewed command injection report") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var count int64
	if err := s.DB.Model(&db.DisclosureSubmission{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rejected submission not released for correction: count=%d err=%v", count, err)
	}
}

func TestAkritesPreviewWithoutToken(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := seedVINCEFinding(t, s).Finding
	path := fmt.Sprintf("/findings/%d/akrites", finding.ID)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, path))
	if w.Code != http.StatusNotFound {
		t.Fatalf("form offered without a token: status=%d", w.Code)
	}
	if err := s.DB.Create(&db.DisclosureSubmission{FindingID: finding.ID, Channel: db.DisclosureChannelAkrites, Endpoint: akrites.DefaultBaseURL + "/v1/reports", ExternalID: "SUB-kept", Status: "not_found"}).Error; err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, path))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "SUB-kept") || !strings.Contains(w.Body.String(), "stopped checking") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAkritesResendNeedsConfirmation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := seedVINCEFinding(t, s).Finding
	var posts atomic.Int32
	intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := posts.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprintf(w, `{"receipt":"SUB-%d"}`, n)
	}))
	defer intake.Close()
	s.Akrites = akrites.Config{BaseURL: intake.URL, SubmissionToken: "secret"}
	s.akritesHTTPClient = intake.Client()
	endpoint, _ := s.Akrites.Endpoint()
	path := fmt.Sprintf("/findings/%d/akrites", finding.ID)
	if w := postAkrites(s, path, akritesForm(endpoint)); w.Code != http.StatusSeeOther {
		t.Fatalf("first status=%d body=%s", w.Code, w.Body.String())
	}
	preview := httptest.NewRecorder()
	s.Handler().ServeHTTP(preview, localReq(http.MethodGet, path))
	if !strings.Contains(preview.Body.String(), `name="resend"`) || !strings.Contains(preview.Body.String(), "SUB-1") {
		t.Fatalf("history or resend confirmation missing: %s", preview.Body.String())
	}
	form := akritesForm(endpoint)
	form.Set("resend", "yes")
	if w := postAkrites(s, path, form); w.Code != http.StatusSeeOther {
		t.Fatalf("confirmed resend status=%d body=%s", w.Code, w.Body.String())
	}
	rows, err := db.FindingDisclosureSubmissions(s.DB, finding.ID, db.DisclosureChannelAkrites)
	if err != nil || len(rows) != 2 || posts.Load() != 2 || rows[0].ExternalID != "SUB-2" || rows[1].ExternalID != "SUB-1" {
		t.Fatalf("rows=%+v posts=%d err=%v", rows, posts.Load(), err)
	}
	var request akrites.Report
	if err := json.Unmarshal([]byte(rows[0].Request), &request); err != nil || len(request.Attachments) != 2 || request.Attachments[0].Data != "Reviewed command injection report" {
		t.Fatalf("recorded request = %s, err = %v", rows[0].Request, err)
	}
	var events int64
	s.DB.Model(&db.AuditEvent{}).Where("kind = ?", db.AuditEventDisclosureAkritesSubmitted).Count(&events)
	if events != 2 {
		t.Fatalf("akrites_submitted events = %d", events)
	}
}
