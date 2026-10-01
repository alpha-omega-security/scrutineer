package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	return report.Raw == "Reviewed command injection report" && len(report.Versions) == 2 &&
		report.RawContentType == "text/markdown" && report.ExploitContentType == "text/plain" &&
		r.Header.Get("Authorization") == "Bearer private-token"
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
			w.WriteHeader(http.StatusAccepted)
			_, _ = fmt.Fprint(w, `{"receipt":"SUB-persisted"}`)
		case "GET /v1/submissions/SUB-persisted":
			polls.Add(1)
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
	path := fmt.Sprintf("/findings/%d/akrites", finding.ID)
	resp, err := client.Get(webServer.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	preview, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(preview), finding.DisclosureDraft) || strings.Contains(string(preview), "private-token") {
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
	var submission db.AkritesSubmission
	if err := s.DB.Where("finding_id = ?", finding.ID).First(&submission).Error; err != nil {
		t.Fatal(err)
	}
	if submission.Receipt != "SUB-persisted" || submission.Status != "queued" || submission.NextPollAt == nil {
		t.Fatalf("saved submission = %+v", submission)
	}
	if err := s.DB.First(&finding, finding.ID).Error; err != nil {
		t.Fatal(err)
	}
	if finding.Status != db.FindingReported {
		t.Fatalf("finding status = %s", finding.Status)
	}
	if w := postAkrites(s, path, akritesForm(endpoint)); w.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d", w.Code)
	}
	if posts.Load() != 1 {
		t.Fatalf("posts=%d", posts.Load())
	}
	var comms []db.FindingCommunication
	if err := s.DB.Where("finding_id = ? AND channel = ?", finding.ID, "akrites").Find(&comms).Error; err != nil {
		t.Fatal(err)
	}
	if len(comms) != 1 || strings.Contains(comms[0].Body, submission.Receipt) {
		t.Fatalf("communications=%+v", comms)
	}
	// A new server resumes persisted work against the original intake origin.
	restarted, err := New(s.DB, s.Queue, s.Log, NewBroker(), s.Worker)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Akrites = akrites.Config{BaseURL: "https://different.example", SubmissionToken: "other-token"}
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
	resp, err = client.Get(webServer.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	statusPage, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(statusPage), "SUB-persisted") || !strings.Contains(string(statusPage), "<strong>done</strong>") {
		t.Fatalf("status page=%s", statusPage)
	}
	if polls.Load() != 1 {
		t.Fatalf("polls=%d", polls.Load())
	}
	t.Logf("HTTP submission saved %s; restarted poller saved done; status page renders receipt and done", submission.Receipt)
}

func waitForAkritesDone(t *testing.T, s *Server, id uint) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var saved db.AkritesSubmission
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
	for _, tc := range []string{"disabled", "unreviewed", "nonviable", "subsumed", "confirmation", "recipient", "invalid report", "empty report", "reserved", "reported"} {
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
				err = s.DB.Create(&db.AkritesSubmission{FindingID: ctx.Finding.ID, Status: "uncertain"}).Error
			case "reported":
				err = s.DB.Model(&ctx.Finding).Update("status", db.FindingReported).Error
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
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			finding := seedVINCEFinding(t, s).Finding
			intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if code == http.StatusServiceUnavailable {
					w.Header().Set("Retry-After", "120")
				}
				w.WriteHeader(code)
			}))
			defer intake.Close()
			s.Akrites = akrites.Config{BaseURL: intake.URL, SubmissionToken: "secret"}
			s.akritesHTTPClient = intake.Client()
			endpoint, _ := s.Akrites.Endpoint()
			w := postAkrites(s, fmt.Sprintf("/findings/%d/akrites", finding.ID), akritesForm(endpoint))
			if w.Code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var rows []db.AkritesSubmission
			if err := s.DB.Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			switch code {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest:
				if len(rows) != 0 {
					t.Fatalf("rejected submission retained: %+v", rows)
				}
			case http.StatusInternalServerError:
				if len(rows) != 1 || rows[0].Status != "uncertain" || rows[0].NextPollAt != nil {
					t.Fatalf("uncertain submission=%+v", rows)
				}
			default:
				checkAkritesRetryDelay(t, s, rows)
			}
		})
	}
}

func checkAkritesRetryDelay(t *testing.T, s *Server, rows []db.AkritesSubmission) {
	t.Helper()
	if len(rows) != 1 || rows[0].Status != "rejected" || rows[0].NextPollAt == nil {
		t.Fatalf("delayed submission=%+v", rows)
	}
	s.pollAkrites(context.Background(), time.Now())
	var count int64
	if err := s.DB.Model(&db.AkritesSubmission{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("released early: count=%d err=%v", count, err)
	}
	s.pollAkrites(context.Background(), rows[0].NextPollAt.Add(time.Second))
	if err := s.DB.Model(&db.AkritesSubmission{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("not released: count=%d err=%v", count, err)
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
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "ecosystem (unknown_ecosystem)") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var count int64
	if err := s.DB.Model(&db.AkritesSubmission{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rejected submission not released for correction: count=%d err=%v", count, err)
	}
}
