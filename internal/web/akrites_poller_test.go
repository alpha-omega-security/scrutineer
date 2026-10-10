package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scrutineer/internal/db"
)

func TestAkritesPollBackoff(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := seedVINCEFinding(t, s).Finding
	var calls atomic.Int32
	intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			_, _ = fmt.Fprint(w, `{"receipt":"SUB-poll","status":"processing","at":"2026-10-01T12:00:00Z"}`)
		case 2:
			w.Header().Set("Retry-After", "7200")
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer intake.Close()
	s.akritesHTTPClient = intake.Client()
	now := time.Now().UTC()
	submission := db.AkritesSubmission{FindingID: finding.ID, Endpoint: intake.URL + "/v1/reports", Receipt: "SUB-poll", Status: "queued", NextPollAt: &now}
	if err := s.DB.Create(&submission).Error; err != nil {
		t.Fatal(err)
	}
	s.pollAkrites(context.Background(), now)
	if err := s.DB.First(&submission, submission.ID).Error; err != nil {
		t.Fatal(err)
	}
	if submission.Status != "processing" || submission.PollAttempts != 1 || !submission.NextPollAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("first poll = %+v", submission)
	}
	s.pollAkrites(context.Background(), now)
	if calls.Load() != 1 {
		t.Fatal("polled before due")
	}
	now = *submission.NextPollAt
	s.pollAkrites(context.Background(), now)
	if err := s.DB.First(&submission, submission.ID).Error; err != nil {
		t.Fatal(err)
	}
	if submission.Status != "processing" || submission.PollAttempts != 2 || submission.LastError == "" || !submission.NextPollAt.Equal(now.Add(2*time.Hour)) {
		t.Fatalf("rate limited poll = %+v", submission)
	}
	if err := s.DB.Model(&submission).Update("poll_attempts", 20).Error; err != nil {
		t.Fatal(err)
	}
	now = *submission.NextPollAt
	s.pollAkrites(context.Background(), now)
	if err := s.DB.First(&submission, submission.ID).Error; err != nil {
		t.Fatal(err)
	}
	if submission.Status != "processing" || !submission.NextPollAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("404 lost status or uncapped backoff = %+v", submission)
	}
}

func TestAkritesReceiptSurvivesOutreachFailure(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := seedVINCEFinding(t, s).Finding
	intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprint(w, `{"receipt":"SUB-recoverable"}`)
	}))
	defer intake.Close()
	s.Akrites.BaseURL, s.Akrites.SubmissionToken = intake.URL, "secret"
	s.akritesHTTPClient = intake.Client()
	if err := s.DB.Exec("CREATE TRIGGER reject_akrites_communication BEFORE INSERT ON finding_communications BEGIN SELECT RAISE(ABORT, 'test write failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	endpoint, _ := s.Akrites.Endpoint()
	w := postAkrites(s, fmt.Sprintf("/findings/%d/akrites", finding.ID), akritesForm(endpoint))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", w.Code)
	}
	var saved db.AkritesSubmission
	if err := s.DB.Where("finding_id = ?", finding.ID).First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.Receipt != "SUB-recoverable" || saved.Status != "queued" {
		t.Fatalf("receipt lost: %+v", saved)
	}
}

func TestAkritesReceiptWriteFailure(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	finding := seedVINCEFinding(t, s).Finding
	var requests atomic.Int32
	intake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
		_, _ = fmt.Fprint(w, `{"receipt":"SUB-save-manually"}`)
	}))
	defer intake.Close()
	s.Akrites.BaseURL, s.Akrites.SubmissionToken = intake.URL, "secret"
	s.akritesHTTPClient = intake.Client()
	if err := s.DB.Exec("CREATE TRIGGER reject_receipt_update BEFORE UPDATE ON akrites_submissions BEGIN SELECT RAISE(ABORT, 'test write failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	endpoint, _ := s.Akrites.Endpoint()
	path := fmt.Sprintf("/findings/%d/akrites", finding.ID)
	w := postAkrites(s, path, akritesForm(endpoint))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "SUB-save-manually") || !strings.Contains(w.Body.String(), "<strong>uncertain</strong>") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if w := postAkrites(s, path, akritesForm(endpoint)); w.Code != http.StatusConflict {
		t.Fatalf("retry status=%d", w.Code)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests=%d", requests.Load())
	}
}
