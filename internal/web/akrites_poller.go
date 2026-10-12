package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"scrutineer/internal/akrites"
	"scrutineer/internal/db"
)

const (
	akritesPollInitial   = time.Minute
	akritesPollMaximum   = time.Hour
	akritesPollBatch     = 100
	akritesBackoffFactor = 2
)

// StartAkritesPoller runs whether or not submission is enabled: polling needs
// no token and uses each submission's saved endpoint.
func (s *Server) StartAkritesPoller(ctx context.Context) {
	ticker := time.NewTicker(akritesPollInitial)
	defer ticker.Stop()
	for {
		s.pollAkrites(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) pollAkrites(ctx context.Context, now time.Time) {
	var submissions []db.AkritesSubmission
	if err := s.DB.WithContext(ctx).Where("next_poll_at <= ?", now).Order("next_poll_at").Limit(akritesPollBatch).Find(&submissions).Error; err != nil {
		s.Log.Error("load Akrites submissions", "err", err)
		return
	}
	for _, submission := range submissions {
		if ctx.Err() != nil {
			return
		}
		s.pollAkritesSubmission(ctx, submission, now)
	}
}

func (s *Server) pollAkritesSubmission(ctx context.Context, submission db.AkritesSubmission, now time.Time) {
	// Poll the original origin even if configuration has since changed. GET has no token.
	cfg := akrites.Config{BaseURL: strings.TrimSuffix(submission.Endpoint, "/v1/reports")}
	client := akrites.Client{Config: cfg, HTTPClient: s.akritesHTTPClient}
	status, err := client.Poll(ctx, submission.Receipt)
	if ctx.Err() != nil {
		return
	}
	delay := akritesPollInitial
	for i := 0; i < submission.PollAttempts && delay < akritesPollMaximum; i++ {
		delay = min(akritesBackoffFactor*delay, akritesPollMaximum)
	}
	update := map[string]any{"last_error": "", "poll_attempts": submission.PollAttempts + 1}
	var response *akrites.ResponseError
	if err != nil {
		update["last_error"] = err.Error()
		if errors.As(err, &response) {
			delay = max(delay, response.RetryAfter)
		}
	} else {
		update["status"], update["status_at"] = status.Status, status.At
	}
	update["next_poll_at"] = now.Add(delay)
	switch {
	case err == nil && status.Status == "done":
		update["next_poll_at"] = nil
	case response != nil && response.StatusCode == http.StatusNotFound:
		// Intake does not know the receipt, so further polls cannot succeed.
		update["status"], update["next_poll_at"] = "not_found", nil
	}
	if err := s.DB.WithContext(ctx).Model(&db.AkritesSubmission{}).Where("id = ?", submission.ID).Updates(update).Error; err != nil {
		s.Log.Error("save Akrites status", "id", submission.ID)
	}
}
