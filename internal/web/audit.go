package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"scrutineer/internal/db"
)

// auditMaxLimit caps the audit queue payload. Spot-checking is the use
// case here; a TOC asking for 10,000 rows is almost certainly a slip.
const auditMaxLimit = 500

// apiListFindingReviews returns reviews on one finding, newest first.
// The finding page renders the same data.
func (s *Server) apiListFindingReviews(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	rows, err := db.ListFindingReviews(s.DB, id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// apiAuditQueue returns the queue payload as JSON, so a TOC export can
// pull it into a spreadsheet without scraping the HTML page. The query
// covers findings across every repository on the instance, so it is
// served from the host-only /api/v1 mux, not the per-scan bearer API: a
// scan token issued for one repo must not be able to read other repos'
// undisclosed findings (#454).
func (s *Server) apiAuditQueue(w http.ResponseWriter, r *http.Request) {
	rows, err := db.AuditQueue(s.DB, auditQueueOptionsFromQuery(r))
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// apiAuditMetrics returns the aggregate stats. The page renders the
// same numbers; the API path is for tooling that needs to pull them on
// a schedule.
func (s *Server) apiAuditMetrics(w http.ResponseWriter, _ *http.Request) {
	m, err := db.ComputeAuditMetrics(s.DB)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// apiAuditQueueDepth returns how many scans were queued at each step of a
// window, for dashboards that plot queue depth over time.
func (s *Server) apiAuditQueueDepth(w http.ResponseWriter, r *http.Request) {
	from, to, step, err := queueDepthWindow(r.URL.Query())
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	points, err := db.QueueDepth(s.DB.WithContext(r.Context()), from, to, step)
	if errors.Is(err, db.ErrInvalidQueueDepthWindow) {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, points)
}

// queueDepthWindow reads the from, to and step parameters, defaulting to the
// last 24 hours in one-hour steps.
func queueDepthWindow(q url.Values) (from, to time.Time, step time.Duration, err error) {
	to, step = time.Now().UTC(), time.Hour
	if v := q.Get("to"); v != "" {
		if to, err = time.Parse(time.RFC3339, v); err != nil {
			return from, to, step, fmt.Errorf("invalid to: %w", err)
		}
	}
	from = to.Add(-24 * time.Hour)
	if v := q.Get("from"); v != "" {
		if from, err = time.Parse(time.RFC3339, v); err != nil {
			return from, to, step, fmt.Errorf("invalid from: %w", err)
		}
	}
	if v := q.Get("step"); v != "" {
		if step, err = time.ParseDuration(v); err != nil {
			return from, to, step, fmt.Errorf("invalid step: %w", err)
		}
	}
	return from, to, step, nil
}

// auditPage renders the audit dashboard: the queue of recently
// auto-bucketed findings (low-sev, rejected, or revalidate-marked as
// not worth pursuing) without lasting marks of human review, plus the
// agreement-rate panel.
func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	rows, err := db.AuditQueue(s.DB, auditQueueOptionsFromQuery(r))
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	metrics, err := db.ComputeAuditMetrics(s.DB)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	const pct = 100
	s.render(w, r, "audit.html", map[string]any{
		"Queue":         rows,
		"Metrics":       metrics,
		"AgreementPct":  int(metrics.AgreementRate * pct),
		"VerdictLabels": []string{"true_positive", "false_positive", "already_fixed", "uncertain"},
	})
}

// findingReviewCreate handles the browser POST from the Review form on
// the finding page. Each field is form-encoded; the automated outcome
// is filled from the latest revalidate note when the form leaves it
// blank, so the operator does not have to remember to paste it in.
func (s *Server) findingReviewCreate(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	verdict := r.FormValue("verdict")
	reason := r.FormValue("reason")
	reviewer := r.FormValue("reviewer")
	automated := r.FormValue("automated_outcome")
	if automated == "" {
		automated = db.LatestRevalidateVerdict(s.DB, f.ID)
	}
	if _, err := db.AddFindingReview(s.DB.WithContext(r.Context()), f.ID, verdict, reason, automated, reviewer); err != nil {
		http.Error(w, err.Error(), findingReviewErrorStatus(err))
		return
	}
	s.redirect(w, r, "/findings/"+strconv.FormatUint(uint64(f.ID), 10)+"#reviews")
}

func (s *Server) rejectFinding(w http.ResponseWriter, r *http.Request, id uint) {
	if err := db.RejectFinding(s.DB.WithContext(r.Context()), id, r.FormValue("verdict"), r.FormValue("reason"), r.FormValue("reviewer")); err != nil {
		http.Error(w, err.Error(), findingReviewErrorStatus(err))
		return
	}
	s.redirect(w, r, "/findings/"+strconv.FormatUint(uint64(id), 10))
}

func findingReviewErrorStatus(err error) int {
	if errors.Is(err, db.ErrInvalidFindingReview) {
		return http.StatusUnprocessableEntity
	}
	return findingWriteErrorStatus(err, http.StatusInternalServerError)
}

func auditQueueOptionsFromQuery(r *http.Request) db.AuditQueueOptions {
	opts := db.AuditQueueOptions{}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n > auditMaxLimit {
				n = auditMaxLimit
			}
			if n > 0 {
				opts.Limit = n
			}
		}
	}
	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			opts.Since = t
		}
	}
	return opts
}
