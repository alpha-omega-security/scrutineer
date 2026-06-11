package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"scrutineer/internal/db"
)

// auditMaxLimit caps the audit queue payload. Spot-checking is the use
// case here; a TOC asking for 10,000 rows is almost certainly a slip.
const auditMaxLimit = 500

// apiAddFindingReview records one structured human verdict against the
// automation's outcome on a finding. The automated_outcome field is
// snapshot from the latest revalidate note at write time so the
// agreement metric does not bend later when revalidate runs again. The
// reviewer field is optional free text; scrutineer is single-operator,
// so populating it is the operator's choice (a GitHub handle, an
// initials marker, or empty).
func (s *Server) apiAddFindingReview(w http.ResponseWriter, r *http.Request) {
	id, ok := s.findingScoped(w, r)
	if !ok {
		return
	}
	var body struct {
		Verdict          string `json:"verdict"`
		Reason           string `json:"reason"`
		Reviewer         string `json:"reviewer"`
		AutomatedOutcome string `json:"automated_outcome"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON")
		return
	}
	automated := body.AutomatedOutcome
	if automated == "" {
		automated = db.LatestRevalidateVerdict(s.DB, id)
	}
	rev, err := db.AddFindingReview(s.DB, id, body.Verdict, body.Reason, automated, body.Reviewer)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rev)
}

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
// pull it into a spreadsheet without scraping the HTML page.
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
	if _, err := db.AddFindingReview(s.DB, f.ID, verdict, reason, automated, reviewer); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.redirect(w, r, "/findings/"+strconv.FormatUint(uint64(f.ID), 10))
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
