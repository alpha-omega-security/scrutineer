package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const exportPrefix = "/api/v1"

func (s *Server) exportHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repositories/{id}/findings", s.apiExportRepoFindings)
	mux.HandleFunc("GET /findings", s.apiExportFindings)
	mux.HandleFunc("GET /scans", s.apiExportScans)
	return mux
}

func (s *Server) apiExportRepoFindings(w http.ResponseWriter, r *http.Request) {
	if !validateExportFormat(w, r) {
		return
	}
	id, _ := strconv.Atoi(r.PathValue("id"))
	var repo db.Repository
	if err := s.DB.First(&repo, id).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "repository not found")
		return
	}

	q := s.DB.Model(&db.Finding{}).
		Where("scan_id IN (?)", s.DB.Model(&db.Scan{}).Select("id").Where("repository_id = ?", id)).
		Order("id desc")
	q = applyFindingFilters(q, r)
	streamJSONL(w, q, findingExport)
}

func (s *Server) apiExportFindings(w http.ResponseWriter, r *http.Request) {
	if !validateExportFormat(w, r) {
		return
	}
	q := applyFindingFilters(s.DB.Model(&db.Finding{}).Order("id desc"), r)
	streamJSONL(w, q, findingExport)
}

func (s *Server) apiExportScans(w http.ResponseWriter, r *http.Request) {
	if !validateExportFormat(w, r) {
		return
	}
	q := s.DB.Model(&db.Scan{}).Order("id desc")
	if v := r.URL.Query().Get("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	if v := r.URL.Query().Get("skill"); v != "" {
		q = q.Where("skill_name = ?", v)
	}
	streamJSONL(w, q, scanExport)
}

func validateExportFormat(w http.ResponseWriter, r *http.Request) bool {
	if v := r.URL.Query().Get("format"); v != "" && v != "jsonl" {
		writeAPIError(w, http.StatusBadRequest, "unsupported format: only jsonl")
		return false
	}
	return true
}

func applyFindingFilters(q *gorm.DB, r *http.Request) *gorm.DB {
	if v := r.URL.Query().Get("severity"); v != "" {
		q = q.Where("severity = ?", v)
	}
	if v := r.URL.Query().Get("status"); v != "" {
		q = q.Where("status = ?", v)
	}
	return q
}

// streamJSONL iterates rows incrementally so a million-row export never
// preloads into memory. The body is partial on mid-stream errors: once
// we have committed to 200, a truncated stream is the only honest signal.
func streamJSONL[T any](w http.ResponseWriter, q *gorm.DB, project func(T) map[string]any) {
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	rows, err := q.Rows()
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	enc := json.NewEncoder(w)
	flusher, _ := w.(http.Flusher)
	for rows.Next() {
		var item T
		if err := q.ScanRows(rows, &item); err != nil {
			return
		}
		if err := enc.Encode(project(item)); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// findingExport mirrors every db.Finding column. Relations (labels, notes,
// ...) are exposed via dedicated endpoints, not inlined here.
func findingExport(f db.Finding) map[string]any {
	return map[string]any{
		"id":                f.ID,
		"scan_id":           f.ScanID,
		"repository_id":     f.RepositoryID,
		"commit":            f.Commit,
		"sub_path":          f.SubPath,
		"fingerprint":       f.Fingerprint,
		"last_seen_scan_id": f.LastSeenScanID,
		"last_seen_commit":  f.LastSeenCommit,
		"seen_count":        f.SeenCount,
		"finding_id":        f.FindingID,
		"sinks":             f.Sinks,
		"title":             f.Title,
		"severity":          f.Severity,
		"status":            string(f.Status),
		"cwe":               f.CWE,
		"location":          f.Location,
		"affected":          f.Affected,
		"cve_id":            f.CVEID,
		"cvss_vector":       f.CVSSVector,
		"cvss_score":        f.CVSSScore,
		"fix_version":       f.FixVersion,
		"fix_commit":        f.FixCommit,
		"resolution":        string(f.Resolution),
		"disclosure_draft":  f.DisclosureDraft,
		"assignee":          f.Assignee,
		"trace":             f.Trace,
		"boundary":          f.Boundary,
		"validation":        f.Validation,
		"prior_art":         f.PriorArt,
		"reach":             f.Reach,
		"rating":            f.Rating,
		"created_at":        f.CreatedAt,
		"updated_at":        f.UpdatedAt,
	}
}

// scanExport mirrors db.Scan's columns minus APIToken: the bearer is the
// running scan's auth credential and must never leak through an
// unauthenticated channel.
func scanExport(sc db.Scan) map[string]any {
	return map[string]any{
		"id":                 sc.ID,
		"repository_id":      sc.RepositoryID,
		"kind":               sc.Kind,
		"status":             string(sc.Status),
		"model":              sc.Model,
		"skill_id":           sc.SkillID,
		"skill_version":      sc.SkillVersion,
		"skill_name":         sc.SkillName,
		"finding_id":         sc.FindingID,
		"sub_path":           sc.SubPath,
		"commit":             sc.Commit,
		"started_at":         sc.StartedAt,
		"finished_at":        sc.FinishedAt,
		"cost_usd":           sc.CostUSD,
		"turns":              sc.Turns,
		"input_tokens":       sc.InputTokens,
		"output_tokens":      sc.OutputTokens,
		"cache_read_tokens":  sc.CacheReadTokens,
		"cache_write_tokens": sc.CacheWriteTokens,
		"prompt":             sc.Prompt,
		"report":             sc.Report,
		"log":                sc.Log,
		"error":              sc.Error,
		"findings_count":     sc.FindingsCount,
		"created_at":         sc.CreatedAt,
		"updated_at":         sc.UpdatedAt,
	}
}
