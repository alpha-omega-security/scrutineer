package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const exportPrefix = "/api/v1"

func (s *Server) exportHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repositories/{id}/findings", s.apiExportRepoFindings)
	mux.HandleFunc("GET /findings", s.apiExportFindings)
	mux.HandleFunc("GET /scans", s.apiExportScans)
	mux.HandleFunc("POST /import", s.handleImport)
	return mux
}

func (s *Server) apiExportRepoFindings(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "" && format != "jsonl" && format != "bundle" {
		writeAPIError(w, http.StatusBadRequest, "unsupported format: jsonl or bundle")
		return
	}
	// encrypt only applies to the bundle format. Rejecting it here is a
	// safety guard: without it, encrypt=1 on the default (NDJSON) path would
	// be silently ignored and return plaintext — a request that asked for
	// encryption must never get cleartext back.
	if r.URL.Query().Get("encrypt") != "" && format != "bundle" {
		writeAPIError(w, http.StatusBadRequest, "encrypt requires format=bundle")
		return
	}

	id, _ := strconv.Atoi(r.PathValue("id"))
	var repo db.Repository
	if err := s.DB.First(&repo, id).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "repository not found")
		return
	}

	if format == "bundle" {
		s.apiExportRepoBundle(w, r, &repo)
		return
	}
	q := s.DB.Model(&db.Finding{}).
		Where("scan_id IN (?)", s.DB.Model(&db.Scan{}).Select("id").Where("repository_id = ?", id)).
		Order("id desc")
	q = applyFindingFilters(q, r)
	streamJSONL(w, q, findingExport)
}

// sharingBundle is the self-contained sharing format that round-trips
// through ingest.Parse (the "minimal" shape). The shareable unit is one
// repository.
type sharingBundle struct {
	Repository string           `json:"repository"`
	Commit     string           `json:"commit"`
	Tool       string           `json:"tool"`
	Findings   []sharingFinding `json:"findings"`
}

// sharingFinding carries only the substance of a finding — what the analyst
// found, not how they triaged it. Analyst-set state (status, CVE/GHSA id,
// affected, fix_version, references) is intentionally dropped: a bundle shares
// the finding, and the receiving team owns their own triage. Imported findings
// therefore land fresh and untriaged on the recipient's side.
type sharingFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	CWE         string `json:"cwe"`
	Location    string `json:"location"`
	Patch       string `json:"patch"`
}

func (s *Server) apiExportRepoBundle(w http.ResponseWriter, r *http.Request, repo *db.Repository) {
	encrypt := r.URL.Query().Get("encrypt") != ""
	if encrypt && len(s.EncRecipients) == 0 {
		writeAPIError(w, http.StatusBadRequest, "encryption requested but no recipients configured")
		return
	}

	var findings []db.Finding
	q := s.DB.Where("scan_id IN (?)",
		s.DB.Model(&db.Scan{}).Select("id").Where("repository_id = ?", repo.ID)).
		Order("id desc")
	q = applyFindingFilters(q, r)
	if err := q.Find(&findings).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	bundle := sharingBundle{
		Repository: repo.URL,
		Tool:       "scrutineer",
	}
	for _, f := range findings {
		if bundle.Commit == "" {
			bundle.Commit = f.Commit
		}
		bundle.Findings = append(bundle.Findings, sharingFinding{
			Title:       f.Title,
			Description: f.Trace,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			CWE:         f.CWE,
			Location:    f.Location,
			Patch:       f.SuggestedFix,
		})
	}

	data, err := json.Marshal(bundle)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !encrypt {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(data)
		return
	}

	// Encrypt to all configured recipients. The entire bundle is built in
	// memory so we can return a proper error code on failure instead of a
	// truncated body.
	ct, err := encryptBundle(data, s.EncRecipients)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="findings.bundle.age"`)
	_, _ = w.Write(ct)
}

// encryptBundle wraps plaintext in armored age for the given recipients.
//
// Confidentiality + integrity only, not sender authentication: a recipient
// can verify the bundle wasn't tampered with, but cannot cryptographically
// prove who produced it.
func encryptBundle(plain []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	aw, err := age.Encrypt(armorW, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(aw, bytes.NewReader(plain)); err != nil {
		return nil, err
	}
	if err := aw.Close(); err != nil {
		return nil, err
	}
	if err := armorW.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
	if v := r.URL.Query().Get(statusKey); v != "" {
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
	// encrypt is only meaningful for per-repository bundle exports. Rejecting
	// it here stops a request that asked for encryption from silently
	// streaming plaintext NDJSON off these endpoints.
	if r.URL.Query().Get("encrypt") != "" {
		writeAPIError(w, http.StatusBadRequest, "encrypt is only supported on per-repository bundle exports")
		return false
	}
	return true
}

func applyFindingFilters(q *gorm.DB, r *http.Request) *gorm.DB {
	if v := r.URL.Query().Get("severity"); v != "" {
		q = q.Where("severity = ?", v)
	}
	if v := r.URL.Query().Get(statusKey); v != "" {
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
		"id":                  f.ID,
		"scan_id":             f.ScanID,
		"repository_id":       f.RepositoryID,
		"commit":              f.Commit,
		"sub_path":            f.SubPath,
		"fingerprint":         f.Fingerprint,
		"last_seen_scan_id":   f.LastSeenScanID,
		"last_seen_commit":    f.LastSeenCommit,
		"seen_count":          f.SeenCount,
		"missed_count":        f.MissedCount,
		"last_missed_scan_id": f.LastMissedScanID,
		"finding_id":          f.FindingID,
		"sinks":               f.Sinks,
		"title":               f.Title,
		"severity":            f.Severity,
		statusKey:             string(f.Status),
		"cwe":                 f.CWE,
		"location":            f.Location,
		"vid":                 f.VID,
		"affected":            f.Affected,
		"reachability":        f.Reachability,
		"quality_tier":        f.QualityTier,
		"cve_id":              f.CVEID,
		"ghsa_id":             f.GHSAID,
		"cvss_vector":         f.CVSSVector,
		"cvss_score":          f.CVSSScore,
		"fix_version":         f.FixVersion,
		"fix_commit":          f.FixCommit,
		"resolution":          string(f.Resolution),
		"disclosure_draft":    f.DisclosureDraft,
		"assignee":            f.Assignee,
		"trace":               f.Trace,
		"boundary":            f.Boundary,
		"validation":          f.Validation,
		"prior_art":           f.PriorArt,
		"reach":               f.Reach,
		"rating":              f.Rating,
		"created_at":          f.CreatedAt,
		"updated_at":          f.UpdatedAt,
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
		statusKey:            string(sc.Status),
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
		"max_turns_hit":      sc.MaxTurnsHit,
		"prompt":             sc.Prompt,
		"report":             sc.Report,
		"log":                sc.Log,
		errorKey:             sc.Error,
		"findings_count":     sc.FindingsCount,
		"created_at":         sc.CreatedAt,
		"updated_at":         sc.UpdatedAt,
	}
}
