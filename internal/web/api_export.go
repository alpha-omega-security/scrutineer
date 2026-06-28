package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const exportPrefix = "/api/v1"

func (s *Server) exportHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repositories/{id}/findings", s.apiExportRepoFindings)
	mux.HandleFunc("GET /repositories", s.apiExportRepositories)
	mux.HandleFunc("GET /findings", s.apiExportFindings)
	mux.HandleFunc("GET /scans", s.apiExportScans)
	mux.HandleFunc("POST /import", s.handleImport)
	// Audit endpoints return instance-wide findings and review aggregates,
	// so they live behind the host-only boundary with the other operator
	// exports rather than under per-scan bearer auth (#454).
	mux.HandleFunc("GET /audit/queue", s.apiAuditQueue)
	mux.HandleFunc("GET /audit/metrics", s.apiAuditMetrics)
	return mux
}

// repositoryExportRow is the selected Repositories-tab projection used by the
// JSONL export. It keeps large blob/cache columns out of the query and computes
// FindingsCount with deepDiveFindingsCountSQL so the value matches the UI
// Findings column.
type repositoryExportRow struct {
	ID                 uint
	URL                string
	Name               string
	FullName           string
	Owner              string
	Languages          string
	Stars              int
	CreatedAt          time.Time
	UpdatedAt          time.Time
	LastScanID         *uint
	LastScanKind       string
	LastScanStatus     db.ScanStatus
	LastScanSkillName  string
	LastScanCommit     string
	LastScanCreatedAt  *time.Time
	LastScanFinishedAt *time.Time
	FindingsCount      int
}

// apiExportRepositories streams the Repositories-tab data set as NDJSON for
// local automation. The export includes scalar repository columns and a latest
// scan summary, deliberately omitting metadata, ecosystems caches, and other
// large text blobs.
func (s *Server) apiExportRepositories(w http.ResponseWriter, r *http.Request) {
	if !validateExportFormat(w, r) {
		return
	}
	q := s.DB.Table("repositories").
		Select(`repositories.id,
			repositories.url,
			repositories.name,
			repositories.full_name,
			repositories.owner,
			repositories.languages,
			repositories.stars,
			repositories.created_at,
			repositories.updated_at,
			last_scans.id AS last_scan_id,
			last_scans.kind AS last_scan_kind,
			last_scans.status AS last_scan_status,
			last_scans.skill_name AS last_scan_skill_name,
			last_scans."commit" AS last_scan_commit,
			last_scans.created_at AS last_scan_created_at,
			last_scans.finished_at AS last_scan_finished_at,
			(` + deepDiveFindingsCountSQL + `) AS findings_count`).
		Joins(`LEFT JOIN scans AS last_scans ON last_scans.id = (
			SELECT id FROM scans
			WHERE repository_id = repositories.id
			ORDER BY id DESC
			LIMIT 1
		)`).
		Order("repositories.updated_at desc")
	streamJSONL(w, q, repositoryExport)
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
	// scope=findings curates the bundle to the Findings bucket (deep-dive,
	// vuln-scan, imports), dropping per-repo scanner noise. Like encrypt it only
	// applies to the bundle format; reject it elsewhere rather than silently
	// returning the full set a caller asked to narrow.
	scope := r.URL.Query().Get("scope")
	if scope != "" && scope != "findings" {
		writeAPIError(w, http.StatusBadRequest, "unsupported scope: findings")
		return
	}
	if scope != "" && format != "bundle" {
		writeAPIError(w, http.StatusBadRequest, "scope requires format=bundle")
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
// repository. GeneratedAt records when the bundle was produced (RFC3339
// UTC); it lives inside the encrypted JSON, not in cleartext metadata, and
// the importer ignores it (it is provenance for the human recipient).
type sharingBundle struct {
	Repository  string           `json:"repository"`
	Commit      string           `json:"commit"`
	Tool        string           `json:"tool"`
	GeneratedAt string           `json:"generated_at,omitempty"`
	Findings    []sharingFinding `json:"findings"`
}

// sharingFinding carries the substance of a finding — what was found and the
// reasoning that justifies it (the six-step audit checklist, reachability,
// sink quality, the cross-party VID), plus enough provenance (commit,
// sub-path, all hit locations) to resolve Location unambiguously on the
// receiving side. Analyst-set triage state (status, CVE/GHSA id, affected,
// fix_version, references, assignee) is intentionally dropped: a bundle shares
// the finding, and the receiving team owns their own triage. Imported findings
// therefore land fresh and untriaged on the recipient's side.
//
// All fields after Patch are emitted with omitempty so a finding that lacks
// them — and a bundle produced before they existed — stays byte-compatible
// with the original seven-field shape.
type sharingFinding struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	CWE         string `json:"cwe"`
	Location    string `json:"location"`
	Patch       string `json:"patch"`

	Commit       string `json:"commit,omitempty"`
	SubPath      string `json:"sub_path,omitempty"`
	Locations    string `json:"locations,omitempty"`
	VID          string `json:"vid,omitempty"`
	Reachability string `json:"reachability,omitempty"`
	QualityTier  string `json:"quality_tier,omitempty"`
	Boundary     string `json:"boundary,omitempty"`
	Validation   string `json:"validation,omitempty"`
	PriorArt     string `json:"prior_art,omitempty"`
	Reach        string `json:"reach,omitempty"`
	Rating       string `json:"rating,omitempty"`
	FixCommit    string `json:"fix_commit,omitempty"`
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
	if r.URL.Query().Get("scope") == "findings" {
		// Curate to the Findings bucket — drop semgrep/zizmor scanner noise,
		// keep deep-dive, vuln-scan, and operator imports (nonScannerScanFilter,
		// the same predicate the Findings tab uses). Validated in
		// apiExportRepoFindings; the default (no scope) shares every finding.
		q = q.Where(nonScannerScanFilter)
	}
	q = applyFindingFilters(q, r)
	if err := q.Find(&findings).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	bundle := sharingBundle{
		Repository:  repo.URL,
		Tool:        "scrutineer",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range findings {
		if bundle.Commit == "" {
			bundle.Commit = f.Commit
		}
		bundle.Findings = append(bundle.Findings, sharingFinding{
			Title:        f.Title,
			Description:  f.Trace,
			Severity:     f.Severity,
			Confidence:   f.Confidence,
			CWE:          f.CWE,
			Location:     f.Location,
			Patch:        f.SuggestedFix,
			Commit:       f.Commit,
			SubPath:      f.SubPath,
			Locations:    f.Locations,
			VID:          f.VID,
			Reachability: f.Reachability,
			QualityTier:  f.QualityTier,
			Boundary:     f.Boundary,
			Validation:   f.Validation,
			PriorArt:     f.PriorArt,
			Reach:        f.Reach,
			Rating:       f.Rating,
			FixCommit:    f.SuggestedFixCommit,
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

// repositoryExport maps a repositoryExportRow to the public JSON object. Repos
// with no scans emit last_scan: null; scanned repos get a compact scan summary.
func repositoryExport(row repositoryExportRow) map[string]any {
	out := map[string]any{
		"id":             row.ID,
		"url":            row.URL,
		"name":           row.Name,
		"full_name":      row.FullName,
		"owner":          row.Owner,
		"languages":      row.Languages,
		"stars":          row.Stars,
		"findings_count": row.FindingsCount,
		"created_at":     row.CreatedAt,
		"updated_at":     row.UpdatedAt,
	}
	if row.LastScanID == nil {
		out["last_scan"] = nil
		return out
	}
	out["last_scan"] = map[string]any{
		"id":          *row.LastScanID,
		"kind":        row.LastScanKind,
		statusKey:     string(row.LastScanStatus),
		"skill_name":  row.LastScanSkillName,
		"commit":      row.LastScanCommit,
		"created_at":  row.LastScanCreatedAt,
		"finished_at": row.LastScanFinishedAt,
	}
	return out
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
	// scope curates the per-repository bundle and has no meaning on these
	// cross-repo NDJSON dumps; reject it rather than silently ignore it.
	if r.URL.Query().Get("scope") != "" {
		writeAPIError(w, http.StatusBadRequest, "scope is only supported on per-repository bundle exports")
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
