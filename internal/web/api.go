// Package web also hosts the small HTTP API skills use while they run.
// The surface mirrors openapi.yaml at the repo root: list scans, read a
// scan, list skills, enqueue a skill scan, fetch a repository summary.
// Requests authenticate with a per-scan bearer token that the worker
// stages into the workspace's context.json.
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

const apiPrefix = "/api"

// NewAPIToken returns a 32-byte hex token suitable for bearer auth.
func NewAPIToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type apiCtxKey struct{}

// apiAuth validates bearer tokens against the currently running scan rows
// and puts the scan on the request context so handlers can apply the
// "skills only touch their own repo" rule.
func (s *Server) apiAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r.Header.Get("Authorization"))
		if token == "" {
			writeAPIError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		var scan db.Scan
		if err := s.DB.Where("api_token = ? AND status = ?", token, db.ScanRunning).
			First(&scan).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				writeAPIError(w, http.StatusUnauthorized, "token invalid or scan not running")
				return
			}
			writeAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), apiCtxKey{}, &scan)
		r.Body = http.MaxBytesReader(w, r.Body, apiMaxBody)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const apiMaxBody = 1 << 20

func bearer(h string) string {
	const prefix = "Bearer "
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// scanFromRequest pulls the authenticated scan off the request context.
func scanFromRequest(r *http.Request) *db.Scan {
	if v, ok := r.Context().Value(apiCtxKey{}).(*db.Scan); ok {
		return v
	}
	return nil
}

// scanOwnsRepo enforces the rule that a scan's API token only grants access
// to the repository it was issued against.
func (s *Server) scanOwnsRepo(r *http.Request, repoID uint) bool {
	sc := scanFromRequest(r)
	return sc != nil && sc.RepositoryID == repoID
}

func (s *Server) apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repositories/{id}", s.apiGetRepository)
	mux.HandleFunc("PATCH /repositories/{id}", s.apiPatchRepository)
	mux.HandleFunc("GET /repositories/{id}/scans", s.apiListScans)
	mux.HandleFunc("GET /repositories/{id}/maintainers", s.apiListMaintainers)
	mux.HandleFunc("GET /repositories/{id}/packages", s.apiListPackages)
	mux.HandleFunc("GET /repositories/{id}/advisories", s.apiListAdvisories)
	mux.HandleFunc("GET /repositories/{id}/dependents", s.apiListDependents)
	mux.HandleFunc("GET /repositories/{id}/ecosystems/{source}/raw", s.apiGetEcosystemsRaw)
	mux.HandleFunc("GET /repositories/{id}/dependencies", s.apiListDependencies)
	mux.HandleFunc("GET /repositories/{id}/findings", s.apiListFindings)
	mux.HandleFunc("POST /repositories/{id}/findings", s.apiStreamFinding)
	mux.HandleFunc("GET /repositories/{id}/dependency-findings", s.apiListDependencyFindings)
	mux.HandleFunc("POST /repositories/{id}/skills/{name}/run", s.apiRunSkill)
	mux.HandleFunc("POST /findings/{id}/skills/{name}/run", s.apiRunFindingSkill)
	mux.HandleFunc("GET /scans/{id}", s.apiGetScan)
	mux.HandleFunc("POST /scans/{id}/validate-report", s.apiValidateReport)
	mux.HandleFunc("GET /findings/{id}", s.apiGetFinding)
	mux.HandleFunc("PATCH /findings/{id}", s.apiPatchFinding)
	mux.HandleFunc("GET /findings/{id}/notes", s.apiListFindingNotes)
	mux.HandleFunc("POST /findings/{id}/notes", s.apiAddFindingNote)
	mux.HandleFunc("GET /findings/{id}/reviews", s.apiListFindingReviews)
	mux.HandleFunc("POST /findings/{id}/reviews", s.apiAddFindingReview)
	// /audit/queue and /audit/metrics are intentionally on the host-only
	// /api/v1 export mux, not here: they return findings across every
	// repository on the instance, so a scan token issued for one repo
	// must not be able to read them (#454).
	mux.HandleFunc("GET /findings/{id}/communications", s.apiListFindingCommunications)
	mux.HandleFunc("POST /findings/{id}/communications", s.apiAddFindingCommunication)
	mux.HandleFunc("GET /findings/{id}/references", s.apiListFindingReferences)
	mux.HandleFunc("POST /findings/{id}/references", s.apiAddFindingReference)
	mux.HandleFunc("PUT /findings/{id}/labels", s.apiSetFindingLabels)
	mux.HandleFunc("GET /findings/{id}/history", s.apiListFindingHistory)
	mux.HandleFunc("GET /skills", s.apiListSkills)
	mux.HandleFunc("GET /cnas", s.apiListCNAs)
	return http.StripPrefix(apiPrefix, s.apiAuth(mux))
}

func (s *Server) apiGetRepository(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	var repo db.Repository
	if err := s.DB.First(&repo, id).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "repository not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":              repo.ID,
		"url":             repo.URL,
		"name":            repo.Name,
		"full_name":       repo.FullName,
		"default_branch":  repo.DefaultBranch,
		"html_url":        repo.HTMLURL,
		"stars":           repo.Stars,
		"forks":           repo.Forks,
		"archived":        repo.Archived,
		"languages":       repo.Languages,
		"license":         repo.License,
		"fork":            repo.Fork,
		"posture":         repo.Posture,
		"posture_summary": repo.PostureSummary,
	})
}

// ecosystemsRawColumns maps the {source} path segment of the diagnostic
// endpoint to the Repository column holding that source's cached payload.
var ecosystemsRawColumns = map[string]string{
	"repo":       "ecosystems_repo_data",
	"packages":   "ecosystems_packages_data",
	"advisories": "ecosystems_advisories_data",
	"commits":    "ecosystems_commits_data",
	"issues":     "ecosystems_issues_data",
	"dependents": "ecosystems_dependents_data",
}

// apiGetEcosystemsRaw returns the verbatim cached ecosyste.ms payload for one
// source: an operator/debug escape hatch, and a skill fallback when a
// digested endpoint does not cover an edge case. 404 when nothing is cached
// (the skill then falls back to WebFetch); 400 for an unknown source.
func (s *Server) apiGetEcosystemsRaw(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	column, ok := ecosystemsRawColumns[r.PathValue("source")]
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "unknown ecosystems source")
		return
	}
	var payload string
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", id).Pluck(column, &payload).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if payload == "" {
		writeAPIError(w, http.StatusNotFound, "no cached payload for source")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(payload))
}

// apiPatchRepository lets a skill write back fields it derived for the
// repository. Currently only `fork` (the staging fork's owner/name) is
// accepted; everything else on Repository is owned by the metadata job.
func (s *Server) apiPatchRepository(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only edit its own repository")
		return
	}
	var body struct {
		Fork *string `json:"fork"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON")
		return
	}
	if body.Fork == nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "no writable fields in body")
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", id).Update("fork", *body.Fork).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiListScans(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only list scans on its own repository")
		return
	}
	q := s.DB.Where("repository_id = ?", id).Order("id desc")
	if status := r.URL.Query().Get(statusKey); status != "" {
		q = q.Where("status = ?", status)
	}
	if skill := r.URL.Query().Get("skill"); skill != "" {
		q = q.Where("skill_name = ?", skill)
	}
	var rows []db.Scan
	q.Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, sc := range rows {
		out = append(out, scanSummary(sc))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiGetScan(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var sc db.Scan
	if err := s.DB.First(&sc, id).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "scan not found")
		return
	}
	if !s.scanOwnsRepo(r, sc.RepositoryID) {
		writeAPIError(w, http.StatusForbidden, "scan may only read scans on its own repository")
		return
	}
	summary := scanSummary(sc)
	summary["report"] = sc.Report
	summary["log"] = sc.Log
	writeJSON(w, http.StatusOK, summary)
}

// apiValidateReport lets a running skill check a candidate report.json against
// its skill's schema without installing a JSON Schema library inside the runner
// container. The request body is the candidate report; the response is
// {"valid":true} or {"valid":false,"errors":"..."} using the exact same
// validator (worker.ValidateReportSchema) the harness runs after the scan, so
// an in-container pass guarantees the harness will not send a repair prompt.
//
// The body is already capped at apiMaxBody (1 MB) by apiAuth's MaxBytesReader;
// an oversized report is rejected rather than silently truncated.
func (s *Server) apiValidateReport(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	scan := scanFromRequest(r)
	if scan == nil || scan.ID != uint(id) {
		writeAPIError(w, http.StatusForbidden, "scan may only validate its own report")
		return
	}
	if scan.SkillID == nil {
		writeAPIError(w, http.StatusBadRequest, "scan has no skill")
		return
	}
	var skill db.Skill
	if err := s.DB.First(&skill, *scan.SkillID).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "skill not found")
		return
	}
	if skill.SchemaJSON == "" {
		writeJSON(w, http.StatusOK, map[string]any{"valid": true, "note": "skill has no schema"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "could not read body (max 1 MB)")
		return
	}
	if detail := worker.ValidateReportSchema(skill.SchemaJSON, string(body)); detail != "" {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "errors": detail})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

func (s *Server) apiRunSkill(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	name := r.PathValue("name")
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only trigger skills on its own repository")
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", name, true).First(&skill).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "skill not found or inactive")
		return
	}
	var body struct {
		Model   string `json:"model"`
		Ref     string `json:"ref"`
		Profile string `json:"profile"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Profile != "" && !worker.KnownProfile(body.Profile) {
		writeAPIError(w, http.StatusBadRequest, "unknown profile")
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), uint(id), skill.ID, ScanOpts{
		Model:   body.Model,
		Ref:     body.Ref,
		Profile: body.Profile,
	})
	if err != nil {
		if errors.Is(err, ErrSkillRequiresRemote) {
			writeAPIError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, ErrSkillProfileMismatch) {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		if errors.Is(err, ErrInvalidRef) {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var sc db.Scan
	s.DB.First(&sc, scanID)
	writeJSON(w, http.StatusCreated, scanSummary(sc))
}

// apiRunFindingSkill enqueues a finding-scoped skill (verify, patch,
// disclose). The authenticated scan must be on the same repository that
// owns the finding.
func (s *Server) apiRunFindingSkill(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	name := r.PathValue("name")
	repoID, ok := s.findingRepoID(uint(id))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "finding not found")
		return
	}
	if !s.scanOwnsRepo(r, repoID) {
		writeAPIError(w, http.StatusForbidden, "scan may only trigger skills on its own repository")
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", name, true).First(&skill).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "skill not found or inactive")
		return
	}
	var body struct {
		Model string `json:"model"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	scanID, err := s.enqueueSkillScoped(r.Context(), repoID, skill.ID, new(uint(id)), body.Model)
	if err != nil {
		if errors.Is(err, ErrSkillRequiresRemote) {
			writeAPIError(w, http.StatusNotFound, err.Error())
			return
		}
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var sc db.Scan
	s.DB.First(&sc, scanID)
	writeJSON(w, http.StatusCreated, scanSummary(sc))
}

// findingRepoID reads the denormalized Finding.RepositoryID column. Used
// by the skill-facing handlers to enforce "scan can only touch findings
// on its own repository" without re-reading the entire Finding row.
func (s *Server) findingRepoID(findingID uint) (uint, bool) {
	var repoID uint
	row := s.DB.Model(&db.Finding{}).Select("repository_id").Where("id = ?", findingID).Row()
	if err := row.Scan(&repoID); err != nil || repoID == 0 {
		return 0, false
	}
	return repoID, true
}

// apiListCNAs returns the cached CVE Numbering Authority list. Global
// (not repo-scoped) since CNA scope is matched against repo metadata by
// the caller, not by scrutineer. Supports ?q= for a substring match
// across short_name, organization, and scope so a skill can narrow before
// reading prose.
func (s *Server) apiListCNAs(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Order("short_name")
	if term := r.URL.Query().Get("q"); term != "" {
		like := "%" + term + "%"
		q = q.Where("short_name LIKE ? OR organization LIKE ? OR scope LIKE ?", like, like, like)
	}
	var rows []db.CNA
	q.Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{
			"short_name":   c.ShortName,
			"cna_id":       c.CNAID,
			"organization": c.Organization,
			"scope":        c.Scope,
			"email":        c.Email,
			"contact_url":  c.ContactURL,
			"policy_url":   c.PolicyURL,
			"advisory_url": c.AdvisoryURL,
			"root":         c.Root,
			"types":        c.Types,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiListSkills(w http.ResponseWriter, r *http.Request) {
	q := s.DB.Order("name")
	if v := r.URL.Query().Get("active"); v != "" {
		active, _ := strconv.ParseBool(v)
		q = q.Where("active = ?", active)
	}
	var rows []db.Skill
	q.Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, sk := range rows {
		out = append(out, map[string]any{
			"id":          sk.ID,
			"name":        sk.Name,
			"description": sk.Description,
			"output_kind": sk.OutputKind,
			"output_file": sk.OutputFile,
			"max_turns":   sk.MaxTurns,
			"model":       sk.Model,
			"version":     sk.Version,
			"active":      sk.Active,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func scanSummary(sc db.Scan) map[string]any {
	m := map[string]any{
		"id":            sc.ID,
		"repository_id": sc.RepositoryID,
		"kind":          sc.Kind,
		statusKey:       string(sc.Status),
		"model":         sc.Model,
		"commit":        sc.Commit,
		"skill_name":    sc.SkillName,
		"skill_version": sc.SkillVersion,
		"started_at":    sc.StartedAt,
		"finished_at":   sc.FinishedAt,
		"max_turns_hit": sc.MaxTurnsHit,
		errorKey:        sc.Error,
	}
	if sc.Ref != "" {
		m["ref"] = sc.Ref
	}
	return m
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{errorKey: msg})
}
