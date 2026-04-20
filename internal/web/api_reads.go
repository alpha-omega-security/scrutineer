package web

import (
	"net/http"
	"strconv"

	"scrutineer/internal/db"
)

// The read endpoints below expose the structured rows scrutineer already
// populates from prior skill scans. Skills that need context for a repo
// (verify/patch/disclose, security-deep-dive's reach and prior-art steps)
// call these instead of re-parsing the original scan reports.

func (s *Server) apiListMaintainers(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	var rows []db.Maintainer
	s.DB.Joins("JOIN repository_maintainers rm ON rm.maintainer_id = maintainers.id").
		Where("rm.repository_id = ?", id).
		Order("maintainers.login").Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, m := range rows {
		out = append(out, map[string]any{
			"id":     m.ID,
			"login":  m.Login,
			"name":   m.Name,
			"email":  m.Email,
			"status": string(m.Status),
			"notes":  m.Notes,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

//nolint:dupl // Field projections differ per row type; sharing boilerplate would hide that.
func (s *Server) apiListPackages(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	var rows []db.Package
	s.DB.Where("repository_id = ?", id).Order("dependent_repos desc, downloads desc").Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, map[string]any{
			"id":                 p.ID,
			"name":               p.Name,
			"ecosystem":          p.Ecosystem,
			"purl":               p.PURL,
			"latest_version":     p.LatestVersion,
			"downloads":          p.Downloads,
			"dependent_packages": p.DependentPackages,
			"dependent_repos":    p.DependentRepos,
			"registry_url":       p.RegistryURL,
			"latest_release_at":  p.LatestReleaseAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

//nolint:dupl // Field projections differ per row type; sharing boilerplate would hide that.
func (s *Server) apiListAdvisories(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	var rows []db.Advisory
	s.DB.Where("repository_id = ?", id).Order("cvss_score desc").Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{
			"id":             a.ID,
			"uuid":           a.UUID,
			"url":            a.URL,
			"title":          a.Title,
			"severity":       a.Severity,
			"cvss_score":     a.CVSSScore,
			"classification": a.Classification,
			"packages":       a.Packages,
			"published_at":   a.PublishedAt,
			"withdrawn_at":   a.WithdrawnAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiListDependents(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	var rows []db.Dependent
	s.DB.Where("repository_id = ?", id).Order("dependent_repos desc").Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, d := range rows {
		out = append(out, map[string]any{
			"id":              d.ID,
			"name":            d.Name,
			"ecosystem":       d.Ecosystem,
			"purl":            d.PURL,
			"repository_url":  d.RepositoryURL,
			"downloads":       d.Downloads,
			"dependent_repos": d.DependentRepos,
			"registry_url":    d.RegistryURL,
			"latest_version":  d.LatestVersion,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiListDependencies(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	var rows []db.Dependency
	s.DB.Where("repository_id = ?", id).Order("ecosystem, name").Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, d := range rows {
		out = append(out, map[string]any{
			"id":              d.ID,
			"name":            d.Name,
			"ecosystem":       d.Ecosystem,
			"purl":            d.PURL,
			"requirement":     d.Requirement,
			"dependency_type": d.DependencyType,
			"manifest_path":   d.ManifestPath,
			"manifest_kind":   d.ManifestKind,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiListFindings returns the findings for a repository across every scan.
// Scoped to the authenticated scan's repository; severity filter optional.
func (s *Server) apiListFindings(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return
	}
	// Direct subquery; GORM's Joins("Scan") aliasing doesn't round-trip on
	// sqlite when the joined struct has its own relations.
	q := s.DB.Where("scan_id IN (?)", s.DB.Model(&db.Scan{}).Select("id").Where("repository_id = ?", id)).
		Order("id desc")
	if sev := r.URL.Query().Get("severity"); sev != "" {
		q = q.Where("severity = ?", sev)
	}
	if status := r.URL.Query().Get("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	var rows []db.Finding
	q.Find(&rows)
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		out = append(out, findingSummary(f))
	}
	writeJSON(w, http.StatusOK, out)
}

// apiGetFinding returns one finding plus its six-step prose and a link back
// to the scan that produced it.
func (s *Server) apiGetFinding(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	var f db.Finding
	if err := s.DB.First(&f, id).Error; err != nil {
		writeAPIError(w, http.StatusNotFound, "finding not found")
		return
	}
	if !s.scanOwnsRepo(r, f.RepositoryID) {
		writeAPIError(w, http.StatusForbidden, "scan may only read findings on its own repository")
		return
	}
	summary := findingSummary(f)
	summary["trace"] = f.Trace
	summary["boundary"] = f.Boundary
	summary["validation"] = f.Validation
	summary["prior_art"] = f.PriorArt
	summary["reach"] = f.Reach
	summary["rating"] = f.Rating
	summary["disclosure_draft"] = f.DisclosureDraft
	writeJSON(w, http.StatusOK, summary)
}

func findingSummary(f db.Finding) map[string]any {
	return map[string]any{
		"id":            f.ID,
		"scan_id":       f.ScanID,
		"repository_id": f.RepositoryID,
		"finding_id":    f.FindingID,
		"sinks":         f.Sinks,
		"title":         f.Title,
		"severity":      f.Severity,
		"status":        string(f.Status),
		"cwe":           f.CWE,
		"location":      f.Location,
		"affected":      f.Affected,
		"cve_id":        f.CVEID,
		"cvss_vector":   f.CVSSVector,
		"cvss_score":    f.CVSSScore,
		"fix_version":   f.FixVersion,
		"fix_commit":    f.FixCommit,
		"resolution":    string(f.Resolution),
		"assignee":      f.Assignee,
	}
}
