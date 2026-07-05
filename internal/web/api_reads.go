package web

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// The read endpoints below expose the structured rows scrutineer already
// populates from prior skill scans. Skills that need context for a repo
// (verify/patch/disclose, security-deep-dive's reach and prior-art steps)
// call these instead of re-parsing the original scan reports.

// repoScopedID parses the path id and enforces the scan-owns-repo auth
// rule for the apiList* handlers. Returns false when the response has
// already been written with a 403.
func (s *Server) repoScopedID(w http.ResponseWriter, r *http.Request) (uint, bool) {
	id, _ := strconv.Atoi(r.PathValue("id"))
	if !s.scanOwnsRepo(r, uint(id)) {
		writeAPIError(w, http.StatusForbidden, "scan may only read its own repository")
		return 0, false
	}
	return uint(id), true
}

type maintainerResponse struct {
	ID     uint   `json:"id"`
	Login  string `json:"login"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

func (s *Server) apiListMaintainers(w http.ResponseWriter, r *http.Request) {
	id, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	var rows []db.Maintainer
	s.DB.Joins("JOIN repository_maintainers rm ON rm.maintainer_id = maintainers.id").
		Where("rm.repository_id = ?", id).
		Order("maintainers.login").Find(&rows)
	out := make([]maintainerResponse, 0, len(rows))
	for _, m := range rows {
		out = append(out, maintainerResponse{
			ID:     m.ID,
			Login:  m.Login,
			Name:   m.Name,
			Email:  m.Email,
			Status: string(m.Status),
			Notes:  m.Notes,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type packageResponse struct {
	ID                uint       `json:"id"`
	Name              string     `json:"name"`
	Ecosystem         string     `json:"ecosystem"`
	PURL              string     `json:"purl"`
	LatestVersion     string     `json:"latest_version"`
	Downloads         int64      `json:"downloads"`
	DependentPackages int        `json:"dependent_packages"`
	DependentRepos    int        `json:"dependent_repos"`
	RegistryURL       string     `json:"registry_url"`
	LatestReleaseAt   *time.Time `json:"latest_release_at"`
}

func (s *Server) apiListPackages(w http.ResponseWriter, r *http.Request) {
	id, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	var rows []db.Package
	s.DB.Where("repository_id = ?", id).Order("dependent_repos desc, downloads desc").Find(&rows)
	out := make([]packageResponse, 0, len(rows))
	for _, p := range rows {
		out = append(out, packageResponse{
			ID:                p.ID,
			Name:              p.Name,
			Ecosystem:         p.Ecosystem,
			PURL:              p.PURL,
			LatestVersion:     p.LatestVersion,
			Downloads:         p.Downloads,
			DependentPackages: p.DependentPackages,
			DependentRepos:    p.DependentRepos,
			RegistryURL:       p.RegistryURL,
			LatestReleaseAt:   p.LatestReleaseAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type advisoryResponse struct {
	ID             uint       `json:"id"`
	UUID           string     `json:"uuid"`
	URL            string     `json:"url"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	CVSSScore      float64    `json:"cvss_score"`
	Classification string     `json:"classification"`
	Packages       string     `json:"packages"`
	PublishedAt    *time.Time `json:"published_at"`
	WithdrawnAt    *time.Time `json:"withdrawn_at"`
}

func (s *Server) apiListAdvisories(w http.ResponseWriter, r *http.Request) {
	id, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	var rows []db.Advisory
	s.DB.Where("repository_id = ?", id).Order("cvss_score desc").Find(&rows)
	out := make([]advisoryResponse, 0, len(rows))
	for _, a := range rows {
		out = append(out, advisoryResponse{
			ID:             a.ID,
			UUID:           a.UUID,
			URL:            a.URL,
			Title:          a.Title,
			Severity:       a.Severity,
			CVSSScore:      a.CVSSScore,
			Classification: a.Classification,
			Packages:       a.Packages,
			PublishedAt:    a.PublishedAt,
			WithdrawnAt:    a.WithdrawnAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type dependentResponse struct {
	ID             uint   `json:"id"`
	Name           string `json:"name"`
	Ecosystem      string `json:"ecosystem"`
	PURL           string `json:"purl"`
	RepositoryURL  string `json:"repository_url"`
	Downloads      int64  `json:"downloads"`
	DependentRepos int    `json:"dependent_repos"`
	RegistryURL    string `json:"registry_url"`
	LatestVersion  string `json:"latest_version"`
}

func (s *Server) apiListDependents(w http.ResponseWriter, r *http.Request) {
	id, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	var rows []db.Dependent
	s.DB.Where("repository_id = ?", id).Order("dependent_repos desc").Find(&rows)
	out := make([]dependentResponse, 0, len(rows))
	for _, d := range rows {
		out = append(out, dependentResponse{
			ID:             d.ID,
			Name:           d.Name,
			Ecosystem:      d.Ecosystem,
			PURL:           d.PURL,
			RepositoryURL:  d.RepositoryURL,
			Downloads:      d.Downloads,
			DependentRepos: d.DependentRepos,
			RegistryURL:    d.RegistryURL,
			LatestVersion:  d.LatestVersion,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

type dependencyResponse struct {
	ID                    uint   `json:"id"`
	Name                  string `json:"name"`
	Ecosystem             string `json:"ecosystem"`
	PURL                  string `json:"purl"`
	Requirement           string `json:"requirement"`
	RequirementUnresolved bool   `json:"requirement_unresolved"`
	RequirementResolution string `json:"requirement_resolution"`
	DependencyType        string `json:"dependency_type"`
	ManifestPath          string `json:"manifest_path"`
	ManifestKind          string `json:"manifest_kind"`
}

func (s *Server) apiListDependencies(w http.ResponseWriter, r *http.Request) {
	id, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	var rows []db.Dependency
	s.DB.Where("repository_id = ?", id).Order("ecosystem, name").Find(&rows)
	out := make([]dependencyResponse, 0, len(rows))
	for _, d := range rows {
		out = append(out, dependencyResponse{
			ID:                    d.ID,
			Name:                  d.Name,
			Ecosystem:             d.Ecosystem,
			PURL:                  d.PURL,
			Requirement:           d.Requirement,
			RequirementUnresolved: d.RequirementUnresolved,
			RequirementResolution: d.RequirementResolution,
			DependencyType:        d.DependencyType,
			ManifestPath:          d.ManifestPath,
			ManifestKind:          d.ManifestKind,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// apiListDependencyFindings returns findings on any library repository whose
// published package appears in this repository's dependency list. The skill
// token still only authorises the caller's own repo; the cross-repo read is
// derived from that repo's dependencies, not chosen by the caller.
func (s *Server) apiListDependencyFindings(w http.ResponseWriter, r *http.Request) {
	id, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	rows, err := db.DependencyFindings(s.DB, id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		filtered := rows[:0]
		for _, row := range rows {
			if row.Severity == sev {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	writeJSON(w, http.StatusOK, rows)
}

// apiListFindings returns the findings for a repository across every scan.
// Scoped to the authenticated scan's repository; severity filter optional.
func (s *Server) apiListFindings(w http.ResponseWriter, r *http.Request) {
	id, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	// Direct subquery; GORM's Joins("Scan") aliasing doesn't round-trip on
	// sqlite when the joined struct has its own relations.
	scans := s.DB.Model(&db.Scan{}).Select("id").Where("repository_id = ?", id)
	if skill := r.URL.Query().Get("skill"); skill != "" {
		scans = scans.Where("skill_name = ?", skill)
	}
	// scan_group narrows to one parallel batch so an in-flight audit skill
	// reads only its siblings' findings. Kept inside the repo-scoped
	// subquery so a guessed group can never leak another repo's findings.
	if sg := r.URL.Query().Get("scan_group"); sg != "" {
		scans = scans.Where("scan_group = ?", sg)
	}
	q := s.DB.Where("scan_id IN (?)", scans).Order("id desc")
	if sev := r.URL.Query().Get("severity"); sev != "" {
		q = q.Where("severity = ?", sev)
	}
	if status := r.URL.Query().Get(statusKey); status != "" {
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

// apiStreamFinding records one finding mid-scan into the concurrent-finding
// log so siblings in the same scan_group can read it before this scan
// completes. The body is a single finding in the report.json finding
// shape; the scan's identity is stamped from the bearer token, not the body.
func (s *Server) apiStreamFinding(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.repoScopedID(w, r); !ok {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	f, err := s.Worker.PersistStreamedFinding(scanFromRequest(r), body)
	if errors.Is(err, worker.ErrInvalidFinding) {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, findingSummary(*f))
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
	summary["suggested_fix"] = f.SuggestedFix
	summary["suggested_fix_commit"] = f.SuggestedFixCommit
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
		statusKey:       string(f.Status),
		"cwe":           f.CWE,
		"location":      f.Location,
		"vid":           f.VID,
		"affected":      f.Affected,
		"reachability":  f.Reachability,
		"quality_tier":  f.QualityTier,
		"cve_id":        f.CVEID,
		"ghsa_id":       f.GHSAID,
		"cvss_vector":   f.CVSSVector,
		"cvss_score":    f.CVSSScore,
		"fix_version":   f.FixVersion,
		"fix_commit":    f.FixCommit,
		"resolution":    string(f.Resolution),
		"assignee":      f.Assignee,
		"missed_count":  f.MissedCount,
		"dup_check":     f.DupCheck,
	}
}
