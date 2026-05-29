package web

import (
	"fmt"
	"net/http"

	"scrutineer/internal/db"
)

// exposureSkillName is the skill the per-finding "Run exposure" action
// invokes. One scan per top-N dependent of the finding's repository.
const exposureSkillName = "exposure"

// exposureTopN caps how many of the finding's library's dependents the
// exposure runner audits per click.
const exposureTopN = 10

// findingExposureRun enqueues one exposure scan per top-N dependent of
// the library this finding lives in. Dependents without a repository
// URL are recorded as under_investigation immediately so the per-
// dependent table is complete; the rest queue at PrioFinding.
func (s *Server) findingExposureRun(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	var scan db.Scan
	if err := s.DB.First(&scan, f.ScanID).Error; err != nil {
		http.Error(w, "scan for finding not found", http.StatusInternalServerError)
		return
	}
	if !findingSupportsExposure(scan) {
		http.Error(w, "dependent exposure is not supported for this finding", http.StatusUnprocessableEntity)
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", exposureSkillName, true).First(&skill).Error; err != nil {
		http.Error(w, "exposure skill is not installed", http.StatusPreconditionFailed)
		return
	}
	var deps []db.Dependent
	s.DB.Where("repository_id = ?", scan.RepositoryID).
		Order("dependent_repos desc, downloads desc").
		Limit(exposureTopN).
		Find(&deps)
	if len(deps) == 0 {
		http.Error(w, "no dependents recorded for this repository", http.StatusUnprocessableEntity)
		return
	}
	model := r.FormValue("model")
	for i := range deps {
		dep := deps[i]
		if dep.RepositoryURL == "" {
			s.recordSkippedExposure(f.ID, dep.ID)
			continue
		}
		if _, err := s.enqueueSkillWith(r.Context(), scan.RepositoryID, skill.ID, ScanOpts{
			Model:       model,
			FindingID:   &f.ID,
			DependentID: &dep.ID,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

// recordSkippedExposure writes an under_investigation row for a
// dependent we cannot audit (no upstream repo URL) so the per-dependent
// table on the finding page stays complete.
func (s *Server) recordSkippedExposure(findingID, dependentID uint) {
	row := db.FindingDependent{
		FindingID:   findingID,
		DependentID: dependentID,
		Status:      db.ExposureUnderInvestigation,
		Rationale:   "skipped: dependent has no repository URL",
	}
	var existing db.FindingDependent
	if err := s.DB.Where("finding_id = ? AND dependent_id = ?", findingID, dependentID).First(&existing).Error; err == nil {
		return
	}
	s.DB.Create(&row)
}
