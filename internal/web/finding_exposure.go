package web

import (
	"fmt"
	"net/http"
	"strings"

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
	var queued, skipped, errored int
	for i := range deps {
		dep := deps[i]
		if dep.RepositoryURL == "" {
			if err := s.recordSkippedExposure(f.ID, dep.ID); err != nil {
				errored++
				continue
			}
			skipped++
			continue
		}
		if _, err := s.enqueueSkillWith(r.Context(), scan.RepositoryID, skill.ID, ScanOpts{
			Model:       model,
			FindingID:   &f.ID,
			DependentID: &dep.ID,
		}); err != nil {
			errored++
			continue
		}
		queued++
	}
	setFlash(w, exposureRunToast(queued, skipped, errored))
	s.redirect(w, r, fmt.Sprintf("/findings/%d", f.ID))
}

func exposureRunToast(queued, skipped, errored int) Flash {
	parts := []string{fmt.Sprintf("%d queued", queued)}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped (no repository URL)", skipped))
	}
	if errored > 0 {
		parts = append(parts, fmt.Sprintf("%d errored", errored))
	}
	category := successKey
	switch {
	case errored > 0:
		category = errorKey
	case queued == 0:
		category = warningKey
	}
	return Flash{Category: category, Title: "Exposure: " + strings.Join(parts, ", ")}
}

// recordSkippedExposure writes an under_investigation row for a
// dependent we cannot audit (no upstream repo URL) so the per-dependent
// table on the finding page stays complete.
func (s *Server) recordSkippedExposure(findingID, dependentID uint) error {
	row := db.FindingDependent{
		FindingID:   findingID,
		DependentID: dependentID,
		Status:      db.ExposureUnderInvestigation,
		Rationale:   "skipped: dependent has no repository URL",
	}
	return db.EnsureFindingDependent(s.DB, row)
}
