package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"scrutineer/internal/db"
)

// loadSubproject loads the {sub} subproject, verifying it belongs to repoID.
// Writes a 404 and returns ok=false otherwise.
func (s *Server) loadSubproject(w http.ResponseWriter, r *http.Request, repoID uint) (db.Subproject, bool) {
	subID, _ := strconv.Atoi(r.PathValue("sub"))
	var sub db.Subproject
	if err := s.DB.Where("id = ? AND repository_id = ?", subID, repoID).First(&sub).Error; err != nil {
		http.NotFound(w, r)
		return db.Subproject{}, false
	}
	return sub, true
}

// subprojectShow renders a monorepo sub-package as a first-class entity: its
// own findings (scoped by sub_path), the packages and advisories attributed to
// it, and its disclosure channel (its own, or the repository's as a fallback).
func (s *Server) subprojectShow(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	sub, ok := s.loadSubproject(w, r, repo.ID)
	if !ok {
		return
	}
	var findings []db.Finding
	s.DB.Where("repository_id = ? AND sub_path = ?", repo.ID, sub.Path).
		Order("id desc").Find(&findings)
	var packages []db.Package
	s.DB.Where("subproject_id = ?", sub.ID).Order("downloads desc").Find(&packages)
	var advisories []db.Advisory
	s.DB.Where("subproject_id = ?", sub.ID).Order("published_at desc").Find(&advisories)
	s.render(w, r, "subproject_show.html", map[string]any{
		"Repo":     repo,
		"Sub":      sub,
		"Findings": findings,
		// Registry attribution (packages/advisories) is a kill-switchable
		// feature; gate its display so turning monorepo_attribution off hides
		// per-sub-package links immediately, even before the next reconcile
		// clears any left over from when it was on.
		"Attribution":       s.MonorepoAttribution,
		"Packages":          packages,
		"Advisories":        advisories,
		"DisclosureChannel": db.EffectiveDisclosureChannel(s.DB, repo.ID, sub.Path),
		"OwnChannel":        sub.DisclosureChannel,
	})
}

// subprojectDisclosureChannel overwrites (or clears) a sub-package's own
// disclosure channel. Empty clears it, so routing falls back to the repository
// channel. Mirrors repoDisclosureChannel.
func (s *Server) subprojectDisclosureChannel(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	sub, ok := s.loadSubproject(w, r, repo.ID)
	if !ok {
		return
	}
	value := strings.TrimSpace(r.FormValue("disclosure_channel"))
	if err := s.DB.Model(&db.Subproject{}).Where("id = ?", sub.ID).
		Update("disclosure_channel", value).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d/subprojects/%d", repo.ID, sub.ID))
}
