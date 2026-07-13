package web

import (
	"fmt"
	"net/http"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

const scanConfigTab = "#rt14"

// repoScanConfigSave validates and persists the analyst-authored repository
// guidance. Empty input deliberately clears the configuration.
func (s *Server) repoScanConfigSave(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	config, _, err := repoconfig.Normalise(r.FormValue("scan_config"))
	if err != nil {
		http.Error(w, "scan config is not valid YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("scan_config", config).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Scan config saved"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
}

func (s *Server) repoScanConfigClear(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
		Update("scan_config", "").Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Scan config cleared"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
}
