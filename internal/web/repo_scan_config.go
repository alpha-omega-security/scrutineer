package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

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

func (s *Server) repoIgnoredPathAdd(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	cfg, err := scanConfigFromRepo(repo)
	if err != nil {
		http.Error(w, "scan config is not valid YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	pattern := strings.TrimSpace(r.FormValue("pattern"))
	if pattern == "" {
		http.Error(w, "ignored path pattern is required", http.StatusBadRequest)
		return
	}
	if slices.Contains(cfg.Skip, pattern) {
		setFlash(w, Flash{Category: successKey, Title: "Ignored path already exists"})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
		return
	}
	cfg.Skip = append(cfg.Skip, pattern)
	if err := s.saveScanConfig(repo.ID, cfg); err != nil {
		http.Error(w, err.Error(), scanConfigStatus(err))
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Ignored path added"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
}

func (s *Server) repoIgnoredPathDelete(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	cfg, err := scanConfigFromRepo(repo)
	if err != nil {
		http.Error(w, "scan config is not valid YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	pattern := r.FormValue("pattern")
	cfg.Skip = slices.DeleteFunc(cfg.Skip, func(skip string) bool {
		return skip == pattern
	})
	if err := s.saveScanConfig(repo.ID, cfg); err != nil {
		http.Error(w, err.Error(), scanConfigStatus(err))
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Ignored path removed"})
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

func scanConfigFromRepo(repo db.Repository) (repoconfig.Config, error) {
	return repoconfig.Parse(repo.ScanConfig)
}

func repoIgnoredPaths(repo db.Repository) []string {
	cfg, err := scanConfigFromRepo(repo)
	if err != nil {
		return nil
	}
	return cfg.Skip
}

func (s *Server) saveScanConfig(repoID uint, cfg repoconfig.Config) error {
	config, err := repoconfig.NormaliseConfig(cfg)
	if err != nil {
		return fmt.Errorf("scan config is not valid: %w", err)
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", repoID).
		Update("scan_config", config).Error; err != nil {
		return err
	}
	return nil
}

func scanConfigStatus(err error) int {
	if strings.Contains(err.Error(), "scan config is not valid") {
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}
