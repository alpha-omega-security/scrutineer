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
	cfg, err := repoconfig.Parse(repo.ScanConfig)
	if err != nil {
		http.Error(w, "scan config is not valid YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	pattern, ok := ignoredPathPattern(w, r)
	if !ok {
		return
	}
	if slices.Contains(cfg.Skip, pattern) {
		setFlash(w, Flash{Category: "success", Title: "Ignored path already exists"})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
		return
	}
	cfg.Skip = append(cfg.Skip, pattern)
	config, err := repoconfig.NormaliseConfig(cfg)
	if err != nil {
		http.Error(w, "scan config is not valid: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.saveScanConfig(repo.ID, config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	setFlash(w, Flash{Category: "success", Title: "Ignored path added"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
}

func ignoredPathPattern(w http.ResponseWriter, r *http.Request) (string, bool) {
	raw := r.FormValue("pattern")
	if strings.TrimSpace(raw) == "" {
		http.Error(w, "ignored path pattern is required", http.StatusBadRequest)
		return "", false
	}
	pattern, err := repoconfig.NormaliseSkipPattern(raw)
	if err != nil {
		http.Error(w, "ignored path pattern is not valid: "+err.Error(), http.StatusBadRequest)
		return "", false
	}
	return pattern, true
}

func (s *Server) repoIgnoredPathDelete(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	cfg, err := repoconfig.Parse(repo.ScanConfig)
	if err != nil {
		http.Error(w, "scan config is not valid YAML: "+err.Error(), http.StatusBadRequest)
		return
	}
	pattern, ok := ignoredPathPattern(w, r)
	if !ok {
		return
	}
	before := len(cfg.Skip)
	cfg.Skip = slices.DeleteFunc(cfg.Skip, func(skip string) bool {
		return skip == pattern
	})
	if len(cfg.Skip) == before {
		setFlash(w, Flash{Category: "warning", Title: "Ignored path was not configured"})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d%s", repo.ID, scanConfigTab))
		return
	}
	config, err := repoconfig.NormaliseConfig(cfg)
	if err != nil {
		http.Error(w, "scan config is not valid: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.saveScanConfig(repo.ID, config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

func repoIgnoredPaths(repo db.Repository) []string {
	cfg, err := repoconfig.Parse(repo.ScanConfig)
	if err != nil {
		return nil
	}
	return cfg.Skip
}

func (s *Server) saveScanConfig(repoID uint, config string) error {
	return s.DB.Model(&db.Repository{}).Where("id = ?", repoID).
		Update("scan_config", config).Error
}
