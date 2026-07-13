package web

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"scrutineer/internal/db"
)

const materialThreatModelFileThreshold = 10

type threatModelDiffStats struct {
	ChangedFiles int                      `json:"changed_files"`
	Files        []threatModelChangedFile `json:"files"`
}

type threatModelChangedFile struct {
	Path string `json:"path"`
	Old  string `json:"old"`
}

func (s *Server) autoUpdateThreatModel(scan *db.Scan) {
	if scan == nil || scan.Status != db.ScanDone || scan.SkillName != threatModelSkillName || strings.TrimSpace(scan.Report) == "" {
		return
	}
	if scan.SubPath != "" || scan.Ref != "" {
		s.markThreatModelUpdate(scan, "skipped_non_default_scope", false, "only root default-branch threat-model scans update the repository model")
		return
	}
	updateReason := "full threat-model scan"
	if scan.RescanMode == db.ScanRescanModeDiff {
		material, reason := threatModelDiffMaterial(scan.DiffStats)
		if !material {
			s.markThreatModelUpdate(scan, "skipped_small_diff", false, reason)
			return
		}
		updateReason = reason
	}

	model, err := normaliseThreatModel(scan.Report)
	if err != nil {
		s.markThreatModelUpdate(scan, "skipped_invalid_report", false, err.Error())
		s.Log.Warn("threat-model update: invalid report", "scan", scan.ID, "err", err)
		return
	}
	if err := s.DB.Model(&db.Repository{}).Where("id = ?", scan.RepositoryID).Update("threat_model", model).Error; err != nil {
		s.markThreatModelUpdate(scan, "skipped_update_error", false, err.Error())
		s.Log.Warn("threat-model update: save repository model", "scan", scan.ID, "repo", scan.RepositoryID, "err", err)
		return
	}
	s.markThreatModelUpdate(scan, "updated", true, updateReason)
}

func threatModelDiffMaterial(raw string) (bool, string) {
	var stats threatModelDiffStats
	if err := json.Unmarshal([]byte(raw), &stats); err != nil {
		return true, "diff metadata unavailable; updating conservatively"
	}
	changed := stats.ChangedFiles
	if changed == 0 {
		changed = len(stats.Files)
	}
	if changed >= materialThreatModelFileThreshold {
		return true, fmt.Sprintf("diff changed %d files", changed)
	}
	for _, f := range stats.Files {
		if p, ok := materialThreatModelPath(f.Path, f.Old); ok {
			return true, "changed material path " + p
		}
	}
	return false, "changed files do not affect known threat-model material paths"
}

func materialThreatModelPath(paths ...string) (string, bool) {
	for _, path := range paths {
		clean := strings.ToLower(filepath.ToSlash(strings.TrimSpace(path)))
		if clean == "" {
			continue
		}
		base := filepath.Base(clean)
		if strings.HasPrefix(base, "security.") || strings.HasPrefix(base, "threat") {
			return path, true
		}
		for _, marker := range []string{
			"security", "threat", "auth", "login", "session", "token",
			"permission", "policy", "acl", "access", "route", "router",
			"handler", "controller", "middleware", "endpoint", "graphql",
			"proto", "openapi", "parser", "parse", "decode", "deserialize",
			"serializ", "validate", "config", "setting", "feature", "flag",
			"build", "cmake", "makefile", "dockerfile", "containerfile",
		} {
			if strings.Contains(clean, marker) {
				return path, true
			}
		}
	}
	return "", false
}

func (s *Server) markThreatModelUpdate(scan *db.Scan, state string, material bool, reason string) {
	var coverage map[string]any
	if err := json.Unmarshal([]byte(scan.Coverage), &coverage); err != nil || coverage == nil {
		coverage = map[string]any{}
	}
	coverage["threat_model_update"] = state
	coverage["threat_model_material"] = material
	if reason != "" {
		coverage["threat_model_update_reason"] = reason
	}
	b, err := json.Marshal(coverage)
	if err != nil {
		s.Log.Warn("threat-model update: marshal coverage", "scan", scan.ID, "err", err)
		return
	}
	scan.Coverage = string(b)
	if err := s.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("coverage", scan.Coverage).Error; err != nil {
		s.Log.Warn("threat-model update: save coverage", "scan", scan.ID, "err", err)
	}
}
