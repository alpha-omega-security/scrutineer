package web

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"scrutineer/internal/coverage"
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

// markThreatModelUpdate records why the repository threat model was or was
// not refreshed from this scan. It is a completeness statement about the
// scan, so it lands inside the coverage record rather than beside it; a scan
// staged by the worker already has a record here, and this merges into it
// without disturbing the worker's own verdict.
func (s *Server) markThreatModelUpdate(scan *db.Scan, state string, material bool, reason string) {
	rec, _ := coverage.Parse(scan.Coverage)
	rec.ThreatModel = &coverage.ThreatModelState{Update: state, Material: material, Reason: reason}
	// Marshal defaults Completeness on its own copy, so a scan with no prior
	// coverage would store "unknown" in the blob and leave the column empty.
	// Default here instead, and both come from this one value.
	if rec.Completeness == "" {
		rec.Completeness = coverage.CompletenessUnknown
	}
	raw, err := coverage.Marshal(rec)
	if err != nil {
		s.Log.Warn("threat-model update: marshal coverage", "scan", scan.ID, "err", err)
		return
	}
	scan.Coverage = raw
	scan.Completeness = rec.Completeness
	if err := s.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).
		Updates(map[string]any{"coverage": scan.Coverage, "completeness": scan.Completeness}).Error; err != nil {
		s.Log.Warn("threat-model update: save coverage", "scan", scan.ID, "err", err)
	}
}
