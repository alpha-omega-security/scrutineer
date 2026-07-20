package web

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

// autoEnqueueFocusAreaDeepDives turns a completed threat-model into one
// security-deep-dive per configured input-processing subsystem. A failed
// threat-model falls back to one unscoped deep-dive so a runner error does not
// suppress the batch's audit coverage. The complete, normalized focus area is
// snapshotted on every child scan so later edits to scan_config cannot change
// already queued work.
func (s *Server) autoEnqueueFocusAreaDeepDives(scan *db.Scan) {
	if scan == nil || scan.SkillName != threatModelSkillName ||
		(scan.Status != db.ScanDone && scan.Status != db.ScanFailed) {
		return
	}

	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", deepDiveSkillName, true).First(&skill).Error; err != nil {
		s.Log.Warn("focus-area deep dives: skill unavailable", "scan", scan.ID, "err", err)
		return
	}

	group := scan.ScanGroup
	if group == "" {
		// A manually launched threat-model has no group. A stable derived
		// group makes the completion hook idempotent if it is called again.
		group = fmt.Sprintf("focus-%d", scan.ID)
	}
	if scan.Status == db.ScanFailed {
		s.Log.Warn("focus-area deep dives: threat-model failed; enqueueing unscoped fallback", "scan", scan.ID)
		s.enqueueFocusAreaDeepDive(scan, skill.ID, group, "")
		return
	}

	var repo db.Repository
	if err := s.DB.Select("id, scan_config").First(&repo, scan.RepositoryID).Error; err != nil {
		s.Log.Warn("focus-area deep dives: load repository", "scan", scan.ID, "err", err)
		return
	}
	config, err := repoconfig.Parse(repo.ScanConfig)
	if err != nil {
		s.Log.Warn("focus-area deep dives: invalid scan config", "scan", scan.ID, "err", err)
		return
	}
	if len(config.FocusAreas) == 0 {
		// Preserve normal coverage until a repository has a useful partition.
		s.enqueueFocusAreaDeepDive(scan, skill.ID, group, "")
		return
	}
	for _, area := range config.FocusAreas {
		raw, err := repoconfig.EncodeFocusAreaJSON(area)
		if err != nil {
			s.Log.Warn("focus-area deep dives: encode area", "scan", scan.ID, "area", area.Name, "err", err)
			continue
		}
		s.enqueueFocusAreaDeepDive(scan, skill.ID, group, raw)
	}
}

func (s *Server) enqueueFocusAreaDeepDive(parent *db.Scan, skillID uint, group, focusArea string) {
	s.agentEnqueueMu.Lock()
	defer s.agentEnqueueMu.Unlock()

	var existing int64
	if err := s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_id = ? AND scan_group = ? AND sub_path = ? AND ref = ? AND focus_area = ? AND status IN ?",
			parent.RepositoryID, skillID, group, parent.SubPath, parent.Ref, focusArea,
			[]db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanDone}).
		Count(&existing).Error; err != nil {
		s.Log.Warn("focus-area deep dives: check existing", "scan", parent.ID, "err", err)
		return
	}
	if existing > 0 {
		return
	}
	if _, err := s.enqueueSkillWith(context.Background(), parent.RepositoryID, skillID, ScanOpts{
		Model:          parent.Model,
		Effort:         parent.Effort,
		Profile:        parent.Profile,
		SubPath:        parent.SubPath,
		Ref:            parent.Ref,
		RescanMode:     parent.RescanMode,
		DiffBaseScanID: parent.DiffBaseScanID,
		ScanGroup:      group,
		FocusArea:      focusArea,
	}); err != nil {
		name := "repository"
		if focusArea != "" {
			var area repoconfig.FocusArea
			if err := json.Unmarshal([]byte(focusArea), &area); err == nil && strings.TrimSpace(area.Name) != "" {
				name = area.Name
			}
		}
		s.Log.Warn("focus-area deep dives: enqueue", "scan", parent.ID, "area", name, "err", err)
	}
}
