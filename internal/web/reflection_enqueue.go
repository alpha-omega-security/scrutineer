package web

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// Queue once per successful root triage. The worker's dynamic preflight waits
// for this invocation's children, including failed/cancelled stages, to settle.
func (s *Server) autoEnqueueReflection(scan *db.Scan) {
	if scan == nil || scan.SkillName != "triage" || scan.Status != db.ScanDone || scan.SubPath != "" || scan.Ref != "" {
		return
	}
	s.agentEnqueueMu.Lock()
	defer s.agentEnqueueMu.Unlock()
	if err := s.enqueueReflection(scan); err != nil {
		s.Log.Warn("auto-enqueue reflect", "scan", scan.ID, "err", err)
	}
}

func (s *Server) enqueueReflection(triage *db.Scan) error {
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", "reflect", true).First(&skill).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	var n int64
	if err := s.DB.Model(&db.Scan{}).Where("repository_id = ? AND triage_scan_id = ? AND skill_name = ?", triage.RepositoryID, triage.ID, "reflect").Count(&n).Error; err != nil {
		return err
	}
	if n != 0 {
		return nil
	}
	if err := s.DB.Model(&db.Scan{}).Where("repository_id = ? AND triage_scan_id = ? AND sub_path = '' AND ref = ''", triage.RepositoryID, triage.ID).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	var repo db.Repository
	if err := s.DB.Select("id, threat_model").First(&repo, triage.RepositoryID).Error; err != nil {
		return err
	}
	if strings.TrimSpace(repo.ThreatModel) == "" {
		if err := s.DB.Model(&db.Scan{}).Where("repository_id = ? AND triage_scan_id = ? AND skill_name = ? AND sub_path = '' AND ref = ''", triage.RepositoryID, triage.ID, threatModelSkillName).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
	_, err := s.enqueueSkillWith(context.Background(), triage.RepositoryID, skill.ID, ScanOpts{TriageScanID: &triage.ID})
	return err
}
