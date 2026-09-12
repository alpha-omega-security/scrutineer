package web

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

var errExploratoryAuditExists = errors.New("triage already has an exploratory audit")

func (s *Server) validateExploratoryEnqueue(scan *db.Scan, skill *db.Skill) error {
	if err := worker.ValidateExploration(scan, skill.Name); err != nil {
		return err
	}
	if scan.ExplorationMode == "" {
		return nil
	}
	if err := s.Worker.ValidateExplorationRunner(skill.Name); err != nil {
		return err
	}
	_, err := worker.ExplorationInstructions(skill)
	return err
}

// Recheck after INSERT has acquired the write lock, before committing or
// enqueueing. Explicit retries have a parent and are deliberately allowed.
func checkExploratoryDuplicate(tx *gorm.DB, scan *db.Scan) error {
	if scan.ExplorationMode == "" || scan.TriageScanID == nil || scan.ParentScanID != nil {
		return nil
	}
	var count int64
	if err := tx.Model(&db.Scan{}).Where("id <> ? AND triage_scan_id = ? AND exploration_mode <> ''", scan.ID, *scan.TriageScanID).
		Count(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return errExploratoryAuditExists
	}
	return nil
}

// Hashing the triage identity samples one third of runs without rolling again
// on completion-hook redelivery or a threat-model retry.
func selectExploratoryAudit(triageID uint) bool {
	const sampleDenominator = 3
	sum := sha256.Sum256(fmt.Appendf(nil, "exploratory-audit:%d", triageID))
	return binary.BigEndian.Uint64(sum[:])%sampleDenominator == 0
}

func (s *Server) autoEnqueueExploratoryAudit(parent *db.Scan, skillID uint, group string) {
	if parent.TriageScanID == nil || parent.Status != db.ScanDone ||
		parent.RescanMode == db.ScanRescanModeDiff || parent.BaselineScanID != nil ||
		!selectExploratoryAudit(*parent.TriageScanID) {
		return
	}
	s.agentEnqueueMu.Lock()
	defer s.agentEnqueueMu.Unlock()
	if err := s.enqueueExploratoryAudit(parent, skillID, group); err != nil && !errors.Is(err, errExploratoryAuditExists) {
		s.Log.Warn("exploratory audit: enqueue", "scan", parent.ID, "err", err)
	}
}

func (s *Server) enqueueExploratoryAudit(parent *db.Scan, skillID uint, group string) error {
	var triages int64
	if err := s.DB.Model(&db.Scan{}).Where("id = ? AND repository_id = ? AND skill_name = ? AND sub_path = ? AND ref = ?",
		*parent.TriageScanID, parent.RepositoryID, "triage", parent.SubPath, parent.Ref).Count(&triages).Error; err != nil {
		return err
	}
	if triages == 0 {
		return nil
	}
	var existing int64
	if err := s.DB.Model(&db.Scan{}).Where("triage_scan_id = ? AND exploration_mode <> ''", *parent.TriageScanID).
		Count(&existing).Error; err != nil {
		return err
	}
	// Include failed/cancelled scans: automatic retries must not spend another
	// exploratory audit. An operator can still explicitly retry that scan.
	if existing != 0 {
		return nil
	}
	var planned int64
	if err := s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_id = ? AND scan_group = ? AND triage_scan_id = ? AND sub_path = ? AND ref = ?",
			parent.RepositoryID, skillID, group, *parent.TriageScanID, parent.SubPath, parent.Ref).
		Where("COALESCE(exploration_mode, '') = '' AND status IN ?", []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanDone}).
		Count(&planned).Error; err != nil {
		return err
	}
	if planned == 0 {
		return nil
	}
	_, err := s.enqueueSkillWith(context.Background(), parent.RepositoryID, skillID, ScanOpts{
		Effort: parent.Effort, Profile: parent.Profile, SubPath: parent.SubPath,
		ScopeMode: parent.ScopeMode, Ref: parent.Ref, ScanGroup: group,
		TriageScanID: parent.TriageScanID, ExplorationMode: worker.ExplorationRandomDig,
	})
	return err
}
