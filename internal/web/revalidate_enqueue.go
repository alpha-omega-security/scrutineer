package web

import (
	"context"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// revalidateSkillName is the cheap finding classifier auto-enqueued for
// High/Critical findings from security-deep-dive and for every finding
// created via the /v1/import path. See skills/revalidate/SKILL.md.
const revalidateSkillName = "revalidate"

// autoEnqueueRevalidate is wired onto Worker.OnFindingCreated. The worker
// calls it after persisting each fresh Finding row from a findings-emitting
// scan. We only act for High/Critical findings produced by
// security-deep-dive: smaller scanners (semgrep, zizmor) and finding-scoped
// re-runs go straight to a human, and lower severities are not worth the
// model spend at this stage of the funnel. Re-running deep-dive on the same
// repo bumps the existing finding's seen_count rather than creating a new
// one, so we never enqueue against an observed-again row.
//
// Errors are logged and swallowed: failing to enqueue the pre-sort step
// must never fail the upstream scan.
func (s *Server) autoEnqueueRevalidate(scan *db.Scan, f *db.Finding) {
	if scan == nil || f == nil {
		return
	}
	if scan.SkillName != deepDiveSkillName {
		return
	}
	if !db.SeverityAtLeast(f.Severity, "High") {
		return
	}
	s.enqueueRevalidateForFinding(context.Background(), f)
}

// enqueueRevalidateForFinding looks up the active revalidate skill and
// enqueues a finding-scoped run. No revalidate skill means no auto-sort,
// which is fine; the workflow degrades to "every finding goes to a human"
// rather than failing the upstream scan. A revalidate run already queued
// or in flight for this finding is also a no-op so re-imports and rescans
// do not pile up duplicate work.
func (s *Server) enqueueRevalidateForFinding(ctx context.Context, f *db.Finding) {
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", revalidateSkillName, true).First(&skill).Error; err != nil {
		return
	}
	if s.hasOpenRevalidate(f.ID, skill.ID) {
		return
	}
	fid := f.ID
	if _, err := s.enqueueSkillWith(ctx, f.RepositoryID, skill.ID, ScanOpts{FindingID: &fid}); err != nil {
		s.Log.Warn("auto-enqueue revalidate",
			"finding", f.ID, "repo", f.RepositoryID, "skill", revalidateSkillName, "err", err)
	}
}

// hasOpenRevalidate returns true when a queued or running revalidate scan
// already exists for the finding. Avoids piling duplicate work onto the
// queue when the same finding is observed by both an import and a rescan,
// or when two findings parsers race in tests.
func (s *Server) hasOpenRevalidate(findingID, skillID uint) bool {
	var n int64
	if err := s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_id = ? AND status IN ?",
			findingID, skillID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
		Count(&n).Error; err != nil && err != gorm.ErrRecordNotFound {
		return false
	}
	return n > 0
}
