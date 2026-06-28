package web

import (
	"context"

	"scrutineer/internal/db"
)

// revalidateSkillName is the cheap finding classifier auto-enqueued for
// High/Critical findings from the LLM audits (security-deep-dive, vuln-scan)
// and for every finding created via the /v1/import path.
// See skills/revalidate/SKILL.md.
const revalidateSkillName = "revalidate"

// verifySkillName is shared with server.go: the heavier
// reproduction-running checker chained after revalidate when a
// High/Critical finding is judged a true positive.

// autoEnqueueRevalidate is wired onto Worker.OnFindingCreated. The worker
// calls it after persisting each fresh Finding row from a findings-emitting
// scan. We only act for High/Critical findings produced by the curated LLM
// audits (security-deep-dive, vuln-scan): smaller scanners (semgrep, zizmor)
// and finding-scoped re-runs go straight to a human, and lower severities are
// not worth the model spend at this stage of the funnel. vuln-scan is the
// high-recall skill, so its High/Critical output needs the cheap revalidate
// pre-sort most — without it those candidates would sit untriaged in the same
// queue as triaged deep-dive rows. Re-running an audit on the same repo bumps
// the existing finding's seen_count rather than creating a new one, so we
// never enqueue against an observed-again row.
//
// Errors are logged and swallowed: failing to enqueue the pre-sort step
// must never fail the upstream scan.
func (s *Server) autoEnqueueRevalidate(scan *db.Scan, f *db.Finding) {
	if scan == nil || f == nil {
		return
	}
	// A fix-validation anchor (validate_fix.go) re-runs deep-dive on a fix
	// ref only to diff fingerprints; feeding its findings back into the
	// revalidate -> verify funnel would double the spend and race the
	// finding-scoped verify the pipeline already enqueued against that ref.
	if !isLLMAuditSkill(scan.SkillName) || scan.BaselineScanID != nil {
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
	return s.hasOpenFindingScopedScan(findingID, skillID)
}

func (s *Server) hasOpenFindingScopedScan(findingID, skillID uint) bool {
	return s.hasOpenScan("finding_id = ? AND skill_id = ?", findingID, skillID)
}

// hasOpenScan reports whether a queued or running scan matching the given
// scope predicate already exists. Shared by the finding-scoped and
// repo-scoped open-scan guards so the "open" definition (queued or running)
// lives in one place.
func (s *Server) hasOpenScan(scope string, args ...any) bool {
	var n int64
	if err := s.DB.Model(&db.Scan{}).
		Where("status IN ?", []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
		Where(scope, args...).
		Count(&n).Error; err != nil {
		return false
	}
	return n > 0
}

// autoChainVerifyAfterRevalidate is wired onto Worker.OnRevalidateVerdict.
// The cheap revalidate pass acts as the gate for the expensive verify
// step: a finding the model has just judged a real bug at High or
// Critical severity is worth running the reproduction against. Anything
// revalidate downgraded, called noise, or could not decide stays off the
// queue. Severity is read post-adjustment so a Critical revalidate marks
// down to Medium correctly stops the chain.
//
// Errors are logged and swallowed; failing to chain verify must not
// roll back the revalidate verdict.
func (s *Server) autoChainVerifyAfterRevalidate(_ *db.Scan, f *db.Finding, verdict, severity string) {
	if f == nil {
		return
	}
	if verdict != "true_positive" {
		return
	}
	if !db.SeverityAtLeast(severity, "High") {
		return
	}
	s.enqueueVerifyForFinding(context.Background(), f)
}

// enqueueVerifyForFinding looks up the active verify skill and enqueues a
// finding-scoped run, with the same absent-skill, already-queued, and
// log-but-do-not-fail behaviour as the revalidate enqueue.
func (s *Server) enqueueVerifyForFinding(ctx context.Context, f *db.Finding) {
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", verifySkillName, true).First(&skill).Error; err != nil {
		return
	}
	if s.hasOpenFindingScopedScan(f.ID, skill.ID) {
		return
	}
	fid := f.ID
	if _, err := s.enqueueSkillWith(ctx, f.RepositoryID, skill.ID, ScanOpts{FindingID: &fid}); err != nil {
		s.Log.Warn("auto-chain verify after revalidate",
			"finding", f.ID, "repo", f.RepositoryID, "skill", verifySkillName, "err", err)
	}
}
