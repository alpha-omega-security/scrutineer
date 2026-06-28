package web

import (
	"context"

	"scrutineer/internal/db"
)

// findingDedupSkillName is the repository-scoped pass that compares open
// findings and marks ones describing the same vulnerability as duplicates.
// See skills/finding-dedup/SKILL.md.
const findingDedupSkillName = "finding-dedup"

// dedupMinFindings is the fewest open non-scanner findings a repository must
// hold for a dedup pass to be worth running: dedup compares findings pairwise,
// so it needs at least a pair.
const dedupMinFindings = 2

// autoEnqueueFindingDedup is wired onto Worker.OnScanFinalized.
// The worker calls it once after a scan completes and its findings are
// committed. We enqueue a repository-scoped finding-dedup run only when both
// conditions the dedup pass needs to be worth its model spend hold:
//
//  1. The scan is a curated LLM audit (security-deep-dive or vuln-scan) that
//     produced at least one *new* finding. Re-observed findings keep the
//     scan_id of the run that first created them, so counting findings with
//     scan_id == this scan counts exactly the new rows. Nothing new means
//     nothing fresh to dedup.
//  2. The repository now holds at least two open non-scanner findings in
//     total (the new rows count toward this). Dedup needs a pair to compare,
//     but the pair need not predate this scan: a first-ever audit that emits
//     several findings describing the same bug from different subagent angles
//     is exactly what dedup exists to collapse.
//
// "Non-scanner" matches the Findings-tab toggle exactly (nonScannerScanFilter):
// the cheap tool scanners (semgrep, zizmor) and tool imports (CodeQL, Snyk)
// do not count. Both counts read committed state rather than threading a
// tally through the callback, so the decision is independent of parse-time
// races.
//
// Errors are logged and swallowed: failing to enqueue the dedup pass must
// never fail the upstream scan.
func (s *Server) autoEnqueueFindingDedup(scan *db.Scan) {
	// A fix-validation anchor (validate_fix.go) re-runs an audit on a fix ref
	// purely to diff fingerprints; its findings are validation scratch, not a
	// repo's working set, so they must not trigger a dedup pass.
	if scan == nil || !isLLMAuditSkill(scan.SkillName) || scan.BaselineScanID != nil {
		return
	}

	var newFromScan int64
	if err := s.DB.Model(&db.Finding{}).
		Where("scan_id = ?", scan.ID).
		Count(&newFromScan).Error; err != nil {
		s.Log.Warn("auto-enqueue finding-dedup: count new findings",
			"scan", scan.ID, "repo", scan.RepositoryID, "err", err)
		return
	}
	if newFromScan == 0 {
		return
	}

	var openNonScanner int64
	if err := s.DB.Model(&db.Finding{}).
		Where("repository_id = ?", scan.RepositoryID).
		Where(nonScannerScanFilter).
		Where("status NOT IN (" + db.ClosedFindingLifecycleSQLValues() + ")").
		Count(&openNonScanner).Error; err != nil {
		s.Log.Warn("auto-enqueue finding-dedup: count open findings",
			"scan", scan.ID, "repo", scan.RepositoryID, "err", err)
		return
	}
	if openNonScanner < dedupMinFindings {
		return
	}

	s.enqueueFindingDedupForRepo(context.Background(), scan.RepositoryID)
}

// enqueueFindingDedupForRepo looks up the active finding-dedup skill and
// enqueues a repository-scoped run. No dedup skill registered means no
// auto-dedup, which is fine; the workflow degrades to leaving duplicates for
// a human rather than failing the upstream scan. A dedup run already queued
// or in flight for this repo is a no-op so concurrent deep-dives do not pile
// up redundant passes.
func (s *Server) enqueueFindingDedupForRepo(ctx context.Context, repoID uint) {
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", findingDedupSkillName, true).First(&skill).Error; err != nil {
		return
	}
	if s.hasOpenRepoScopedScan(repoID, skill.ID) {
		return
	}
	if _, err := s.enqueueSkillWith(ctx, repoID, skill.ID, ScanOpts{}); err != nil {
		s.Log.Warn("auto-enqueue finding-dedup",
			"repo", repoID, "skill", findingDedupSkillName, "err", err)
	}
}

// hasOpenRepoScopedScan returns true when a queued or running repository-scoped
// scan (no finding attached) of the given skill already exists for the repo.
// Mirrors hasOpenFindingScopedScan for repo-wide passes like finding-dedup.
func (s *Server) hasOpenRepoScopedScan(repoID, skillID uint) bool {
	return s.hasOpenScan("repository_id = ? AND skill_id = ? AND finding_id IS NULL", repoID, skillID)
}
