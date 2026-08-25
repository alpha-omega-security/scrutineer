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

// autoEnqueueFindingDedup is wired onto Worker.OnScanFinalized, and onto
// Worker.OnScanGroupSettled for scans launched as part of a batch.
// The worker calls it once after a scan completes and its findings are
// committed. We enqueue a repository-scoped finding-dedup run only when all
// three conditions the dedup pass needs to be worth its model spend hold:
//
//  1. The batch this scan belongs to has drained: every other scan sharing
//     its scan_group has left the in-flight set. See
//     hasOutstandingBatchSiblings. An ungrouped scan has nothing to wait for.
//  2. A curated LLM audit (security-deep-dive, vuln-scan or
//     advisory-deep-dive) that is not a fix-validation anchor produced at
//     least one *new* finding. Re-observed findings keep the scan_id of the
//     run that first created them, so counting findings by scan_id counts
//     exactly the new rows. Nothing new means nothing fresh to dedup.
//  3. The repository now holds at least two open non-scanner findings in
//     total (the new rows count toward this). Dedup needs a pair to compare,
//     but the pair need not predate this scan: a first-ever audit that emits
//     several findings describing the same bug from different subagent angles
//     is exactly what dedup exists to collapse.
//
// Condition 1 is evaluated first, and for a grouped scan condition 2 is
// evaluated over the whole cohort rather than over the sibling that happened
// to arrive last. Which sibling that is carries no meaning, and gating the
// batch on it turns "run fewer times" into "sometimes never run": it may have
// produced no new findings, it may not be an LLM audit at all
// (enqueueDiffRescanGroup puts recon, embedded-native, threat-model and
// semgrep in the same scan_group as the fanned-out deep dives), or it may
// have failed or been
// cancelled. In each case every earlier sibling has already suppressed, so
// skipping here would drop a pass that main would have run.
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
	if scan == nil || scan.BaselineScanID != nil {
		return
	}

	if s.hasOutstandingBatchSiblings(scan) {
		return
	}

	// An ungrouped scan speaks only for itself, so it has to qualify on its
	// own. A grouped one answers for the cohort and is checked below.
	if scan.ScanGroup == "" && !isLLMAuditSkill(scan.SkillName) {
		return
	}

	newFindings, err := s.countNewAuditFindings(scan)
	if err != nil {
		s.Log.Warn("auto-enqueue finding-dedup: count new findings",
			"scan", scan.ID, "repo", scan.RepositoryID, "err", err)
		return
	}
	if newFindings == 0 {
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

// countNewAuditFindings counts the findings created by the scans entitled to
// trigger a dedup pass. Re-observed findings keep the scan_id of the run that
// first created them, so counting rows by scan_id counts exactly the new ones.
//
// For an ungrouped scan that is the scan itself. For a grouped one it is every
// curated LLM audit in the cohort that is not a fix-validation anchor: the
// batch is one logical unit of work, so what it produced as a whole is what
// decides whether a pass is worth running.
func (s *Server) countNewAuditFindings(scan *db.Scan) (int64, error) {
	q := s.DB.Model(&db.Finding{})
	if scan.ScanGroup == "" {
		q = q.Where("scan_id = ?", scan.ID)
	} else {
		cohort := s.DB.Model(&db.Scan{}).Select("id").
			Where("scan_group = ?", scan.ScanGroup).
			Where("skill_name IN ?", llmAuditSkillNames()).
			Where("baseline_scan_id IS NULL")
		q = q.Where("scan_id IN (?)", cohort)
	}
	var n int64
	err := q.Count(&n).Error
	return n, err
}

// hasOutstandingBatchSiblings reports whether any other scan in this scan's
// ScanGroup is still in flight. A batch of focus-area deep dives is launched
// as one cohort (focus_area_deep_dive.go), and dedup compares the repository's
// open findings pairwise, so running it per sibling completion spends a model
// pass on a working set that is still filling up.
//
// The in-flight guard in enqueueRepoScopedSkillIfIdle does not cover this on
// its own: it only suppresses while a dedup is queued or running, so the
// moment one completes between two sibling completions the gate reopens and
// the next sibling enqueues another. That it usually collapses to a single
// pass today is incidental — it depends on the dedup still sitting behind the
// batch in the queue, i.e. on worker saturation rather than on the batch being
// finished.
//
// "In flight" has to include paused: a sibling parked on a rate limit will
// resume and file more findings, so treating it as drained fires the pass
// early against a half-filled working set. The scan being settled is excluded
// by id — its own terminal status may not be committed yet when the hook runs,
// and counting itself would stall the batch forever. Scans with no ScanGroup
// were not launched as a batch and keep the previous behaviour.
func (s *Server) hasOutstandingBatchSiblings(scan *db.Scan) bool {
	if scan.ScanGroup == "" {
		return false
	}
	return s.hasOpenScan("scan_group = ? AND id <> ?", scan.ScanGroup, scan.ID)
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
	if err := s.enqueueRepoScopedSkillIfIdle(ctx, repoID, skill.ID); err != nil {
		s.Log.Warn("auto-enqueue finding-dedup",
			"repo", repoID, "skill", findingDedupSkillName, "err", err)
	}
}

// hasOpenRepoScopedScan returns true when a queued or running repository-scoped
// scan (no finding attached) of the given skill already exists for the repo at
// the same sub-path. Mirrors hasOpenFindingScopedScan for repo-wide passes like
// finding-dedup. The sub_path term keeps two different monorepo sub-packages
// from colliding on one skill's conflict check: activesupport and actionpack
// can each run the same skill concurrently. Pass "" for a repo-root scan.
func (s *Server) hasOpenRepoScopedScan(repoID, skillID uint, subPath string) bool {
	return s.hasOpenScan("repository_id = ? AND skill_id = ? AND finding_id IS NULL AND COALESCE(sub_path, '') = ?", repoID, skillID, subPath)
}
