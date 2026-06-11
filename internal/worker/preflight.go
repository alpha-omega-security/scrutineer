// Prereq gating for skill jobs. A skill declaring scrutineer.requires
// only dispatches when each named upstream skill has a completed scan
// for the same repository; otherwise the job is re-published with a
// delay so the runner picks it up again later.
//
// "Satisfied" is currently any done scan on this repository, regardless
// of commit. URL-keyed skills (packages, advisories, dependents,
// maintainers, metadata) do not have a commit identity, so a uniform
// rule across all prereqs avoids special cases. Triage's commit-aware
// skip set covers the redo-on-new-commit case at a different layer.
//
// A prereq with no scan rows at all on the repository is treated as
// satisfied: triage (or the operator) decided not to enqueue it — e.g.
// dependents on a no-packages repo — and waiting would deadlock the
// dependent skill. The same applies to a prereq skill that is not
// registered or is disabled. Only a prereq that has been enqueued for
// the repository but has no done scan yet defers the job.

package worker

import (
	"context"
	"fmt"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

// preflightSkill checks the skill's declared prereqs and decides whether
// to dispatch now, re-enqueue with a delay, or fail the scan. Returns
// (deferred, err): deferred=true means the caller should return without
// running the handler; the scan stays at status queued and a delayed
// copy of the job is back on the queue.
func (w *Worker) preflightSkill(ctx context.Context, scan *db.Scan, attempt int) (bool, error) {
	if scan.SkillID == nil {
		return false, nil
	}
	var skill db.Skill
	if err := w.DB.First(&skill, *scan.SkillID).Error; err != nil {
		return false, fmt.Errorf("load skill %d for preflight: %w", *scan.SkillID, err)
	}
	requires := skills.SplitPatterns(skill.Requires)
	if len(requires) == 0 {
		return false, nil
	}
	missing := w.unsatisfiedPrereqs(scan.RepositoryID, requires)
	if len(missing) == 0 {
		return false, nil
	}

	maxAttempts := w.MaxPrereqAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxPrereqAttempts
	}
	if attempt >= maxAttempts {
		w.failScanPrereqsUnmet(scan, skill.Name, missing, attempt)
		return true, nil
	}

	base := w.PrereqRetryDelay
	if base <= 0 {
		base = DefaultPrereqRetryDelay
	}
	delay := prereqBackoff(base, attempt)
	prio := PrioScan
	if scan.FindingID != nil {
		prio = PrioFinding
	}
	w.Log.Info("deferring skill on unmet prereqs",
		"scan", scan.ID,
		"skill", skill.Name,
		"missing", missing,
		"attempt", attempt+1,
		"delay", delay)
	if err := w.Queue.EnqueueRetry(ctx, JobSkill, scan.ID, prio, attempt+1, delay); err != nil {
		return false, fmt.Errorf("requeue scan %d on prereq wait: %w", scan.ID, err)
	}
	return true, nil
}

// prereqBackoff doubles the base delay per attempt up to
// MaxPrereqRetryDelay. Prereqs include hour-scale scans (semgrep,
// threat-model) competing for runner slots, so a fixed short delay
// exhausts the attempt budget long before a slow prereq can finish;
// backing off stretches the same attempt count across a much longer
// wall-clock window without hammering the queue.
func prereqBackoff(base time.Duration, attempt int) time.Duration {
	for range attempt {
		base *= 2
		if base >= MaxPrereqRetryDelay {
			return MaxPrereqRetryDelay
		}
	}
	return base
}

// unsatisfiedPrereqs returns the subset of names that have been
// enqueued on the repository but have no done scan yet. A prereq that
// is unregistered, disabled, or has never been enqueued for this repo
// is treated as satisfied; see file header for why.
func (w *Worker) unsatisfiedPrereqs(repoID uint, names []string) []string {
	missing := make([]string, 0, len(names))
	for _, name := range names {
		var skillRow db.Skill
		err := w.DB.Where("name = ?", name).First(&skillRow).Error
		if err != nil {
			w.Log.Warn("prereq skill not registered; treating as satisfied",
				"prereq", name, "repo", repoID)
			continue
		}
		if !skillRow.Active {
			w.Log.Warn("prereq skill disabled; treating as satisfied",
				"prereq", name, "repo", repoID)
			continue
		}
		var total int64
		w.DB.Model(&db.Scan{}).
			Where("repository_id = ? AND skill_name = ?", repoID, name).
			Count(&total)
		if total == 0 {
			continue
		}
		var done int64
		w.DB.Model(&db.Scan{}).
			Where("repository_id = ? AND skill_name = ? AND status = ?", repoID, name, db.ScanDone).
			Count(&done)
		if done == 0 {
			missing = append(missing, name)
		}
	}
	return missing
}

func (w *Worker) failScanPrereqsUnmet(scan *db.Scan, skillName string, missing []string, attempt int) {
	now := time.Now()
	msg := fmt.Sprintf("prereqs not satisfied after %d attempts: %v", attempt, missing)
	scan.Status = db.ScanFailed
	scan.StatusPriority = db.StatusPriorityFor(db.ScanFailed)
	scan.Error = msg
	scan.StartedAt = &now
	scan.FinishedAt = &now
	if err := w.DB.Save(scan).Error; err != nil {
		w.Log.Error("save failed-prereq scan",
			"scan", scan.ID, "skill", skillName, "err", err)
		return
	}
	w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
	w.Log.Warn("scan failed: prereqs not satisfied",
		"scan", scan.ID, "skill", skillName, "missing", missing)
}
