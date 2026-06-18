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
// registered or is disabled. A prereq that has been enqueued for the
// repository but has no done scan yet defers the job while one is
// still in flight (queued/running/paused); when every attempt has
// reached a terminal failed/cancelled state the dependent fails
// immediately rather than burning the retry budget waiting on
// something that will not recover on its own.

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
	pending, dead := w.unsatisfiedPrereqs(scan.RepositoryID, requires)
	if len(dead) > 0 {
		w.failScanPrereqs(scan, skill.Name,
			fmt.Sprintf("prereqs failed: %v", dead), dead)
		return true, nil
	}
	if len(pending) == 0 {
		return false, nil
	}

	maxAttempts := w.MaxPrereqAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxPrereqAttempts
	}
	if attempt >= maxAttempts {
		w.failScanPrereqs(scan, skill.Name,
			fmt.Sprintf("prereqs not satisfied after %d attempts: %v", attempt, pending), pending)
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
		"pending", pending,
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

// unsatisfiedPrereqs classifies declared prereqs against the
// repository's scan history. A name lands in pending when it has at
// least one in-flight scan (queued/running/paused) and no done scan
// yet — the gate should defer and re-check later. A name lands in
// dead when every scan for it on the repo is terminal but none is
// done — the prereq has irrecoverably failed and the dependent should
// fail now rather than burn the retry budget. A prereq that is
// unregistered, disabled, or has never been enqueued for this repo is
// treated as satisfied; see file header for why.
func (w *Worker) unsatisfiedPrereqs(repoID uint, names []string) (pending, dead []string) {
	inFlight := []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused}
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
		if done > 0 {
			continue
		}
		var live int64
		w.DB.Model(&db.Scan{}).
			Where("repository_id = ? AND skill_name = ? AND status IN ?", repoID, name, inFlight).
			Count(&live)
		if live > 0 {
			pending = append(pending, name)
		} else {
			dead = append(dead, name)
		}
	}
	return pending, dead
}

func (w *Worker) failScanPrereqs(scan *db.Scan, skillName, msg string, missing []string) {
	now := time.Now()
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
