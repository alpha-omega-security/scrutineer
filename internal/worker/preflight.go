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
//
// Two content-aware special cases sit on top of the generic rule for the
// dependents skill, which is meaningful only when the repository publishes
// a package:
//  1. A packages re-scan is in progress (done scan + live scan): Package
//     rows are mid delete-recreate, so a zero count is "parsing" not
//     "empty". Treat packages as pending so dependents defers until the
//     re-scan settles.
//  2. packages ran and produced no Package rows: skip dependents as a
//     no-op done, sparing an agent run that could only emit an empty
//     result.
//
// dependents is the sole skill that requires packages, so both checks
// stay name-keyed here instead of in generic machinery.

package worker

import (
	"context"
	"fmt"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

// preflightSkill checks the skill's declared prereqs and decides what to
// do with the scan. Returns (deferred, err): deferred=true means the
// caller should return without running the handler. There are four
// outcomes: dispatch now (false, nil); re-enqueue with a delay while a
// prereq is still in flight (true, nil + a delayed copy back on the
// queue); fail the scan when a prereq has irrecoverably failed
// (true, nil); and skip the scan as a no-op done when the dependents
// skill's `packages` prereq completed but found no published packages
// (true, nil) — see skipScanNoPackages.
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
		// Prereqs satisfied. Apply the two content-aware dependents checks
		// (see file header). The rescan check must come first: during a
		// re-scan Package rows are momentarily zero (mid delete-recreate),
		// so packagesRanButEmpty would fire falsely if called in that
		// window. Appending "packages" to pending lets the defer machinery
		// below re-enqueue dependents until the re-scan settles.
		if skill.Name == "dependents" {
			if w.packagesRescanInFlight(scan.RepositoryID) {
				pending = append(pending, "packages")
			} else if w.packagesRanButEmpty(scan.RepositoryID) {
				w.skipScanNoPackages(scan, skill.Name)
				return true, nil
			}
		}
		if len(pending) == 0 {
			return false, nil
		}
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

// packagesRescanInFlight reports whether a packages re-scan is in progress:
// a prior done scan satisfies the prereq while a new run is still live
// (queued/running/paused). During this window parsePackagesOutput has deleted
// the old Package rows and not yet committed the new ones, so the row count is
// momentarily zero even for a repo that publishes packages. Callers must check
// this before packagesRanButEmpty; see preflightSkill.
func (w *Worker) packagesRescanInFlight(repoID uint) bool {
	var done int64
	w.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_name = ? AND status = ?", repoID, "packages", db.ScanDone).
		Count(&done)
	if done == 0 {
		return false
	}
	var live int64
	w.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_name = ? AND status IN ?",
			repoID, "packages", []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused}).
		Count(&live)
	return live > 0
}

// packagesRanButEmpty reports whether the `packages` skill has a done scan for
// the repository yet produced zero Package rows — i.e. the repo publishes
// nothing. parsePackagesOutput commits Package rows before the packages scan is
// marked done, so done+zero-rows reliably means "ran and found nothing" with no
// read race. Returns false when packages has no done scan: zero rows there means
// "not yet known", not "no packages".
//
// Callers must check packagesRescanInFlight first. During a re-scan Package rows
// are momentarily zero (mid delete-recreate), so this function would incorrectly
// return true in that window.
func (w *Worker) packagesRanButEmpty(repoID uint) bool {
	var done int64
	w.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_name = ? AND status = ?", repoID, "packages", db.ScanDone).
		Count(&done)
	if done == 0 {
		return false
	}
	var pkgs int64
	w.DB.Model(&db.Package{}).Where("repository_id = ?", repoID).Count(&pkgs)
	return pkgs == 0
}

// skipScanNoPackages marks a gated scan as a no-op done: its packages
// prereq completed but the repository publishes no packages, so the skill
// (dependents) has nothing to do. Terminal and not requeued — the same
// shape as failScanPrereqs but a success status, so anything that
// `requires` this skill downstream stays satisfied rather than blocked.
//
// Deliberately leaves Error empty. This is a successful no-op, not a
// failure, and Error renders as a destructive alert (scan_show.html) and an
// "### Error" section (scan_report.go) — both of which would misrepresent
// the skip as a failure. The outcome is identical to dependents running and
// finding nothing: a done scan with no findings. The reason is recorded in
// the log line below for operators who need it.
func (w *Worker) skipScanNoPackages(scan *db.Scan, skillName string) {
	now := time.Now()
	scan.Status = db.ScanDone
	scan.StatusPriority = db.StatusPriorityFor(db.ScanDone)
	scan.StartedAt = &now
	scan.FinishedAt = &now
	if err := w.DB.Save(scan).Error; err != nil {
		w.Log.Error("save skipped-no-packages scan",
			"scan", scan.ID, "skill", skillName, "err", err)
		return
	}
	w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
	w.Log.Info("scan skipped: repository publishes no packages",
		"scan", scan.ID, "skill", skillName)
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
