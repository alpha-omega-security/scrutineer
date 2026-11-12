// Prereq gating for skill jobs. A skill declaring scrutineer.requires
// only dispatches when each named upstream skill has a completed scan
// for the same repository; otherwise the job is re-published with a
// delay so the runner picks it up again later. Group-local prerequisites take
// precedence; when absent, only in-flight repository prerequisites block.
//
// Within that scope, any done scan satisfies the prerequisite, regardless
// of commit. URL-keyed skills (packages, advisories, maintainers,
// metadata) do not have a commit identity, so a uniform
// rule across all prereqs avoids special cases. Triage's commit-aware
// skip set covers the redo-on-new-commit case at a different layer.
//
// A prereq with no scan rows in scope, or an unregistered or disabled skill,
// is treated as satisfied. A prereq that has been enqueued for the
// repository but has no done scan yet defers the job while one is
// still in flight (queued/running/paused); when every attempt has
// reached a terminal failed/cancelled state the dependent fails
// immediately rather than burning the retry budget waiting on
// something that will not recover on its own.

package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/skills"
)

// preflightSkill checks the skill's declared prereqs and decides what to
// do with the scan. Returns (deferred, err): deferred=true means the
// caller should return without running the handler. There are four
// outcomes: dispatch now (false, nil); re-enqueue with a delay while a
// prereq is still in flight (true, nil + a delayed copy back on the
// queue); or fail the scan when a prereq has irrecoverably failed
// (true, nil).
func (w *Worker) preflightSkill(ctx context.Context, scan *db.Scan, attempt int) (bool, error) {
	if scan.SkillID == nil || scan.ExplorationMode != "" {
		return false, nil
	}
	var skill db.Skill
	if err := w.DB.First(&skill, *scan.SkillID).Error; err != nil {
		return false, fmt.Errorf("load skill %d for preflight: %w", *scan.SkillID, err)
	}
	if skill.Name == "reflect" {
		pending, err := w.prepareReflection(scan)
		if err != nil {
			w.failScanPrereqs(scan, skill.Name, err.Error(), nil)
			return true, nil
		}
		if pending {
			return w.deferSkillPrereqs(ctx, scan, &skill, attempt, []string{"triage cohort"})
		}
	}
	requires := skills.SplitPatterns(skill.Requires)
	if len(requires) == 0 {
		return false, nil
	}
	pending, dead, err := w.unsatisfiedPrereqs(scan, requires)
	if err != nil {
		return false, fmt.Errorf("check prereqs for scan %d: %w", scan.ID, err)
	}
	if len(dead) > 0 {
		fallback, err := w.isThreatModelFallback(scan, skill.Name)
		if err != nil {
			return false, err
		}
		if fallback {
			w.Log.Warn("fallback audit proceeding without failed prerequisites", "scan", scan.ID, "prereqs", dead)
			dead = nil
		}
	}
	if len(dead) > 0 {
		w.failScanPrereqs(scan, skill.Name,
			fmt.Sprintf("prereqs failed: %v", dead), dead)
		return true, nil
	}
	if len(pending) == 0 {
		return false, nil
	}
	return w.deferSkillPrereqs(ctx, scan, &skill, attempt, pending)
}

func (w *Worker) isThreatModelFallback(scan *db.Scan, skillName string) (bool, error) {
	if skillName != deepDiveSkillName || scan.FocusArea != "" || scan.FallbackFromScanID == nil {
		return false, nil
	}
	var count int64
	err := w.DB.Model(&db.Scan{}).Where(
		"id = ? AND repository_id = ? AND skill_name = ? AND status = ? AND sub_path = ? AND ref = ?",
		*scan.FallbackFromScanID, scan.RepositoryID, threatModelSkillName, db.ScanFailed, scan.SubPath, scan.Ref,
	).Where("scan_group = ?", scan.ScanGroup).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("load fallback threat-model: %w", err)
	}
	return count == 1, nil
}

func (w *Worker) deferSkillPrereqs(ctx context.Context, scan *db.Scan, skill *db.Skill, attempt int, pending []string) (bool, error) {
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

// unsatisfiedPrereqs uses group-local history when available. Without a
// group-local row, grouped scans wait only for in-flight repository scans.
// Ungrouped scans use the repository's full prerequisite history.
func (w *Worker) unsatisfiedPrereqs(scan *db.Scan, names []string) (pending, dead []string, err error) {
	inFlight := []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused}
	for _, name := range names {
		var skillRow db.Skill
		err = w.DB.Where("name = ?", name).First(&skillRow).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			w.Log.Warn("prereq skill not registered; treating as satisfied",
				"prereq", name, "repo", scan.RepositoryID)
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("load prereq skill %s: %w", name, err)
		}
		if !skillRow.Active {
			w.Log.Warn("prereq skill disabled; treating as satisfied",
				"prereq", name, "repo", scan.RepositoryID)
			continue
		}
		var state prereqState
		state, err = w.scopedPrereqStatus(scan, name, inFlight)
		if err != nil {
			return nil, nil, fmt.Errorf("prereq %s: %w", name, err)
		}
		switch state {
		case prereqPending:
			pending = append(pending, name)
		case prereqDead:
			dead = append(dead, name)
		case prereqAbsent, prereqSatisfied:
		}
	}
	return pending, dead, nil
}

func (w *Worker) scopedPrereqStatus(scan *db.Scan, name string, inFlight []db.ScanStatus) (prereqState, error) {
	if scan.ScanGroup == "" {
		return w.prereqStatus("repository_id = ? AND skill_name = ?",
			[]any{scan.RepositoryID, name}, inFlight)
	}
	state, err := w.prereqStatus("repository_id = ? AND skill_name = ? AND scan_group = ?",
		[]any{scan.RepositoryID, name, scan.ScanGroup}, inFlight)
	if err != nil || state != prereqAbsent {
		return state, err
	}
	var active int64
	if err := w.DB.Model(&db.Scan{}).Where("repository_id = ? AND skill_name = ? AND status IN ?",
		scan.RepositoryID, name, inFlight).Count(&active).Error; err != nil {
		return prereqAbsent, err
	}
	if active > 0 {
		return prereqPending, nil
	}
	return prereqAbsent, nil
}

type prereqState int

const (
	prereqAbsent prereqState = iota
	prereqSatisfied
	prereqPending
	prereqDead
)

func (w *Worker) prereqStatus(where string, args []any, inFlight []db.ScanStatus) (prereqState, error) {
	var total int64
	if err := w.DB.Model(&db.Scan{}).Where(where, args...).Count(&total).Error; err != nil {
		return prereqAbsent, err
	}
	if total == 0 {
		return prereqAbsent, nil
	}
	var done int64
	if err := w.DB.Model(&db.Scan{}).Where(where, args...).Where("status = ?", db.ScanDone).Count(&done).Error; err != nil {
		return prereqAbsent, err
	}
	if done > 0 {
		return prereqSatisfied, nil
	}
	var live int64
	if err := w.DB.Model(&db.Scan{}).Where(where, args...).Where("status IN ?", inFlight).Count(&live).Error; err != nil {
		return prereqAbsent, err
	}
	if live > 0 {
		return prereqPending, nil
	}
	return prereqDead, nil
}

func (w *Worker) failScanPrereqs(scan *db.Scan, skillName, msg string, missing []string) {
	now := time.Now()
	result := w.DB.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanQueued).Updates(map[string]any{
		"status": db.ScanFailed, "status_priority": db.StatusPriorityFor(db.ScanFailed),
		errorColumn: msg, "started_at": now, "finished_at": now, "api_token": "",
	})
	if result.Error != nil {
		w.Log.Error("save failed-prereq scan",
			"scan", scan.ID, "skill", skillName, "err", result.Error)
		return
	}
	if result.RowsAffected == 0 {
		return
	}
	scan.Status = db.ScanFailed
	scan.StatusPriority = db.StatusPriorityFor(db.ScanFailed)
	scan.Error = msg
	scan.StartedAt = &now
	scan.FinishedAt = &now
	scan.APIToken = ""
	w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
	w.Log.Warn("scan failed: prereqs not satisfied",
		"scan", scan.ID, "skill", skillName, "missing", missing)
	w.maybeFireScanFailed(scan)
}
