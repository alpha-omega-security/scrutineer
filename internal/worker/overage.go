package worker

import (
	"context"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// OveragePauseReason is deliberately separate from account errors and manual
// pauses: an allowed paid-overage event is not an account rejection.
const OveragePauseReason = "Subscription overage: paused by overage policy"

func (w *Worker) ShouldPauseOnOverage() bool {
	if w == nil || !w.PauseOnOverage {
		return false
	}
	w.rlStatusMu.Lock()
	defer w.rlStatusMu.Unlock()
	return w.onOverageLocked() || w.persistedOverageHold && (w.persistedOverageReset == nil || w.persistedOverageReset.After(w.now().UTC()))
}

// overageState combines provider signals with the cached restart hold.
func (w *Worker) overageState() (bool, *time.Time) {
	w.rlStatusMu.Lock()
	defer w.rlStatusMu.Unlock()
	var resets []*time.Time
	for _, info := range w.rlStatus {
		if info.IsUsingOverage {
			resets = append(resets, info.ResetTime())
		}
	}
	if w.persistedOverageHold {
		resets = append(resets, w.persistedOverageReset)
	}
	return w.overageResetState(resets)
}

func (w *Worker) setPersistedOverageHold(active bool, reset *time.Time) {
	w.rlStatusMu.Lock()
	defer w.rlStatusMu.Unlock()
	w.persistedOverageHold = active
	w.persistedOverageReset = reset
}

// Unknown or implausible resets dominate reliable ones and require manual action.
func (w *Worker) overageResetState(resets []*time.Time) (bool, *time.Time) {
	now := w.now().UTC()
	var active, unknown bool
	var latest *time.Time
	for _, reset := range resets {
		if reset != nil && !reset.After(now) {
			continue
		}
		active = true
		if reset == nil || reset.Sub(now) > w.maxRateLimitAutoResumeDelay() {
			unknown = true
			continue
		}
		if latest == nil || reset.After(*latest) {
			value := reset.UTC()
			latest = &value
		}
	}
	if unknown {
		return active, nil
	}
	if !active {
		return false, &now
	}
	return true, latest
}

func (w *Worker) applyOveragePolicy(wasOverage bool) {
	w.overageMu.Lock()
	defer w.overageMu.Unlock()
	if !w.OnOverage() {
		if wasOverage && w.DB != nil {
			now := w.now().UTC()
			if err := w.DB.Model(&db.Scan{}).Where("status = ? AND error LIKE ?", db.ScanPaused, OveragePauseReason+"%").
				Updates(map[string]any{"paused_until": now, errorColumn: appendAutoResume(OveragePauseReason, &now)}).Error; err != nil {
				w.logOverageError(err)
				return
			}
			w.scheduleAccountResumeAt(now)
		}
		if wasOverage {
			w.setPersistedOverageHold(false, nil)
		}
		return
	}
	// Stop all active jobs before attempting persistence; a DB failure must not
	// let them keep consuming paid turns. Explicit user cancellations win.
	w.mu.Lock()
	for _, running := range w.running {
		if running.reason == "" {
			running.reason = OveragePauseReason
			running.cancel()
		}
	}
	w.mu.Unlock()
	_, reset := w.overageState()
	if w.DB != nil {
		if err := w.pauseOverageRows(reset); err != nil {
			w.logOverageError(err)
			return
		}
	}
	w.setPersistedOverageHold(true, reset)
	w.scheduleAccountResumeAtValue(reset)
	if !wasOverage && w.Log != nil {
		w.Log.Info("subscription overage detected; model scans paused")
	}
}

func (w *Worker) logOverageError(err error) {
	if w.Log != nil {
		w.Log.Error("persist overage pause", "err", err)
	}
}

func (w *Worker) scheduleAccountResumeAtValue(reset *time.Time) {
	if reset != nil {
		w.scheduleAccountResumeAt(*reset)
	}
}

func (w *Worker) pauseOverageRows(reset *time.Time) error {
	return w.DB.Transaction(func(tx *gorm.DB) error {
		var queued []db.Scan
		if err := tx.Omit("log", "report").Where("status = ? AND kind IN ?", db.ScanQueued, []string{JobSkill, JobExposure}).Find(&queued).Error; err != nil {
			return err
		}
		now := w.now().UTC()
		for _, scan := range queued {
			result := tx.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanQueued).Updates(map[string]any{
				"status": db.ScanPaused, "status_priority": db.StatusPriorityFor(db.ScanPaused),
				errorColumn: appendAutoResume(OveragePauseReason, reset), "paused_until": reset, "finished_at": &now,
			})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected > 0 {
				scan.Status = db.ScanPaused
				scan.Error = appendAutoResume(OveragePauseReason, reset)
				scan.PausedUntil = reset
				scan.FinishedAt = &now
				if err := db.LogScanEvent(tx, db.AuditEventScanPaused, &scan); err != nil {
					return err
				}
			}
		}
		return tx.Model(&db.Scan{}).Where("status = ? AND error LIKE ?", db.ScanPaused, OveragePauseReason+"%").
			Updates(map[string]any{"paused_until": reset, errorColumn: appendAutoResume(OveragePauseReason, reset)}).Error
	})
}

func (w *Worker) startScanUnlessOverage(scan *db.Scan) error {
	if !w.PauseOnOverage {
		return w.startScan(scan)
	}
	paused, err := w.pauseIfOverage()
	if err != nil {
		return err
	}
	if paused {
		return errScanClaimLost
	}
	return w.startScan(scan)
}

func (w *Worker) preflightSkillUnlessOverage(ctx context.Context, scan *db.Scan, attempt int) (bool, error) {
	if !w.PauseOnOverage {
		return w.preflightSkill(ctx, scan, attempt)
	}
	if paused, err := w.pauseIfOverage(); paused || err != nil {
		return paused, err
	}
	return w.preflightSkill(ctx, scan, attempt)
}

// Only policy-pause writes serialize with reset updates; ordinary dispatch does not.
func (w *Worker) pauseIfOverage() (bool, error) {
	if !w.ShouldPauseOnOverage() {
		return false, nil
	}
	w.overageMu.Lock()
	defer w.overageMu.Unlock()
	active, reset := w.overageState()
	if active {
		if err := w.pauseOverageRows(reset); err != nil {
			return false, err
		}
		w.scheduleAccountResumeAtValue(reset)
	}
	return active, nil
}
