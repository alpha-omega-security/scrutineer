package worker

import (
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
	active, _, err := w.overageState()
	return active || err != nil
}

// overageState includes persisted policy pauses so a restart cannot dispatch
// fresh work before an outstanding reset. Unknown resets dominate known ones.
func (w *Worker) overageState() (bool, *time.Time, error) {
	now := w.now().UTC()
	var active, unknown bool
	var latest *time.Time
	add := func(reset *time.Time) {
		if reset != nil && !reset.After(now) {
			return
		}
		active = true
		if reset == nil || reset.Sub(now) > w.maxRateLimitAutoResumeDelay() {
			unknown = true
			return
		}
		if latest == nil || reset.After(*latest) {
			value := reset.UTC()
			latest = &value
		}
	}
	w.rlStatusMu.Lock()
	for _, info := range w.rlStatus {
		if info.IsUsingOverage {
			add(info.ResetTime())
		}
	}
	w.rlStatusMu.Unlock()
	if w.DB != nil {
		var paused []db.Scan
		if err := w.DB.Select("paused_until").Where("status = ? AND error LIKE ?", db.ScanPaused, OveragePauseReason+"%").Find(&paused).Error; err != nil {
			return true, nil, err
		}
		for _, scan := range paused {
			add(scan.PausedUntil)
		}
	}
	if unknown {
		return active, nil, nil
	}
	if !active {
		return false, &now, nil
	}
	return true, latest, nil
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
	_, reset, err := w.overageState()
	if err == nil && w.DB != nil {
		err = w.pauseOverageRows(reset)
	}
	if err != nil {
		w.logOverageError(err)
		return
	}
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
	now := w.now().UTC()
	return w.DB.Transaction(func(tx *gorm.DB) error {
		var queued []db.Scan
		if err := tx.Omit("log", "report").Where("status = ? AND kind IN ?", db.ScanQueued, []string{JobSkill, JobExposure}).Find(&queued).Error; err != nil {
			return err
		}
		for _, scan := range queued {
			result := tx.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanQueued).Updates(map[string]any{
				"status": db.ScanPaused, "status_priority": db.StatusPriorityFor(db.ScanPaused),
				errorColumn: appendAutoResume(OveragePauseReason, reset), "finished_at": now, "paused_until": reset,
			})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected > 0 {
				scan.Status = db.ScanPaused
				scan.Error = appendAutoResume(OveragePauseReason, reset)
				scan.FinishedAt = &now
				scan.PausedUntil = reset
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
	w.overageMu.Lock()
	defer w.overageMu.Unlock()
	active, reset, err := w.overageState()
	if err != nil {
		return err
	}
	if active {
		if err := w.pauseOverageRows(reset); err != nil {
			return err
		}
		w.scheduleAccountResumeAtValue(reset)
		return errScanClaimLost
	}
	return w.startScan(scan)
}
