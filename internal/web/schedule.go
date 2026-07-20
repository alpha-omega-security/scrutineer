package web

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	"gorm.io/gorm"

	"scrutineer/internal/db"
)

// ScheduleOff disables scheduled scans for a repository even when a global
// default schedule is configured. An empty repo schedule inherits the global
// setting instead.
const ScheduleOff = "off"

// scheduleKind marks the scans-list rows the scheduler writes when it decides
// not to run (remote HEAD unchanged, scan in flight, ...). Such rows are
// created directly in a terminal status and never enter the queue.
const scheduleKind = "schedule"

// schedulerTick is how often the scheduler re-evaluates every repository's
// schedule. Due-ness is driven by the persisted NextScheduledScanAt, so the
// tick interval only bounds the firing latency, not the cadence.
const schedulerTick = time.Minute

// ScheduleNext validates a scan-schedule value, the "daily"/"weekly"
// presets or anything cron.ParseStandard accepts (5-field cron expressions
// and @-descriptors), and returns its next firing after the given time.
// Callers filter "" and "off" before parsing; validation-only callers
// discard the time.
func ScheduleNext(expr string, after time.Time) (time.Time, error) {
	switch expr {
	case "daily":
		expr = "@daily"
	case "weekly":
		expr = "@weekly"
	}
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(after), nil
}

// StartScheduler runs the recurring-scan loop until ctx is cancelled.
// Started from main in its own goroutine, alongside the queue.
func (s *Server) StartScheduler(ctx context.Context) {
	t := time.NewTicker(schedulerTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.scheduleTick(ctx, now)
		}
	}
}

// scheduleTick advances every repository's schedule state: it backfills
// NextScheduledScanAt where a schedule applies but no due time is set (new
// repos, schedule edits, global-default changes all reset it to null and
// let the tick recompute), clears it where scheduling no longer applies, and
// fires repositories that are due. Firing and recomputing the next due time
// are decoupled from the outcome: a skipped run still advances the clock.
// Only repositories whose due time is unset or reached are loaded, so the
// NextScheduledScanAt index does the filtering instead of a full-table walk;
// future-dated repos are nothing-to-do this tick and stay out of the query.
func (s *Server) scheduleTick(ctx context.Context, now time.Time) {
	global, _ := db.GetSetting(s.DB, db.SettingScanSchedule)
	var repos []db.Repository
	if err := s.DB.Select("id, url, name, scan_schedule, upstream_url, next_scheduled_scan_at").
		Where("next_scheduled_scan_at IS NULL OR next_scheduled_scan_at <= ?", now).
		Find(&repos).Error; err != nil {
		s.Log.Error("scheduler: list repositories", "err", err)
		return
	}
	for _, repo := range repos {
		expr := repo.ScanSchedule
		if expr == "" {
			expr = global
		}
		if expr == "" || expr == ScheduleOff {
			if repo.NextScheduledScanAt != nil {
				if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
					UpdateColumn("next_scheduled_scan_at", nil).Error; err != nil {
					s.Log.Error("scheduler: clear next_scheduled_scan_at", "repo", repo.Name, "err", err)
				}
			}
			continue
		}
		next, err := ScheduleNext(expr, now)
		if err != nil {
			// Save paths validate, so this only happens on hand-edited
			// data; skip rather than firing on a schedule we can't read.
			s.Log.Warn("scheduler: invalid schedule", "repo", repo.Name, "schedule", expr, "err", err)
			continue
		}
		if repo.NextScheduledScanAt != nil {
			s.runScheduledScan(ctx, repo)
		}
		if err := s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
			UpdateColumn("next_scheduled_scan_at", next).Error; err != nil {
			s.Log.Error("scheduler: advance next_scheduled_scan_at", "repo", repo.Name, "err", err)
		}
	}
}

// runScheduledScan performs one scheduled firing for repo: sync from the
// upstream when one is configured, then compare the remote HEAD against the
// most recent completed scan's commit and either record a skip or enqueue a
// diff-rescan group (which falls back to full coverage when no baseline
// exists, e.g. on a never-scanned repository).
func (s *Server) runScheduledScan(ctx context.Context, repo db.Repository) {
	var inflight int64
	if err := s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND status IN ?", repo.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused}).
		Count(&inflight).Error; err != nil {
		s.Log.Error("scheduler: count in-flight scans", "repo", repo.Name, "err", err)
		return
	}
	if inflight > 0 {
		s.recordScheduledSkip(repo, fmt.Sprintf("%d scan(s) still queued or running", inflight))
		return
	}
	if repo.UpstreamURL != "" {
		if err := s.syncUpstream(ctx, repo.URL, repo.UpstreamURL); err != nil {
			s.recordScheduledSkip(repo, "upstream sync failed: "+err.Error())
			return
		}
	}
	head, err := s.resolveRemoteHead(ctx, repo)
	if err != nil {
		s.recordScheduledSkip(repo, "remote HEAD lookup failed: "+err.Error())
		return
	}
	var last db.Scan
	err = s.DB.Select("id, `commit`").
		Where("repository_id = ? AND status = ? AND `commit` <> ''", repo.ID, db.ScanDone).
		Order("id desc").First(&last).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		// Only a confirmed empty history may fall through to the rescan:
		// treating a lock or connection failure as "never scanned" would
		// fire a full rescan off a transient error.
		s.Log.Error("scheduler: look up last completed scan", "repo", repo.Name, "err", err)
		return
	}
	if err == nil && last.Commit == head {
		s.recordScheduledSkip(repo, fmt.Sprintf("no new commits since %.12s", head))
		return
	}
	n, err := s.enqueueDiffRescanGroup(ctx, repo.ID, "", "")
	if err != nil {
		s.recordScheduledSkip(repo, "enqueue failed: "+err.Error())
		return
	}
	s.Log.Info("scheduled scan enqueued", "repo", repo.Name, "scans", n)
}

// recordScheduledSkip writes the visible trace of a scheduled run that did
// not enqueue anything: a terminal `skipped` scan whose Error carries the
// reason, so the scans list answers "why did nothing run last night".
func (s *Server) recordScheduledSkip(repo db.Repository, reason string) {
	now := time.Now()
	// Collapse consecutive identical skips: an idle repo on a tight schedule
	// would otherwise write one skipped row per tick forever. When the newest
	// scan for this repo is already an identical scheduled skip, drop it so a
	// single row survives, refreshed to the latest firing. A real scan in
	// between ends the run and keeps its row (Select stays narrow so the
	// lookup never pulls the log/report/prompt text columns).
	var prev db.Scan
	if err := s.DB.Select("id, kind, status, error").
		Where("repository_id = ?", repo.ID).Order("id desc").First(&prev).Error; err == nil &&
		prev.Kind == scheduleKind && prev.Status == db.ScanSkipped && prev.Error == reason {
		if err := s.DB.Delete(&db.Scan{}, prev.ID).Error; err != nil {
			s.Log.Error("scheduler: collapse skip", "repo", repo.Name, "err", err)
		}
	}
	scan := db.Scan{
		RepositoryID:   repo.ID,
		Kind:           scheduleKind,
		Status:         db.ScanSkipped,
		StatusPriority: db.StatusPriorityFor(db.ScanSkipped),
		Error:          reason,
		StartedAt:      &now,
		FinishedAt:     &now,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		s.Log.Error("scheduler: record skip", "repo", repo.Name, "err", err)
		return
	}
	s.Log.Info("scheduled scan skipped", "repo", repo.Name, "reason", reason)
}
