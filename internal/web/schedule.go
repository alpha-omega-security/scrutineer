package web

import (
	"context"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"

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
func (s *Server) scheduleTick(ctx context.Context, now time.Time) {
	global, _ := db.GetSetting(s.DB, db.SettingScanSchedule)
	var repos []db.Repository
	if err := s.DB.Select("id, url, name, scan_schedule, upstream_url, next_scheduled_scan_at").
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
				s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
					UpdateColumn("next_scheduled_scan_at", nil)
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
		if repo.NextScheduledScanAt != nil && now.Before(*repo.NextScheduledScanAt) {
			continue
		}
		if repo.NextScheduledScanAt != nil {
			s.runScheduledScan(ctx, repo)
		}
		s.DB.Model(&db.Repository{}).Where("id = ?", repo.ID).
			UpdateColumn("next_scheduled_scan_at", next)
	}
}

// runScheduledScan performs one scheduled firing for repo: sync from the
// upstream when one is configured, then compare the remote HEAD against the
// most recent completed scan's commit and either record a skip or enqueue a
// diff-rescan group (which falls back to full coverage when no baseline
// exists, e.g. on a never-scanned repository).
func (s *Server) runScheduledScan(ctx context.Context, repo db.Repository) {
	var inflight int64
	s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND status IN ?", repo.ID, []db.ScanStatus{db.ScanQueued, db.ScanRunning}).
		Count(&inflight)
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
	found := s.DB.Select("id, `commit`").
		Where("repository_id = ? AND status = ? AND `commit` <> ''", repo.ID, db.ScanDone).
		Order("id desc").First(&last).Error == nil
	if found && last.Commit == head {
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
	scan := db.Scan{
		RepositoryID:   repo.ID,
		Kind:           scheduleKind,
		Status:         db.ScanSkipped,
		StatusPriority: db.StatusPriorityFor(db.ScanSkipped),
		Error:          reason,
		FinishedAt:     &now,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		s.Log.Error("scheduler: record skip", "repo", repo.Name, "err", err)
		return
	}
	s.Log.Info("scheduled scan skipped", "repo", repo.Name, "reason", reason)
}
