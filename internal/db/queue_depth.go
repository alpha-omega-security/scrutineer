package db

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"time"

	"gorm.io/gorm"
)

const QueueDepthMaxPoints = 1000

// SQLite compares timestamps as text in the offset each was written in, and two
// UTC offsets are at most 26 hours apart.
const queueDepthOffsetSlack = 26 * time.Hour

var ErrInvalidQueueDepthWindow = errors.New("invalid queue depth window")

type QueueDepthPoint struct {
	At     time.Time `json:"at"`
	Queued int       `json:"queued"`
}

type queueDepthScan struct {
	ID         uint
	Status     ScanStatus
	StartedAt  *time.Time
	FinishedAt *time.Time
	CreatedAt  time.Time
}

type queueDepthEvent struct {
	SubjectID uint
	Kind      string
	CreatedAt time.Time
}

// Resuming clears the pause from a scan's timestamps, so only these events
// tell its paused hours apart from its queued ones.
var queueDepthEventKinds = []string{AuditEventScanStarted, AuditEventScanPaused, AuditEventScanResumeEnqueueFailed, AuditEventScanResumeRequested}

// QueueDepth counts the queued scans at each step from from to to, both
// included.
func QueueDepth(gdb *gorm.DB, from, to time.Time, step time.Duration) ([]QueueDepthPoint, error) {
	if step <= 0 || to.Before(from) {
		return nil, fmt.Errorf("%w: step must be positive and from must not be after to", ErrInvalidQueueDepthWindow)
	}
	// Sub saturates past about 292 years.
	span := to.Sub(from)
	if span == math.MaxInt64 || span/step >= QueueDepthMaxPoints {
		return nil, fmt.Errorf("%w: more than %d points", ErrInvalidQueueDepthWindow, QueueDepthMaxPoints)
	}
	inWindow := gdb.Model(&Scan{}).
		Where("created_at <= ? AND (finished_at IS NULL OR finished_at > ?)", to.Add(queueDepthOffsetSlack), from.Add(-queueDepthOffsetSlack)).
		Session(&gorm.Session{})
	var scans []queueDepthScan
	if err := inWindow.Select("id", "status", "started_at", "finished_at", "created_at").Find(&scans).Error; err != nil {
		return nil, err
	}
	var events []queueDepthEvent
	if err := gdb.Model(&AuditEvent{}).Select("subject_id", "kind", "created_at").
		Where("subject_type = ? AND kind IN ? AND subject_id IN (?)", AuditSubjectScan, queueDepthEventKinds, inWindow.Select("id")).
		Order("id").Find(&events).Error; err != nil {
		return nil, err
	}
	byScan := make(map[uint][]queueDepthEvent)
	for _, ev := range events {
		byScan[ev.SubjectID] = append(byScan[ev.SubjectID], ev)
	}
	var enters, exits []time.Time
	for _, sc := range scans {
		enter := &sc.CreatedAt
		leave := func(at *time.Time) {
			// Imports and scheduler trace rows are written terminal and never queue.
			if at != nil && !at.After(*enter) {
				return
			}
			enters = append(enters, *enter)
			if at != nil {
				exits = append(exits, *at)
			}
		}
		for _, ev := range byScan[sc.ID] {
			switch {
			case ev.Kind == AuditEventScanResumeRequested && enter == nil:
				enter = &ev.CreatedAt
			case ev.Kind != AuditEventScanResumeRequested && enter != nil:
				leave(&ev.CreatedAt)
				enter = nil
			}
		}
		if enter != nil {
			leave(queueExit(sc))
		}
	}
	slices.SortFunc(enters, time.Time.Compare)
	slices.SortFunc(exits, time.Time.Compare)
	points := make([]QueueDepthPoint, 0, span/step+1)
	for at := from; !at.After(to); at = at.Add(step) {
		points = append(points, QueueDepthPoint{At: at, Queued: countUpTo(enters, at) - countUpTo(exits, at)})
	}
	return points, nil
}

// queueExit is nil while sc is queued. A queued row's started_at predates its
// resume.
func queueExit(sc queueDepthScan) *time.Time {
	if sc.Status == ScanQueued {
		return nil
	}
	if sc.StartedAt != nil && (sc.FinishedAt == nil || sc.StartedAt.Before(*sc.FinishedAt)) {
		return sc.StartedAt
	}
	return sc.FinishedAt
}

func countUpTo(sorted []time.Time, at time.Time) int {
	return sort.Search(len(sorted), func(i int) bool { return sorted[i].After(at) })
}
