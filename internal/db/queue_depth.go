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

// QueueDepth counts the queued scans at each step from from to to, both
// included. Resuming or cancelling a paused scan rewrites its timestamps, so
// the count around such a scan is approximate.
func QueueDepth(gdb *gorm.DB, from, to time.Time, step time.Duration) ([]QueueDepthPoint, error) {
	if step <= 0 || to.Before(from) {
		return nil, fmt.Errorf("%w: step must be positive and from must not be after to", ErrInvalidQueueDepthWindow)
	}
	// Sub saturates past about 292 years.
	span := to.Sub(from)
	if span == math.MaxInt64 || span/step >= QueueDepthMaxPoints {
		return nil, fmt.Errorf("%w: more than %d points", ErrInvalidQueueDepthWindow, QueueDepthMaxPoints)
	}
	var scans []Scan
	if err := gdb.Select("status", "started_at", "finished_at", "created_at").
		Where("created_at <= ? AND (finished_at IS NULL OR finished_at > ?)", to.Add(queueDepthOffsetSlack), from.Add(-queueDepthOffsetSlack)).
		Find(&scans).Error; err != nil {
		return nil, err
	}
	var enters, exits []time.Time
	for _, sc := range scans {
		exit := queueExit(sc)
		// Imports and scheduler trace rows are written terminal and never queue.
		if exit != nil && !exit.After(sc.CreatedAt) {
			continue
		}
		enters = append(enters, sc.CreatedAt)
		if exit != nil {
			exits = append(exits, *exit)
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
// resume, and the overage pause stamps no timestamp at all.
func queueExit(sc Scan) *time.Time {
	exit := sc.FinishedAt
	if sc.Status != ScanQueued && sc.StartedAt != nil && (exit == nil || sc.StartedAt.Before(*exit)) {
		exit = sc.StartedAt
	}
	if exit == nil && sc.Status != ScanQueued {
		exit = &sc.CreatedAt
	}
	return exit
}

func countUpTo(sorted []time.Time, at time.Time) int {
	return sort.Search(len(sorted), func(i int) bool { return sorted[i].After(at) })
}
