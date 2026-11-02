package worker

import (
	"fmt"
	"sync"
	"time"

	"scrutineer/internal/db"
)

// groupSpend tracks the live spend of scans that share a group budget. The
// worker queue runs in one process, so this map sees every running sibling.
// Siblings that finish while others still run stay in it with their final
// cost, which keeps each scan counted exactly once.
type groupSpend struct {
	mu     sync.Mutex
	groups map[string]*groupState
}

type groupState struct {
	limit float64
	// base is the cost already recorded in the DB for scans that were not
	// tracked when the group first registered.
	base  float64
	scans map[uint]*groupScan
}

type groupScan struct {
	cost    float64
	running int
}

func (s *groupState) total() float64 {
	t := s.base
	for _, sc := range s.scans {
		t += sc.cost
	}
	return t
}

// register starts tracking a run of scan id, whose recorded cost is cost. The
// first run of a group calls load for the cap and the DB cost of every other
// scan in it. It returns the cap, 0 when the group has no budget.
func (g *groupSpend) register(group string, id uint, cost float64, load func() (limit, base float64, err error)) (float64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.groups[group]
	joined := st != nil
	if st == nil {
		limit, base, err := load()
		if err != nil || limit <= 0 {
			return 0, err
		}
		st = &groupState{limit: limit, base: base, scans: map[uint]*groupScan{}}
		if g.groups == nil {
			g.groups = map[string]*groupState{}
		}
		g.groups[group] = st
	}
	sc := st.scans[id]
	if sc == nil {
		sc = &groupScan{cost: cost}
		st.scans[id] = sc
		if joined {
			// Its recorded cost is already part of base.
			st.base = max(st.base-cost, 0)
		}
	}
	sc.running++
	return st.limit, nil
}

// update sets the live estimate of a registered scan and returns the group's
// total spend and cap.
func (g *groupSpend) update(group string, id uint, cost float64) (total, limit float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.groups[group]
	if st == nil || st.scans[id] == nil {
		return 0, 0
	}
	st.scans[id].cost = cost
	return st.total(), st.limit
}

// finish records the final cost of one run. The group is dropped once no scan
// in it is running, so a later run reloads finished siblings from the DB.
func (g *groupSpend) finish(group string, id uint, cost float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.groups[group]
	if st == nil || st.scans[id] == nil {
		return
	}
	st.scans[id].cost = cost
	st.scans[id].running--
	for _, sc := range st.scans {
		if sc.running > 0 {
			return
		}
	}
	delete(g.groups, group)
}

// spent returns the tracked total and cap, ok false when the group is not tracked.
func (g *groupSpend) spent(group string) (total, limit float64, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.groups[group]
	if st == nil {
		return 0, 0, false
	}
	return st.total(), st.limit, true
}

// registerGroupSpend tracks a run of scan under its group budget and returns
// the cap, 0 when the group has none. A DB error is logged and leaves the
// group uncapped for this run.
func (w *Worker) registerGroupSpend(scan *db.Scan) float64 {
	if scan.ScanGroup == "" {
		return 0
	}
	limit, err := w.groups.register(scan.ScanGroup, scan.ID, scan.CostUSD, func() (float64, float64, error) {
		limit, err := db.ScanGroupBudgetFor(w.DB, scan.ScanGroup)
		if err != nil || limit <= 0 {
			return 0, 0, err
		}
		base, err := db.ScanGroupSpend(w.DB, scan.ScanGroup, scan.ID)
		return limit, base, err
	})
	if err != nil {
		w.Log.Warn("load group cost cap", "scan", scan.ID, "group", scan.ScanGroup, "err", err)
		return 0
	}
	return limit
}

// groupSpendStatus returns the group's spend and cap, preferring the live
// tracker over the DB. The cap is 0 when the group has no budget.
func (w *Worker) groupSpendStatus(group string) (spent, limit float64) {
	if group == "" {
		return 0, 0
	}
	if spent, limit, ok := w.groups.spent(group); ok {
		return spent, limit
	}
	limit, err := db.ScanGroupBudgetFor(w.DB, group)
	if err != nil || limit <= 0 {
		return 0, 0
	}
	spent, err = db.ScanGroupSpend(w.DB, group, 0)
	if err != nil {
		w.Log.Warn("load group spend", "group", group, "err", err)
		return 0, 0
	}
	return spent, limit
}

// groupCapReached reports whether the scan's group has spent its budget.
func (w *Worker) groupCapReached(scan *db.Scan) bool {
	spent, limit := w.groupSpendStatus(scan.ScanGroup)
	return limit > 0 && spent >= limit
}

// skipIfGroupSpent finishes a queued scan as skipped, without cloning or
// running anything, when its group budget is already spent. It reports whether
// the scan was skipped.
func (w *Worker) skipIfGroupSpent(scan *db.Scan) bool {
	spent, limit := w.groupSpendStatus(scan.ScanGroup)
	if limit <= 0 || spent < limit {
		return false
	}
	reason := fmt.Sprintf("group cost cap $%.2f reached (group spent $%.2f)", limit, spent)
	now := time.Now()
	res := w.DB.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanQueued).
		Updates(db.Scan{
			Status:         db.ScanSkipped,
			StatusPriority: db.StatusPriorityFor(db.ScanSkipped),
			Error:          reason,
			Log:            FormatEvent(Event{Kind: KindText, Text: reason}) + "\n",
			StartedAt:      &now,
			FinishedAt:     &now,
		})
	if res.Error != nil {
		w.Log.Error("save group-capped scan", "scan", scan.ID, "err", res.Error)
		return false
	}
	if res.RowsAffected == 0 {
		return true
	}
	scan.Status = db.ScanSkipped
	scan.StatusPriority = db.StatusPriorityFor(db.ScanSkipped)
	scan.Error = reason
	scan.FinishedAt = &now
	w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
	w.SettleScanGroup(scan)
	w.Log.Info("skipping scan: group cost cap reached", "scan", scan.ID, "group", scan.ScanGroup)
	return true
}
