package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"scrutineer/internal/db"
)

// groupSpend tracks the live spend of scans that share a scan group. The
// worker queue runs in one process, so this map sees every running sibling.
// wrap holds a scan's entry from before its claim until its final cost is
// saved. Siblings that finish while others still run stay in it with that
// cost, which keeps each scan counted exactly once. A group without a budget
// is tracked with a zero limit so nested runs skip the DB read.
type groupSpend struct {
	mu     sync.Mutex
	groups map[string]*groupState
}

type groupState struct {
	// limit is 0 when the group has no budget.
	limit float64
	// base is the cost already recorded in the DB for scans that were not
	// tracked when the group first registered.
	base  float64
	scans map[uint]*groupScan
}

type groupScan struct {
	cost    float64
	running int
	// unsaved is set when the scan's final save failed. The DB total then
	// lacks its cost, so the group stays tracked instead of being reloaded.
	unsaved bool
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
	st, _, err := g.registerLocked(group, id, cost, load)
	if err != nil {
		return 0, err
	}
	return st.limit, nil
}

// admit registers a run like register, then checks the group total under the
// same lock. A group that has already spent its cap is not tracked for the
// run and admitted is false, so no sibling can exhaust the budget between the
// check and the hold.
func (g *groupSpend) admit(group string, id uint, cost float64, load func() (limit, base float64, err error)) (total, limit float64, admitted bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	st, undo, err := g.registerLocked(group, id, cost, load)
	if err != nil {
		return 0, 0, false, err
	}
	total, limit = st.total(), st.limit
	if limit > 0 && total >= limit {
		undo()
		return total, limit, false, nil
	}
	return total, limit, true, nil
}

// registerLocked adds one run of scan id to its group and returns the group
// plus an undo that removes exactly that run again. g.mu must be held.
func (g *groupSpend) registerLocked(group string, id uint, cost float64, load func() (limit, base float64, err error)) (*groupState, func(), error) {
	st := g.groups[group]
	joined := st != nil
	if st == nil {
		limit, base, err := load()
		if err != nil {
			return nil, nil, err
		}
		st = &groupState{limit: max(limit, 0), base: base, scans: map[uint]*groupScan{}}
		if g.groups == nil {
			g.groups = map[string]*groupState{}
		}
		g.groups[group] = st
	}
	sc := st.scans[id]
	created := sc == nil
	var moved float64
	if created {
		sc = &groupScan{cost: cost}
		st.scans[id] = sc
		if joined {
			// Its recorded cost is already part of base.
			moved = min(cost, st.base)
			st.base -= moved
		}
	} else {
		// Recorded cost only grows, for example by a backend probe charged
		// after the hold registered the scan.
		sc.cost = max(sc.cost, cost)
	}
	sc.running++
	undo := func() {
		sc.running--
		if created {
			delete(st.scans, id)
			st.base += moved
		}
		g.dropIfIdle(group)
	}
	return st, undo, nil
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

// finish records the cost of one run when it stops. wrap's hold keeps the
// group tracked until the scan's final cost is saved.
func (g *groupSpend) finish(group string, id uint, cost float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if sc := g.endRun(group, id, cost); sc != nil {
		g.dropIfIdle(group)
	}
}

// release ends wrap's hold on a scan once its final save has run. A failed
// save keeps the cost tracked, since a later run would otherwise reload a DB
// total that lacks it.
func (g *groupSpend) release(group string, id uint, cost float64, saved bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if sc := g.endRun(group, id, cost); sc != nil {
		sc.unsaved = !saved
		g.dropIfIdle(group)
	}
}

func (g *groupSpend) endRun(group string, id uint, cost float64) *groupScan {
	st := g.groups[group]
	if st == nil || st.scans[id] == nil {
		return nil
	}
	sc := st.scans[id]
	sc.cost = cost
	sc.running--
	return sc
}

// dropIfIdle forgets the group once no scan in it is running or holds an
// unsaved cost, so a later run reloads finished siblings from the DB.
func (g *groupSpend) dropIfIdle(group string) {
	for _, sc := range g.groups[group].scans {
		if sc.running > 0 || sc.unsaved {
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

// registerGroupSpend tracks a run of scan under its group and returns the
// cap, 0 when the group has none. A DB error is returned rather than read as
// no budget, so the caller never runs a grouped scan without its cap.
func (w *Worker) registerGroupSpend(scan *db.Scan) (float64, error) {
	if scan.ScanGroup == "" {
		return 0, nil
	}
	limit, err := w.groups.register(scan.ScanGroup, scan.ID, scan.CostUSD, w.loadGroupSpend(scan))
	if err != nil {
		return 0, fmt.Errorf("load group cost cap for %q: %w", scan.ScanGroup, err)
	}
	return limit, nil
}

// loadGroupSpend reads the cap of the scan's group and the DB cost of every
// other scan in it. A group without a budget loads as zero.
func (w *Worker) loadGroupSpend(scan *db.Scan) func() (float64, float64, error) {
	return func() (float64, float64, error) {
		limit, err := db.ScanGroupBudgetFor(w.DB, scan.ScanGroup)
		if err != nil || limit <= 0 {
			return 0, 0, err
		}
		base, err := db.ScanGroupSpend(w.DB, scan.ScanGroup, scan.ID)
		return limit, base, err
	}
}

// groupCapError reports that a scan's group had already spent its budget
// when the scan asked for its hold.
type groupCapError struct {
	spent, limit float64
}

func (e *groupCapError) Error() string {
	return fmt.Sprintf("group cost cap $%.2f reached (group spent $%.2f)", e.limit, e.spent)
}

// holdGroupSpend keeps the scan's group tracked from before its claim until
// wrap has saved its final cost, so a sibling starting in between still
// counts that cost. The returned release takes whether the save succeeded.
func (w *Worker) holdGroupSpend(scan *db.Scan) (func(saved bool), error) {
	if scan.ScanGroup == "" {
		return func(bool) {}, nil
	}
	spent, limit, admitted, err := w.groups.admit(scan.ScanGroup, scan.ID, scan.CostUSD, w.loadGroupSpend(scan))
	if err != nil {
		return nil, fmt.Errorf("load group cost cap for %q: %w", scan.ScanGroup, err)
	}
	if !admitted {
		return nil, &groupCapError{spent: spent, limit: limit}
	}
	return func(saved bool) { w.groups.release(scan.ScanGroup, scan.ID, scan.CostUSD, saved) }, nil
}

// heldGroupCapped records the current cost of a scan holding its group spend
// and returns a *groupCapError when the group has reached its cap, nil
// otherwise.
func (w *Worker) heldGroupCapped(scan *db.Scan) *groupCapError {
	if scan.ScanGroup == "" {
		return nil
	}
	spent, limit := w.groups.update(scan.ScanGroup, scan.ID, scan.CostUSD)
	if limit <= 0 || spent < limit {
		return nil
	}
	return &groupCapError{spent: spent, limit: limit}
}

// groupSpendStatus returns the group's spend and cap, preferring the live
// tracker over the DB. The cap is 0 when the group has no budget.
func (w *Worker) groupSpendStatus(group string) (spent, limit float64, err error) {
	if group == "" {
		return 0, 0, nil
	}
	if spent, limit, ok := w.groups.spent(group); ok {
		return spent, limit, nil
	}
	limit, err = db.ScanGroupBudgetFor(w.DB, group)
	if err != nil {
		return 0, 0, fmt.Errorf("load group cost cap for %q: %w", group, err)
	}
	if limit <= 0 {
		return 0, 0, nil
	}
	spent, err = db.ScanGroupSpend(w.DB, group, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("load group spend for %q: %w", group, err)
	}
	return spent, limit, nil
}

// groupCapReached reports whether the scan's group has spent its budget.
func (w *Worker) groupCapReached(scan *db.Scan) (bool, error) {
	spent, limit, err := w.groupSpendStatus(scan.ScanGroup)
	return limit > 0 && spent >= limit, err
}

// groupBudgetRetryDelay is how long a scan waits before trying again when its
// group budget could not be read.
const groupBudgetRetryDelay = 30 * time.Second

// deferUnreadGroupBudget puts a queued scan back on the queue when its group
// budget or spend could not be read, instead of running it without the cap.
// Without a queue the error goes back to goqite, which retries the job.
func (w *Worker) deferUnreadGroupBudget(ctx context.Context, scan *db.Scan, attempt int, cause error) error {
	w.Log.Warn("deferring scan: group cost cap unavailable", "scan", scan.ID, "group", scan.ScanGroup, "err", cause)
	if w.Queue == nil {
		return cause
	}
	prio := PrioScan
	if scan.FindingID != nil {
		prio = PrioFinding
	}
	if err := w.Queue.EnqueueRetry(ctx, scan.Kind, scan.ID, prio, attempt, groupBudgetRetryDelay); err != nil {
		return errors.Join(cause, fmt.Errorf("requeue scan %d: %w", scan.ID, err))
	}
	return nil
}

// skipGroupCapped finishes a queued scan as skipped, without cloning or
// running anything, because its group budget is already spent. The bearer
// token is cleared with the terminal status.
func (w *Worker) skipGroupCapped(scan *db.Scan, capped *groupCapError) error {
	reason := capped.Error()
	now := time.Now()
	// Select makes Updates write the empty APIToken, which a plain struct
	// update would skip as a zero value.
	res := w.DB.Model(&db.Scan{}).Where("id = ? AND status = ?", scan.ID, db.ScanQueued).
		Select("Status", "StatusPriority", "Error", "Log", "StartedAt", "FinishedAt", "APIToken").
		Updates(db.Scan{
			Status:         db.ScanSkipped,
			StatusPriority: db.StatusPriorityFor(db.ScanSkipped),
			Error:          reason,
			Log:            FormatEvent(Event{Kind: KindText, Text: reason}) + "\n",
			StartedAt:      &now,
			FinishedAt:     &now,
		})
	if res.Error != nil {
		return fmt.Errorf("save group-capped scan %d: %w", scan.ID, res.Error)
	}
	if res.RowsAffected == 0 {
		return nil
	}
	scan.Status = db.ScanSkipped
	scan.StatusPriority = db.StatusPriorityFor(db.ScanSkipped)
	scan.Error = reason
	scan.APIToken = ""
	scan.FinishedAt = &now
	w.publish(scan.ID, scan.RepositoryID, "scan-status", string(scan.Status))
	w.SettleScanGroup(scan)
	w.Log.Info("skipping scan: group cost cap reached", "scan", scan.ID, "group", scan.ScanGroup)
	return nil
}
