package worker

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

// errCostCapped is the cancellation cause set on the run context when the
// running cost estimate reaches the scan's cap or its group's cap.
var errCostCapped = errors.New("cost cap reached")

// costCapFinalizeMaxTurns bounds the short resume turn that asks the agent to
// write its report after the cap tripped.
const costCapFinalizeMaxTurns = 3

// costGuard watches a run's event stream and cancels the run context once the
// estimated spend reaches the scan cap or the group cap. scan.CostUSD only
// grows on KindResult, so usage events are tracked in pending until the result
// folds them in. It only trips on usage events because a result means the run
// already finished.
type costGuard struct {
	mu      sync.Mutex
	scan    *db.Scan
	cap     float64
	pending float64
	tripped bool
	cancel  context.CancelCauseFunc
	// groups is set when the scan's group has a budget.
	groups *groupSpend
}

func newCostGuard(scan *db.Scan, limit float64, cancel context.CancelCauseFunc) *costGuard {
	return &costGuard{scan: scan, cap: limit, cancel: cancel}
}

// wrap returns an emit that forwards to emit then checks the estimate.
func (g *costGuard) wrap(emit func(Event)) func(Event) {
	return func(e Event) {
		g.mu.Lock()
		defer g.mu.Unlock()
		emit(e)
		switch e.Kind {
		case KindUsage:
			g.pending += e.CostUSD
		case KindResult:
			g.pending = 0
		default:
			return
		}
		estimate := g.scan.CostUSD + g.pending
		var groupTotal, groupLimit float64
		if g.groups != nil {
			groupTotal, groupLimit = g.groups.update(g.scan.ScanGroup, g.scan.ID, estimate)
		}
		if e.Kind != KindUsage || g.tripped {
			return
		}
		var notice string
		switch {
		case g.cap > 0 && estimate >= g.cap:
			notice = fmt.Sprintf("cost cap $%.2f reached (estimated $%.2f); stopping after the current call", g.cap, estimate)
		case groupLimit > 0 && groupTotal >= groupLimit:
			notice = fmt.Sprintf("group cost cap $%.2f reached (group estimated $%.2f); stopping after the current call", groupLimit, groupTotal)
		default:
			return
		}
		g.tripped = true
		emit(Event{Kind: KindText, Text: notice})
		g.cancel(errCostCapped)
	}
}

// foldPending charges usage that no result event folded in. A run stopped by
// the cap, a timeout or a crash ends before it reports a result, so without
// this that spend would be missing from the scan and its group.
// SessionCostUSD moves with it so a resumed Claude session, whose total
// includes the killed run, does not charge that spend a second time.
func (g *costGuard) foldPending() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.scan.CostUSD += g.pending
	g.scan.SessionCostUSD += g.pending
	g.pending = 0
}

// Tripped reports whether the cap was reached. Safe on a nil guard.
func (g *costGuard) Tripped() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tripped
}

// startCostGuardRun returns the context and emit for the skill run. Without a
// scan or group cap they are the originals and the guard is nil. With one, the
// context is a child of ctx so tripping never looks like an operator cancel to
// finishScan. An error means the group budget could not be read. The run must
// not start then.
func (w *Worker) startCostGuardRun(ctx context.Context, scan *db.Scan, emit func(Event)) (context.Context, func(Event), *costGuard, func(), error) {
	groupLimit, err := w.registerGroupSpend(scan)
	if err != nil {
		return ctx, emit, nil, func() {}, err
	}
	finish := func() {}
	if scan.ScanGroup != "" {
		finish = func() { w.groups.finish(scan.ScanGroup, scan.ID, scan.CostUSD) }
	}
	if scan.MaxCostUSD <= 0 && groupLimit <= 0 {
		return ctx, emit, nil, finish, nil
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	guard := newCostGuard(scan, scan.MaxCostUSD, cancel)
	if groupLimit > 0 {
		guard.groups = &w.groups
	}
	stop := func() {
		cancel(nil)
		finish()
	}
	return runCtx, guard.wrap(emit), guard, stop, nil
}

func (w *Worker) runFollowupSkill(ctx context.Context, scan *db.Scan, job SkillJob, emit func(Event)) (SkillResult, error) {
	if err := ctx.Err(); err != nil {
		return SkillResult{}, err
	}
	groupCapped, err := w.groupCapReached(scan)
	if err != nil {
		return SkillResult{}, err
	}
	if scanCapReached(scan) || groupCapped {
		return SkillResult{}, errCostCapped
	}
	runCtx, runEmit, guard, stop, err := w.startCostGuardRun(ctx, scan, emit)
	if err != nil {
		return SkillResult{}, err
	}
	defer stop()
	res, err := w.Runner.RunSkill(runCtx, job, runEmit)
	w.applySkillResult(scan, res)
	if err != nil {
		guard.foldPending()
	}
	// The resume's backend probe stops it when a sibling spent the group meanwhile.
	if _, ok := errors.AsType[*groupCapError](err); ok {
		return res, errCostCapped
	}
	if err != nil && guard.Tripped() && ctx.Err() == nil {
		return res, errCostCapped
	}
	return res, err
}

func costCapPrompt(skill *db.Skill) string {
	outputFile := skillOutputFile(skill)
	return fmt.Sprintf(`The cost budget for this %q scan is exhausted. Stop investigating now. Do not start any new analysis or tool-heavy work.

Write ./%s now with the work completed so far. It must validate against ./%s when that file exists. Record anything unfinished as such, for example as cost_capped or deferred receipts where the skill has a coverage channel, rather than guessing at results.

Write nothing else.`, skill.Name, outputFile, skillSchemaFile)
}

func scanCapReached(scan *db.Scan) bool {
	return scan.MaxCostUSD > 0 && scan.CostUSD >= scan.MaxCostUSD
}

// markCostCapped flags the scan and records the early stop as partial coverage.
// The scan's own cap is named when it was reached, otherwise the group's.
func (w *Worker) markCostCapped(scan *db.Scan) error {
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok && scan.Coverage != "" {
		return fmt.Errorf("stored coverage record %q did not decode", scan.Coverage)
	}
	scan.CostCapped = true
	rec.Completeness = coverage.CompletenessPartial
	rec.Reason = fmt.Sprintf("cost_cap: stopped at $%.2f of a $%.2f cap", scan.CostUSD, scan.MaxCostUSD)
	spent, limit, err := w.groupSpendStatus(scan.ScanGroup)
	switch {
	case scanCapReached(scan):
	case err != nil:
		w.Log.Warn("load group spend for capped scan", "scan", scan.ID, "err", err)
		rec.Reason = "group_cost_cap: stopped at the group cost cap"
	case limit > 0:
		rec.Reason = fmt.Sprintf("group_cost_cap: group spent $%.2f of a $%.2f cap", spent, limit)
	}
	setCoverage(scan, rec)
	return nil
}

// finishCostCappedRun handles a run the guard stopped: it asks the agent to
// write its report from the saved session, parses it and marks the scan capped.
func (w *Worker) finishCostCappedRun(ctx context.Context, skill *db.Skill, scan *db.Scan, sj SkillJob, report string, emit func(Event)) (string, error) {
	valid := func(r string) bool {
		return r != "" && (skill.SchemaJSON == "" || ValidateSkillReport(skill.Name, skill.SchemaJSON, skill.PoCField, r) == "")
	}
	final := w.finalizeCostCapped(ctx, skill, scan, sj, report, emit)
	if valid(report) && !valid(final) {
		emit(Event{Kind: KindText, Text: "cost cap: finalized report does not validate; keeping the earlier valid report"})
	} else {
		report = final
	}
	// Set before parseSkillOutput so parseFindingsOutput's markNotObserved
	// guard sees this is a partial report. markCostCapped sets it again
	// alongside the Coverage record.
	scan.CostCapped = true
	var parseErr error
	if report != "" {
		parseErr = w.parseSkillOutput(ctx, skill, scan, report, emit)
	}
	if err := w.markCostCapped(scan); err != nil {
		return report, err
	}
	return report, parseErr
}

// finalizeCostCapped resumes the session for a short turn so the agent writes
// its output file, returning the report to use. The finalize turn is not cost
// checked, its spend is bounded by costCapFinalizeMaxTurns.
func (w *Worker) finalizeCostCapped(ctx context.Context, skill *db.Skill, scan *db.Scan, sj SkillJob, report string, emit func(Event)) string {
	if scan.SessionID == "" {
		emit(Event{Kind: KindText, Text: "cost cap: no session to resume; using the partial report as-is"})
		return report
	}
	job := sj
	job.ResumeSessionID = scan.SessionID
	job.ResumePrompt = costCapPrompt(skill)
	job.MaxTurns = costCapFinalizeMaxTurns
	res, err := w.Runner.RunSkill(ctx, job, emit)
	w.applySkillResult(scan, res)
	if res.Report != "" {
		return res.Report
	}
	reason := "no report was written"
	if err != nil {
		reason = err.Error()
	}
	emit(Event{Kind: KindError, Text: fmt.Sprintf("cost cap: finalize turn did not produce the report (%s); keeping the earlier report", reason)})
	return report
}
