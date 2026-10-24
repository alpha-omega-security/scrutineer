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
// running cost estimate reaches the scan's cap.
var errCostCapped = errors.New("cost cap reached")

// costCapFinalizeMaxTurns bounds the short resume turn that asks the agent to
// write its report after the cap tripped.
const costCapFinalizeMaxTurns = 3

// costGuard watches a run's event stream and cancels the run context once the
// estimated spend reaches the cap. scan.CostUSD only grows on KindResult, so
// usage events are tracked in pending until the result folds them in.
type costGuard struct {
	mu      sync.Mutex
	scan    *db.Scan
	cap     float64
	pending float64
	tripped bool
	cancel  context.CancelCauseFunc
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
		}
		estimate := g.scan.CostUSD + g.pending
		if g.cap <= 0 || g.tripped || estimate < g.cap {
			return
		}
		g.tripped = true
		emit(Event{Kind: KindText, Text: fmt.Sprintf(
			"cost cap $%.2f reached (estimated $%.2f); stopping after the current call", g.cap, estimate)})
		g.cancel(errCostCapped)
	}
}

// foldPending charges usage that no result event folded in. Stopping the run
// kills the agent before it reports a result, so without this the spend that
// tripped the cap would be missing from the scan. SessionCostUSD moves with it
// so a resumed Claude session, whose total includes the killed run, does not
// charge that spend a second time.
func (g *costGuard) foldPending() {
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
// cap they are the originals and the guard is nil. With one, the context is a
// child of ctx so tripping never looks like an operator cancel to finishScan.
func startCostGuardRun(ctx context.Context, scan *db.Scan, emit func(Event)) (context.Context, func(Event), *costGuard, func()) {
	if scan.MaxCostUSD <= 0 {
		return ctx, emit, nil, func() {}
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	guard := newCostGuard(scan, scan.MaxCostUSD, cancel)
	return runCtx, guard.wrap(emit), guard, func() { cancel(nil) }
}

func costCapPrompt(skill *db.Skill) string {
	outputFile := skillOutputFile(skill)
	return fmt.Sprintf(`The cost budget for this %q scan is exhausted. Stop investigating now. Do not start any new analysis or tool-heavy work.

Write ./%s now with the work completed so far. It must validate against ./%s when that file exists. Record anything unfinished as such, for example as cost_capped or deferred receipts where the skill has a coverage channel, rather than guessing at results.

Write nothing else.`, skill.Name, outputFile, skillSchemaFile)
}

// markCostCapped flags the scan and records the early stop as partial coverage.
func markCostCapped(scan *db.Scan) error {
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok && scan.Coverage != "" {
		return fmt.Errorf("stored coverage record %q did not decode", scan.Coverage)
	}
	scan.CostCapped = true
	rec.Completeness = coverage.CompletenessPartial
	rec.Reason = fmt.Sprintf("cost_cap: stopped at $%.2f of a $%.2f cap", scan.CostUSD, scan.MaxCostUSD)
	setCoverage(scan, rec)
	return nil
}

// finishCostCappedRun handles a run the guard stopped: it asks the agent to
// write its report from the saved session, parses it and marks the scan capped.
func (w *Worker) finishCostCappedRun(ctx context.Context, skill *db.Skill, scan *db.Scan, sj SkillJob, report string, emit func(Event)) (string, error) {
	report = w.finalizeCostCapped(ctx, skill, scan, sj, report, emit)
	if report != "" {
		var err error
		report, err = w.repairAndParseSkillOutput(ctx, skill, scan, sj, report, emit)
		if err != nil {
			return report, err
		}
	}
	if err := markCostCapped(scan); err != nil {
		return report, err
	}
	return report, nil
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
