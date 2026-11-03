package worker

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func loadGroup(limit, base float64, calls *int) func() (float64, float64, error) {
	return func() (float64, float64, error) {
		*calls++
		return limit, base, nil
	}
}

func TestGroupSpend_countsEachScanOnce(t *testing.T) {
	var g groupSpend
	loads := 0
	load := loadGroup(10, 3, &loads)

	if limit, err := g.register("g", 1, 0, load); err != nil || limit != 10 {
		t.Fatalf("register A = %v, %v", limit, err)
	}
	if total, _ := g.update("g", 1, 1); total != 4 {
		t.Errorf("total after A = %v, want 4", total)
	}
	// B joins with $1 already recorded in the DB, which base already counts.
	if _, err := g.register("g", 2, 1, load); err != nil {
		t.Fatal(err)
	}
	if loads != 1 {
		t.Errorf("load ran %d times, want 1", loads)
	}
	if total, _ := g.update("g", 2, 1.5); total != 4.5 {
		t.Errorf("total with B = %v, want 4.5", total)
	}
	// A finishes while B still runs: it keeps its final cost, counted once.
	g.finish("g", 1, 1.25)
	if total, _, ok := g.spent("g"); !ok || total != 4.75 {
		t.Errorf("total after A finished = %v ok %v, want 4.75", total, ok)
	}
	if total, _ := g.update("g", 2, 2); total != 5.25 {
		t.Errorf("total after B grew = %v, want 5.25", total)
	}
	g.finish("g", 2, 2)
	if _, _, ok := g.spent("g"); ok {
		t.Error("group still tracked after its last scan ended")
	}

	if _, err := g.register("g", 3, 0, load); err != nil {
		t.Fatal(err)
	}
	if loads != 2 {
		t.Errorf("load ran %d times after the group was dropped, want 2", loads)
	}
}

func TestGroupSpend_nestedRunsKeepGroupUntilOutermostEnds(t *testing.T) {
	var g groupSpend
	loads := 0
	load := loadGroup(10, 0, &loads)
	for range 2 {
		if _, err := g.register("g", 1, 0, load); err != nil {
			t.Fatal(err)
		}
	}
	g.finish("g", 1, 2)
	if total, _, ok := g.spent("g"); !ok || total != 2 {
		t.Fatalf("inner finish dropped the group: total %v ok %v", total, ok)
	}
	g.finish("g", 1, 3)
	if _, _, ok := g.spent("g"); ok {
		t.Error("group kept after the outermost run ended")
	}
}

func TestGroupSpend_noBudgetRegistersNothing(t *testing.T) {
	var g groupSpend
	loads := 0
	limit, err := g.register("g", 1, 0, loadGroup(0, 0, &loads))
	if err != nil || limit != 0 {
		t.Fatalf("register = %v, %v, want 0", limit, err)
	}
	if _, _, ok := g.spent("g"); ok {
		t.Error("a group without a budget is tracked")
	}
	if _, err := g.register("g", 1, 0, func() (float64, float64, error) { return 0, 0, errors.New("boom") }); err == nil {
		t.Error("load error was swallowed")
	}
}

func TestCostGuard_tripsOnGroupTotal(t *testing.T) {
	var g groupSpend
	loads := 0
	if _, err := g.register("g", 1, 0, loadGroup(1, 0.7, &loads)); err != nil {
		t.Fatal(err)
	}
	scan := &db.Scan{ID: 1, ScanGroup: "g"}
	ctx, cancel := context.WithCancelCause(context.Background())
	guard := newCostGuard(scan, 0, cancel)
	guard.groups = &g
	var texts []string
	emit := guard.wrap(func(e Event) {
		guardEmit(scan)(e)
		if e.Kind == KindText {
			texts = append(texts, e.Text)
		}
	})

	emit(Event{Kind: KindUsage, CostUSD: 0.2})
	if guard.Tripped() {
		t.Fatal("tripped below the group cap")
	}
	emit(Event{Kind: KindUsage, CostUSD: 0.2})
	if !guard.Tripped() || !errors.Is(context.Cause(ctx), errCostCapped) {
		t.Fatal("did not trip at the group cap")
	}
	if len(texts) != 1 || !strings.Contains(texts[0], "group cost cap $1.00 reached (group estimated $1.10)") {
		t.Errorf("notices = %q", texts)
	}
}

// groupFixture adds a finished sibling that already spent siblingCost and a
// budget for the group the fixture scan belongs to.
func groupFixture(t *testing.T, ownCap, groupCap, siblingCost float64) (*Worker, *db.Scan) {
	t.Helper()
	w, scan := costCapFixture(t, ownCap)
	scan.ScanGroup = "grp"
	if err := w.DB.Model(scan).Update("scan_group", "grp").Error; err != nil {
		t.Fatal(err)
	}
	sibling := db.Scan{RepositoryID: scan.RepositoryID, Kind: JobSkill, Status: db.ScanDone, ScanGroup: "grp", CostUSD: siblingCost}
	if err := w.DB.Create(&sibling).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.SetScanGroupBudget(w.DB, "grp", scan.RepositoryID, groupCap); err != nil {
		t.Fatal(err)
	}
	return w, scan
}

func TestDoSkill_groupCostCapFinalizesFromSession(t *testing.T) {
	w, scan := groupFixture(t, 0, 1.0, 0.7)
	runner := &capRunner{
		first: blockUntilCapped("sess-g"),
		finalize: func(SkillJob) (SkillResult, error) {
			return SkillResult{Report: `{"partial":true}`}, nil
		},
	}
	w.Runner = runner
	got := runCapScan(t, w, scan)

	if len(runner.jobs) != 2 || runner.jobs[1].ResumeSessionID != "sess-g" {
		t.Fatalf("jobs = %+v, want a run and a finalize turn", runner.jobs)
	}
	if got.Status != db.ScanDone || !got.CostCapped || got.Error != "" || got.Report != `{"partial":true}` {
		t.Errorf("status %s capped %v error %q report %q", got.Status, got.CostCapped, got.Error, got.Report)
	}
	rec, ok := coverage.Parse(got.Coverage)
	if !ok || rec.Completeness != coverage.CompletenessPartial ||
		rec.Reason != "group_cost_cap: group spent $1.90 of a $1.00 cap" {
		t.Errorf("coverage = %+v ok %v", rec, ok)
	}
	if !strings.Contains(got.Log, "group cost cap $1.00 reached") {
		t.Errorf("log lacks the group trip notice: %s", got.Log)
	}
	// Both 0.6 usage events land before the run sees the cancel. The finalize turn carries no cost.
	if math.Abs(got.CostUSD-1.2) > 1e-9 {
		t.Errorf("cost = %v, want 1.2", got.CostUSD)
	}
	if _, _, ok := w.groups.spent("grp"); ok {
		t.Error("group still tracked after the run")
	}
}

func TestDoSkill_ownCapWinsWhenGroupBudgetIsLarger(t *testing.T) {
	w, scan := groupFixture(t, 1.0, 100, 0)
	w.Runner = &capRunner{
		first:    blockUntilCapped("sess-o"),
		finalize: func(SkillJob) (SkillResult, error) { return SkillResult{Report: `{}`}, nil },
	}
	got := runCapScan(t, w, scan)
	rec, ok := coverage.Parse(got.Coverage)
	if !got.CostCapped || !ok || !strings.HasPrefix(rec.Reason, "cost_cap: stopped at $1.20 of a $1.00 cap") {
		t.Errorf("capped %v coverage %+v ok %v", got.CostCapped, rec, ok)
	}
}

func TestDoSkill_groupBelowBudgetRunsToCompletion(t *testing.T) {
	w, scan := groupFixture(t, 0, 100, 1)
	runner := &capRunner{first: completedCapRun(0.5, `{"ok":true}`)}
	w.Runner = runner
	got := runCapScan(t, w, scan)
	if got.Status != db.ScanDone || got.CostCapped || got.Report != `{"ok":true}` {
		t.Errorf("status %s capped %v report %q", got.Status, got.CostCapped, got.Report)
	}
}

func TestStartCostGuardRun_noGuardWithoutBudget(t *testing.T) {
	w, scan := costCapFixture(t, 0)
	scan.ScanGroup = "grp"
	_, _, guard, stop := w.startCostGuardRun(context.Background(), scan, func(Event) {})
	defer stop()
	if guard != nil {
		t.Error("grouped scan without a budget or cap got a guard")
	}
	if _, _, ok := w.groups.spent("grp"); ok {
		t.Error("a group without a budget is tracked")
	}
}

// pairRunner scripts two sibling scans through one worker.
type pairRunner struct {
	aUsed, bUsed, aDone chan struct{}
	aScan               uint
}

func (*pairRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func (p *pairRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	if sj.ScanID == p.aScan {
		emit(Event{Kind: KindUsage, CostUSD: 0.4})
		close(p.aUsed)
		<-p.bUsed
		emit(Event{Kind: KindUsage, CostUSD: 0.15})
		emit(Event{Kind: KindResult, CostUSD: 0.55})
		close(p.aDone)
		return SkillResult{Report: `{"a":true}`}, nil
	}
	<-p.aUsed
	emit(Event{Kind: KindUsage, CostUSD: 0.4})
	close(p.bUsed)
	<-p.aDone
	emit(Event{Kind: KindUsage, CostUSD: 0.15})
	<-ctx.Done()
	return SkillResult{}, ctx.Err()
}

func TestDoSkill_concurrentSiblingsTripOnSharedTotal(t *testing.T) {
	w, a := groupFixture(t, 0, 1.0, 0)
	b := db.Scan{RepositoryID: a.RepositoryID, Kind: JobSkill, Status: db.ScanQueued, Model: "fake",
		SkillID: a.SkillID, ScanGroup: "grp"}
	if err := w.DB.Create(&b).Error; err != nil {
		t.Fatal(err)
	}
	w.Runner = &pairRunner{aUsed: make(chan struct{}), bUsed: make(chan struct{}), aDone: make(chan struct{}), aScan: a.ID}

	var wg sync.WaitGroup
	var gotA, gotB db.Scan
	for _, run := range []struct {
		scan *db.Scan
		out  *db.Scan
	}{{a, &gotA}, {&b, &gotB}} {
		wg.Go(func() { *run.out = runCapScan(t, w, run.scan) })
	}
	wg.Wait()

	// Each scan alone spent $0.55 against a $1.00 cap.
	if gotA.Status != db.ScanDone || gotA.CostCapped {
		t.Errorf("A status %s capped %v, want done and uncapped", gotA.Status, gotA.CostCapped)
	}
	rec, ok := coverage.Parse(gotB.Coverage)
	if gotB.Status != db.ScanDone || !gotB.CostCapped || !ok ||
		rec.Reason != "group_cost_cap: group spent $1.10 of a $1.00 cap" {
		t.Errorf("B status %s capped %v coverage %+v", gotB.Status, gotB.CostCapped, rec)
	}
	if _, _, ok := w.groups.spent("grp"); ok {
		t.Error("group still tracked after both scans ended")
	}
}

func TestWrap_skipsQueuedScanWhenGroupBudgetSpent(t *testing.T) {
	w, scan := groupFixture(t, 0, 1.0, 1.5)
	w.PrepareRepoSrcWithOptions = func(context.Context, string, string, string, RepoSrcOptions, func(Event)) (string, error) {
		t.Error("cloned a scan whose group budget is spent")
		return "", nil
	}
	runner := &capRunner{first: func(context.Context, func(Event)) (SkillResult, error) {
		t.Error("ran a scan whose group budget is spent")
		return SkillResult{}, nil
	}}
	w.Runner = runner
	var settled []uint
	w.OnScanGroupSettled = func(s *db.Scan) { settled = append(settled, s.ID) }

	got := runCapScan(t, w, scan)
	if len(runner.jobs) != 0 {
		t.Errorf("runner called %d times", len(runner.jobs))
	}
	if got.Status != db.ScanSkipped || got.StatusPriority != db.StatusPriorityFor(db.ScanSkipped) ||
		got.FinishedAt == nil || got.Error != "group cost cap $1.00 reached (group spent $1.50)" {
		t.Errorf("status %s priority %d finished %v error %q", got.Status, got.StatusPriority, got.FinishedAt, got.Error)
	}
	if !strings.Contains(got.Log, got.Error) {
		t.Errorf("log %q lacks the reason", got.Log)
	}
	if len(settled) != 1 || settled[0] != scan.ID {
		t.Errorf("group settled hook calls = %v", settled)
	}
}

func TestWrap_runsQueuedScanWhenGroupBudgetRemains(t *testing.T) {
	w, scan := groupFixture(t, 0, 5.0, 1.5)
	w.Runner = &capRunner{first: completedCapRun(0.1, `{"ok":1}`)}
	if got := runCapScan(t, w, scan); got.Status != db.ScanDone {
		t.Errorf("status %s, want done", got.Status)
	}
}

func TestRunFollowupSkill_stopsWhenGroupSpent(t *testing.T) {
	w, scan := groupFixture(t, 0, 1.0, 0)
	if _, err := w.groups.register("grp", 99, 0, loadGroup(1, 1.2, new(int))); err != nil {
		t.Fatal(err)
	}
	runner := &capRunner{first: func(context.Context, func(Event)) (SkillResult, error) {
		t.Error("follow-up ran with the group budget spent")
		return SkillResult{}, nil
	}}
	w.Runner = runner
	_, err := w.runFollowupSkill(context.Background(), scan, SkillJob{}, func(Event) {})
	if !errors.Is(err, errCostCapped) {
		t.Errorf("err = %v, want errCostCapped", err)
	}
}
