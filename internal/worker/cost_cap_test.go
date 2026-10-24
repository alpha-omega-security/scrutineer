package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

// guardEmit mimics scanEmitter: a result event adds its cost to the scan.
func guardEmit(scan *db.Scan) func(Event) {
	return func(e Event) {
		if e.Kind == KindResult {
			scan.CostUSD += e.CostUSD
		}
	}
}

func TestCostGuard_tripsOnceAtCap(t *testing.T) {
	scan := &db.Scan{}
	ctx, cancel := context.WithCancelCause(context.Background())
	g := newCostGuard(scan, 1.0, cancel)
	var texts []string
	emit := g.wrap(func(e Event) {
		guardEmit(scan)(e)
		if e.Kind == KindText {
			texts = append(texts, e.Text)
		}
	})

	emit(Event{Kind: KindUsage, CostUSD: 0.4})
	emit(Event{Kind: KindUsage, CostUSD: 0.4})
	if g.Tripped() || ctx.Err() != nil {
		t.Fatal("tripped below the cap")
	}
	emit(Event{Kind: KindUsage, CostUSD: 0.4})
	if !g.Tripped() {
		t.Fatal("did not trip at the cap")
	}
	if !errors.Is(context.Cause(ctx), errCostCapped) {
		t.Errorf("cause = %v, want errCostCapped", context.Cause(ctx))
	}
	emit(Event{Kind: KindUsage, CostUSD: 0.4})
	if len(texts) != 1 || !strings.Contains(texts[0], "cost cap $1.00 reached") {
		t.Errorf("trip notices = %q, want exactly one", texts)
	}
}

func TestCostGuard_resultFoldsPending(t *testing.T) {
	scan := &db.Scan{}
	_, cancel := context.WithCancelCause(context.Background())
	g := newCostGuard(scan, 1.0, cancel)
	emit := g.wrap(guardEmit(scan))

	emit(Event{Kind: KindUsage, CostUSD: 0.6})
	emit(Event{Kind: KindResult, CostUSD: 0.6})
	if g.pending != 0 || scan.CostUSD != 0.6 {
		t.Fatalf("pending %v cost %v, want 0 and 0.6", g.pending, scan.CostUSD)
	}
	// Counting the usage twice would be 1.2 and trip.
	if g.Tripped() {
		t.Fatal("tripped although the result replaced the pending usage")
	}
	emit(Event{Kind: KindUsage, CostUSD: 0.5})
	if !g.Tripped() {
		t.Fatal("did not trip at 0.6 + 0.5")
	}
}

func TestCostGuard_zeroCapNeverTrips(t *testing.T) {
	scan := &db.Scan{}
	ctx, cancel := context.WithCancelCause(context.Background())
	g := newCostGuard(scan, 0, cancel)
	emit := g.wrap(guardEmit(scan))
	emit(Event{Kind: KindUsage, CostUSD: 1000})
	if g.Tripped() || ctx.Err() != nil {
		t.Fatal("zero cap tripped")
	}
}

// capRunner scripts RunSkill: the first call runs first, later calls run
// finalize. Every job is recorded.
type capRunner struct {
	mu       sync.Mutex
	jobs     []SkillJob
	first    func(ctx context.Context, emit func(Event)) (SkillResult, error)
	finalize func(sj SkillJob) (SkillResult, error)
}

func (c *capRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	c.mu.Lock()
	c.jobs = append(c.jobs, sj)
	n := len(c.jobs)
	c.mu.Unlock()
	if n == 1 {
		return c.first(ctx, emit)
	}
	return c.finalize(sj)
}

func (*capRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func costCapFixture(t *testing.T, maxCost float64) (*Worker, *db.Scan) {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/cap", Name: "cap"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{
		Name: "capskill", Description: "x", Body: "b", OutputFile: "report.json",
		OutputKind: "freeform", Version: 1, Active: true, Source: "test",
	}
	if err := gdb.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued,
		Model: "fake", SkillID: &skill.ID, MaxCostUSD: maxCost,
	}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	w := &Worker{
		DB:      gdb,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(),
		PrepareRepoSrcWithOptions: func(_ context.Context, _, _, workRoot string, _ bool, _ func(Event)) (string, error) {
			return "abc", os.MkdirAll(filepath.Join(workRoot, "src"), 0o755)
		},
	}
	return w, &scan
}

func runCapScan(t *testing.T, w *Worker, scan *db.Scan) db.Scan {
	t.Helper()
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	var got db.Scan
	if err := w.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	return got
}

func blockUntilCapped(session string) func(context.Context, func(Event)) (SkillResult, error) {
	return func(ctx context.Context, emit func(Event)) (SkillResult, error) {
		if session != "" {
			emit(Event{Kind: KindSession, SessionID: session})
		}
		emit(Event{Kind: KindUsage, CostUSD: 0.6})
		emit(Event{Kind: KindUsage, CostUSD: 0.6})
		<-ctx.Done()
		return SkillResult{}, ctx.Err()
	}
}

func TestDoSkill_costCapFinalizesFromSession(t *testing.T) {
	w, scan := costCapFixture(t, 1.0)
	runner := &capRunner{
		first: blockUntilCapped("sess-1"),
		finalize: func(SkillJob) (SkillResult, error) {
			return SkillResult{Report: `{"partial":true}`}, nil
		},
	}
	w.Runner = runner
	got := runCapScan(t, w, scan)

	if len(runner.jobs) != 2 {
		t.Fatalf("RunSkill called %d times, want 2", len(runner.jobs))
	}
	fin := runner.jobs[1]
	if fin.ResumeSessionID != "sess-1" || fin.MaxTurns != costCapFinalizeMaxTurns ||
		!strings.Contains(fin.ResumePrompt, "cost budget") {
		t.Errorf("finalize job = session %q turns %d prompt %q", fin.ResumeSessionID, fin.MaxTurns, fin.ResumePrompt)
	}
	if got.Status != db.ScanDone || !got.CostCapped || got.Error != "" {
		t.Errorf("status %s capped %v error %q", got.Status, got.CostCapped, got.Error)
	}
	if got.Report != `{"partial":true}` || got.SessionID != "sess-1" {
		t.Errorf("report %q session %q", got.Report, got.SessionID)
	}
	if got.Completeness != coverage.CompletenessPartial {
		t.Errorf("completeness = %q", got.Completeness)
	}
	rec, ok := coverage.Parse(got.Coverage)
	if !ok || !strings.HasPrefix(rec.Reason, "cost_cap") {
		t.Errorf("coverage = %+v ok %v", rec, ok)
	}
	if !got.Resumable() {
		t.Error("capped scan is not resumable")
	}
	// The killed run never reported a result, so its usage is charged directly.
	if math.Abs(got.CostUSD-1.2) > 1e-9 || math.Abs(got.SessionCostUSD-1.2) > 1e-9 {
		t.Errorf("cost %v session cost %v, want 1.2 each", got.CostUSD, got.SessionCostUSD)
	}
}

func TestDoSkill_costCapWithoutSessionKeepsPartialReport(t *testing.T) {
	w, scan := costCapFixture(t, 1.0)
	first := blockUntilCapped("")
	runner := &capRunner{
		first: func(ctx context.Context, emit func(Event)) (SkillResult, error) {
			_, err := first(ctx, emit)
			return SkillResult{Report: `{"partial":"yes"}`}, err
		},
		finalize: func(SkillJob) (SkillResult, error) {
			t.Error("finalize ran without a session")
			return SkillResult{}, nil
		},
	}
	w.Runner = runner
	got := runCapScan(t, w, scan)

	if len(runner.jobs) != 1 {
		t.Fatalf("RunSkill called %d times, want 1", len(runner.jobs))
	}
	if got.Status != db.ScanDone || !got.CostCapped || got.Report != `{"partial":"yes"}` {
		t.Errorf("status %s capped %v report %q", got.Status, got.CostCapped, got.Report)
	}
}

func TestDoSkill_operatorCancelIsNotACostCap(t *testing.T) {
	w, scan := costCapFixture(t, 100)
	started := make(chan struct{})
	w.Runner = &capRunner{
		first: func(ctx context.Context, _ func(Event)) (SkillResult, error) {
			close(started)
			<-ctx.Done()
			return SkillResult{}, ctx.Err()
		},
		finalize: func(SkillJob) (SkillResult, error) {
			t.Error("finalize ran after an operator cancel")
			return SkillResult{}, nil
		},
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	done := make(chan error, 1)
	go func() { done <- w.wrap(w.doSkill)(context.Background(), body) }()
	<-started
	if found, err := w.CancelWithAudit(scan.ID, "", nil); !found || err != nil {
		t.Fatal("cancel reported scan not running")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not stop")
	}
	var got db.Scan
	if err := w.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Status != db.ScanCancelled || got.CostCapped {
		t.Errorf("status %s capped %v, want cancelled and not capped", got.Status, got.CostCapped)
	}
}
