package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestCostGuard_resultDoesNotTrip(t *testing.T) {
	scan := &db.Scan{}
	ctx, cancel := context.WithCancelCause(context.Background())
	g := newCostGuard(scan, 1.0, cancel)
	emit := g.wrap(guardEmit(scan))

	emit(Event{Kind: KindUsage, CostUSD: 0.4})
	emit(Event{Kind: KindResult, CostUSD: 1.5})
	if g.Tripped() || ctx.Err() != nil {
		t.Fatalf("a result over the cap tripped the guard (tripped %v err %v)", g.Tripped(), ctx.Err())
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
	next     func(context.Context, SkillJob, func(Event)) (SkillResult, error)
}

func (c *capRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	c.mu.Lock()
	c.jobs = append(c.jobs, sj)
	n := len(c.jobs)
	c.mu.Unlock()
	if n == 1 {
		return c.first(ctx, emit)
	}
	if c.next != nil {
		return c.next(ctx, sj, emit)
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
		PrepareRepoSrcWithOptions: func(_ context.Context, _, _, workRoot string, _ RepoSrcOptions, _ func(Event)) (string, error) {
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

func assertFullReportKept(t *testing.T, runner *capRunner, got db.Scan) {
	t.Helper()
	if len(runner.jobs) != 1 {
		t.Fatalf("RunSkill called %d times, want 1", len(runner.jobs))
	}
	if got.Status != db.ScanDone || got.CostCapped {
		t.Errorf("status %s capped %v", got.Status, got.CostCapped)
	}
	if got.Report != `{"full":true}` {
		t.Errorf("report %q", got.Report)
	}
	if got.Completeness == coverage.CompletenessPartial {
		t.Errorf("completeness = %q", got.Completeness)
	}
}

func TestDoSkill_resultOverCapKeepsFullReport(t *testing.T) {
	w, scan := costCapFixture(t, 1.0)
	runner := &capRunner{
		first: func(_ context.Context, emit func(Event)) (SkillResult, error) {
			emit(Event{Kind: KindSession, SessionID: "sess-1"})
			emit(Event{Kind: KindUsage, CostUSD: 0.4})
			emit(Event{Kind: KindResult, CostUSD: 1.5})
			return SkillResult{Report: `{"full":true}`}, nil
		},
		finalize: func(SkillJob) (SkillResult, error) {
			t.Error("finalize ran for a finished run")
			return SkillResult{}, nil
		},
	}
	w.Runner = runner
	assertFullReportKept(t, runner, runCapScan(t, w, scan))
}

func TestDoSkill_usageTripAfterFinishKeepsFullReport(t *testing.T) {
	w, scan := costCapFixture(t, 1.0)
	runner := &capRunner{
		first: func(_ context.Context, emit func(Event)) (SkillResult, error) {
			emit(Event{Kind: KindUsage, CostUSD: 0.6})
			emit(Event{Kind: KindUsage, CostUSD: 0.6})
			emit(Event{Kind: KindResult, CostUSD: 1.2})
			return SkillResult{Report: `{"full":true}`}, nil
		},
		finalize: func(SkillJob) (SkillResult, error) {
			t.Error("finalize ran for a finished run")
			return SkillResult{}, nil
		},
	}
	w.Runner = runner
	assertFullReportKept(t, runner, runCapScan(t, w, scan))
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

const capRepairSchema = `{"type":"object","required":["complete"],"properties":{"complete":{"type":"boolean"}}}`

func completedCapRun(cost float64, report string) func(context.Context, func(Event)) (SkillResult, error) {
	return func(_ context.Context, emit func(Event)) (SkillResult, error) {
		emit(Event{Kind: KindSession, SessionID: "sess-followup"})
		emit(Event{Kind: KindResult, SessionCostUSD: cost})
		return SkillResult{Report: report}, nil
	}
}

func TestDoSkill_costCapCoversSchemaRepair(t *testing.T) {
	for _, finalReport := range []string{`{"complete":false}`, `{}`} {
		t.Run(finalReport, func(t *testing.T) {
			testSchemaRepairCostCap(t, finalReport)
		})
	}
}

func testSchemaRepairCostCap(t *testing.T, finalReport string) {
	t.Helper()
	w, scan := costCapFixture(t, 1)
	w.SchemaStrict = true
	if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Update("schema_json", capRepairSchema).Error; err != nil {
		t.Fatal(err)
	}
	runner := &capRunner{first: completedCapRun(0.4, `{}`)}
	runner.next = func(ctx context.Context, job SkillJob, emit func(Event)) (SkillResult, error) {
		switch len(runner.jobs) {
		case 2:
			if job.MaxTurns != schemaRepairMaxTurns {
				t.Fatal("expected schema repair")
			}
			emit(Event{Kind: KindUsage, CostUSD: 0.7})
			if !errors.Is(context.Cause(ctx), errCostCapped) {
				t.Fatal("schema repair continued beyond the remaining budget")
			}
			return SkillResult{}, ctx.Err()
		case 3:
			if job.MaxTurns != costCapFinalizeMaxTurns || !strings.Contains(job.ResumePrompt, "cost budget") || ctx.Err() != nil {
				t.Fatal("expected bounded finalization on the live parent context")
			}
			emit(Event{Kind: KindResult, SessionCostUSD: 1.3})
			return SkillResult{Report: finalReport}, nil
		default:
			t.Fatal("another model call ran after cost-cap finalization")
			return SkillResult{}, nil
		}
	}
	w.Runner = runner
	got := runCapScan(t, w, scan)
	wantStatus := db.ScanDone
	if finalReport == `{}` {
		wantStatus = db.ScanFailed
	}
	if len(runner.jobs) != 3 {
		t.Fatalf("calls=%d, want 3", len(runner.jobs))
	}
	assertCostCappedReport(t, got, wantStatus, finalReport)
	if math.Abs(got.CostUSD-1.3) > 1e-9 || math.Abs(got.SessionCostUSD-1.3) > 1e-9 {
		t.Fatalf("cost=%v session=%v; interrupted usage was not reconciled", got.CostUSD, got.SessionCostUSD)
	}
}

func TestDoSkill_costCapInterruptedRepairReport(t *testing.T) {
	for _, tc := range []struct {
		name, interrupted, final, want string
		strict                         bool
	}{
		{"valid repair retained", `{"complete":false}`, "", `{"complete":false}`, false},
		{"valid repair kept over invalid finalize", `{"complete":false}`, `{}`, `{"complete":false}`, true},
		{"truncated repair dropped", `{"compl`, "", `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, scan := costCapFixture(t, 1)
			w.SchemaStrict = tc.strict
			if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Update("schema_json", capRepairSchema).Error; err != nil {
				t.Fatal(err)
			}
			runner := &capRunner{first: completedCapRun(0.4, `{}`)}
			runner.next = func(ctx context.Context, _ SkillJob, emit func(Event)) (SkillResult, error) {
				switch len(runner.jobs) {
				case 2:
					emit(Event{Kind: KindUsage, CostUSD: 0.7})
					return SkillResult{Report: tc.interrupted}, ctx.Err()
				case 3:
					if tc.final != "" {
						return SkillResult{Report: tc.final}, nil
					}
					return SkillResult{}, errors.New("finalization failed")
				default:
					t.Fatal("another model call ran after cost-cap finalization")
					return SkillResult{}, nil
				}
			}
			w.Runner = runner
			got := runCapScan(t, w, scan)
			if len(runner.jobs) != 3 {
				t.Fatalf("calls=%d, want 3", len(runner.jobs))
			}
			assertCostCappedReport(t, got, db.ScanDone, tc.want)
		})
	}
}

func assertCostCappedReport(t *testing.T, got db.Scan, status db.ScanStatus, report string) {
	t.Helper()
	if got.Status != status || !got.CostCapped || got.Report != report || got.Completeness != coverage.CompletenessPartial {
		t.Fatalf("status=%s capped=%v report=%s completeness=%s", got.Status, got.CostCapped, got.Report, got.Completeness)
	}
}

func TestDoSkill_costCapCoversRefusalAudit(t *testing.T) {
	for _, primaryCost := range []float64{0.4, 1.2} {
		t.Run(fmt.Sprint(primaryCost), func(t *testing.T) {
			w, scan := costCapFixture(t, 1)
			if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Update("name", refusalAuditSkillName).Error; err != nil {
				t.Fatal(err)
			}
			runner := &capRunner{first: completedCapRun(primaryCost, `{"findings":[]}`)}
			runner.next = func(ctx context.Context, job SkillJob, emit func(Event)) (SkillResult, error) {
				if primaryCost >= 1 || len(runner.jobs) != 2 || job.OutputFile != refusalAuditOutputFile {
					t.Fatal("unexpected follow-up after budget exhaustion")
				}
				emit(Event{Kind: KindUsage, CostUSD: 0.7})
				if !errors.Is(context.Cause(ctx), errCostCapped) {
					t.Fatal("refusal audit continued beyond the remaining budget")
				}
				return SkillResult{}, ctx.Err()
			}
			w.Runner = runner
			got := runCapScan(t, w, scan)
			wantCost, wantCalls := primaryCost, 1
			if primaryCost < 1 {
				wantCost += 0.7
				wantCalls++
			}
			if len(runner.jobs) != wantCalls || got.Status != db.ScanDone || got.CostCapped || got.Report != `{"findings":[]}` || got.RefusalAudit != "" {
				t.Fatalf("calls=%d status=%s capped=%v report=%s audit=%s", len(runner.jobs), got.Status, got.CostCapped, got.Report, got.RefusalAudit)
			}
			if math.Abs(got.CostUSD-wantCost) > 1e-9 || got.Completeness == coverage.CompletenessPartial {
				t.Fatalf("cost=%v completeness=%s", got.CostUSD, got.Completeness)
			}
		})
	}
}

func TestCostGuard_warnsOnceOnUnpricedUsage(t *testing.T) {
	scan := &db.Scan{Model: "openrouter/meta/muse-spark-1.3-contributor"}
	_, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	g := newCostGuard(scan, 1.0, cancel)
	var texts []string
	emit := g.wrap(func(e Event) {
		if e.Kind == KindText {
			texts = append(texts, e.Text)
		}
	})

	emit(Event{Kind: KindUsage})
	emit(Event{Kind: KindUsage, CostUSD: 0.1, Usage: Usage{InputTokens: 10}})
	if len(texts) != 0 {
		t.Fatalf("warned for priced or empty usage: %q", texts)
	}
	emit(Event{Kind: KindUsage, Usage: Usage{InputTokens: 10, OutputTokens: 5}})
	emit(Event{Kind: KindUsage, Usage: Usage{InputTokens: 10}})
	if len(texts) != 1 || !strings.Contains(texts[0], "no price is known for openrouter/meta/muse-spark-1.3-contributor") {
		t.Fatalf("warnings = %q, want exactly one naming the model", texts)
	}
	if g.Tripped() {
		t.Error("an unpriced warning must not trip the cap")
	}
}

func TestCostGuard_unpricedWarningPrefersEventModel(t *testing.T) {
	scan := &db.Scan{Model: "configured"}
	_, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	g := newCostGuard(scan, 1.0, cancel)
	var text string
	g.wrap(func(e Event) {
		if e.Kind == KindText {
			text = e.Text
		}
	})(Event{Kind: KindUsage, Model: "reported", Usage: Usage{OutputTokens: 1}})
	if !strings.Contains(text, "no price is known for reported") {
		t.Fatalf("warning = %q, want the model the event reported", text)
	}
}
