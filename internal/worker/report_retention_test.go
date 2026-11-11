package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

func TestQueuedSubprojectsReportSurvivesIngestionFailure(t *testing.T) {
	for _, name := range []string{"completed", "capped finalized", "capped without session"} {
		t.Run(name, func(t *testing.T) {
			s := newSubprojectsScanTest(t, dbtest.Open(t))
			report := "{\n  \"subprojects\": [{\"path\":\"core\",\"name\":\"updated\"}]\n}\n"
			capped := name != "completed"
			if capped {
				subprojectCheck(t, s.db.Model(&s.scan).Update("max_cost_usd", 1).Error)
			}
			runner := &capRunner{first: completedCapRun(0.2, report)}
			wantCalls := 1
			switch name {
			case "capped finalized":
				runner.first = blockUntilCapped("retained-session")
				runner.finalize = func(SkillJob) (SkillResult, error) { return SkillResult{Report: report}, nil }
				wantCalls = 2
			case "capped without session":
				runner.first = func(ctx context.Context, emit func(Event)) (SkillResult, error) {
					res, err := blockUntilCapped("")(ctx, emit)
					res.Report = report
					return res, err
				}
			}
			subprojectCheck(t, s.db.Callback().Delete().Before("gorm:delete").Register("test:ingestion_failure", func(tx *gorm.DB) {
				if tx.Statement.Table == "subprojects" {
					_ = tx.AddError(errors.New("ingestion unavailable"))
				}
			}))
			w := &Worker{DB: s.db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(), Runner: runner, PrepareRepoSrc: stubPrepareRepoSrc}
			got := runQueuedReportScan(t, w, s.scan.ID)
			if got.Status != db.ScanFailed || got.CostCapped != capped || got.Report != report || !strings.Contains(got.Error, "ingestion unavailable") {
				t.Fatalf("status=%s capped=%v report=%q error=%q", got.Status, got.CostCapped, got.Report, got.Error)
			}
			if len(runner.jobs) != wantCalls {
				t.Fatalf("model calls=%d, want %d", len(runner.jobs), wantCalls)
			}
			if capped {
				rec, ok := coverage.Parse(got.Coverage)
				if !ok || rec.Completeness != coverage.CompletenessPartial {
					t.Fatalf("coverage=%+v decoded=%v", rec, ok)
				}
			}
			rows := s.rows(t)
			if len(rows) != 2 || rows[0].Name != "old" || rows[0].DisclosureChannel != s.old.DisclosureChannel {
				t.Fatalf("rollback changed subprojects: %+v", rows)
			}
		})
	}
}

func runQueuedReportScan(t *testing.T, w *Worker, scanID uint) db.Scan {
	t.Helper()
	sqldb, err := w.DB.DB()
	subprojectCheck(t, err)
	q, err := queue.New(sqldb, w.Log, 1, queue.SQLite)
	subprojectCheck(t, err)
	w.Register(q)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan struct{})
	go func() { q.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	subprojectCheck(t, q.Enqueue(ctx, JobSkill, scanID, 0))
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		var got db.Scan
		subprojectCheck(t, w.DB.First(&got, scanID).Error)
		if got.Status.Terminal() {
			return got
		}
		select {
		case <-ctx.Done():
			t.Fatalf("scan did not finish: status=%s error=%q", got.Status, got.Error)
		case <-ticker.C:
		}
	}
}
