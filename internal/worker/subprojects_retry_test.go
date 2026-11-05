package worker

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

type countingSubprojectsRunner struct {
	fakeRunner
	calls int
}

func (r *countingSubprojectsRunner) RunSkill(ctx context.Context, job SkillJob, emit func(Event)) (SkillResult, error) {
	r.calls++
	return r.fakeRunner.RunSkill(ctx, job, emit)
}

type subprojectsScanTest struct {
	db   *gorm.DB
	scan db.Scan
	old  db.Subproject
}

func newSubprojectsScanTest(t *testing.T) subprojectsScanTest {
	t.Helper()
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/subprojects", Name: "subprojects"}
	subprojectCheck(t, gdb.Create(&repo).Error)
	skill := db.Skill{Name: "subprojects", Body: "enumerate subprojects", OutputFile: "report.json", OutputKind: "subprojects", Version: 1, Active: true, Source: "ui"}
	subprojectCheck(t, gdb.Create(&skill).Error)
	old := db.Subproject{RepositoryID: repo.ID, Path: "core", Name: "old", DisclosureChannel: "security@example.com"}
	removed := db.Subproject{RepositoryID: repo.ID, Path: "removed"}
	subprojectCheck(t, gdb.Create(&old).Error)
	subprojectCheck(t, gdb.Create(&removed).Error)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, Model: "fake", SkillID: &skill.ID}
	subprojectCheck(t, gdb.Create(&scan).Error)
	return subprojectsScanTest{db: gdb, scan: scan, old: old}
}

func subprojectCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (s subprojectsScanTest) startWriter(t *testing.T) *sql.Tx {
	t.Helper()
	sqldb, err := s.db.DB()
	subprojectCheck(t, err)
	writer, err := sqldb.Begin()
	subprojectCheck(t, err)
	t.Cleanup(func() { _ = writer.Rollback() })
	_, err = writer.Exec("UPDATE repositories SET description = 'concurrent write' WHERE id = ?", s.scan.RepositoryID)
	subprojectCheck(t, err)
	return writer
}

func (s subprojectsScanTest) run(t *testing.T, report string) db.Scan {
	t.Helper()
	runner := &countingSubprojectsRunner{fakeRunner: fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}}}
	w := &Worker{DB: s.db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DataDir: t.TempDir(), Runner: runner, PrepareRepoSrc: stubPrepareRepoSrc}
	body, err := json.Marshal(queue.Payload{ScanID: s.scan.ID})
	subprojectCheck(t, err)
	subprojectCheck(t, w.wrap(w.doSkill)(context.Background(), body))
	var persisted db.Scan
	subprojectCheck(t, s.db.First(&persisted, s.scan.ID).Error)
	if runner.calls != 1 || persisted.Report != report {
		t.Fatalf("model calls=%d, report=%q", runner.calls, persisted.Report)
	}
	return persisted
}

func (s subprojectsScanTest) rows(t *testing.T) []db.Subproject {
	t.Helper()
	var rows []db.Subproject
	subprojectCheck(t, s.db.Where("repository_id = ?", s.scan.RepositoryID).Order("id").Find(&rows).Error)
	return rows
}

func TestSubprojectsScanBusy(t *testing.T) {
	s := newSubprojectsScanTest(t)
	var writer *sql.Tx
	var lockErr error
	attempts := 0
	subprojectCheck(t, s.db.Callback().Delete().Before("gorm:delete").Register("test:contention", func(tx *gorm.DB) {
		if tx.Statement.Table != "subprojects" {
			return
		}
		attempts++
		if attempts == 1 {
			writer = s.startWriter(t)
		}
	}))
	subprojectCheck(t, s.db.Callback().Delete().After("gorm:delete").Register("test:release", func(tx *gorm.DB) {
		if tx.Statement.Table == "subprojects" && attempts == 1 {
			lockErr = tx.Error
			subprojectCheck(t, writer.Rollback())
		}
	}))
	persisted := s.run(t, `{"subprojects":[]}`)
	assertSubprojectRecovery(t, persisted, attempts, lockErr, 5)
	if rows := s.rows(t); len(rows) != 0 {
		t.Fatalf("unpruned rows: %+v", rows)
	}
}

func TestSubprojectsScanSnapshot(t *testing.T) {
	s := newSubprojectsScanTest(t)
	attempts := 0
	var lockErr error
	subprojectCheck(t, s.db.Callback().Query().After("gorm:query").Register("test:snapshot", func(tx *gorm.DB) {
		if tx.Statement.Table != "subprojects" {
			return
		}
		attempts++
		if attempts == 1 {
			subprojectCheck(t, s.startWriter(t).Commit())
		}
	}))
	subprojectCheck(t, s.db.Callback().Update().After("gorm:update").Register("test:capture", func(tx *gorm.DB) {
		if tx.Statement.Table == "subprojects" && tx.Error != nil {
			lockErr = tx.Error
		}
	}))
	persisted := s.run(t, `{"subprojects":[{"path":"core","name":"new","kind":"go-module"}]}`)
	assertSubprojectRecovery(t, persisted, attempts, lockErr, 517)
	rows := s.rows(t)
	if len(rows) != 1 || rows[0].ID != s.old.ID || rows[0].Name != "new" || rows[0].DisclosureChannel != s.old.DisclosureChannel {
		t.Fatalf("updated rows: %+v", rows)
	}
}

func assertSubprojectRecovery(t *testing.T, scan db.Scan, attempts int, lockErr error, wantCode int) {
	t.Helper()
	var sqliteErr interface{ Code() int }
	if !errors.As(lockErr, &sqliteErr) || sqliteErr.Code() != wantCode {
		t.Fatalf("lock error=%v, want code %d", lockErr, wantCode)
	}
	if attempts != 2 || scan.Status != db.ScanDone || scan.Error != "" {
		t.Fatalf("attempts=%d status=%s error=%s", attempts, scan.Status, scan.Error)
	}
}

func TestSubprojectsScanIngestionFailure(t *testing.T) {
	s := newSubprojectsScanTest(t)
	attempts := 0
	subprojectCheck(t, s.db.Callback().Delete().Before("gorm:delete").Register("test:failure", func(tx *gorm.DB) {
		if tx.Statement.Table != "subprojects" {
			return
		}
		attempts++
		_ = tx.AddError(errors.New("ingestion unavailable"))
	}))
	persisted := s.run(t, `{"subprojects":[{"path":"core","name":"new","kind":"go-module"}]}`)
	rows := s.rows(t)
	if attempts != 1 || persisted.Status != db.ScanFailed || !strings.Contains(persisted.Error, "ingestion unavailable") || len(rows) != 2 || rows[0].Name != "old" {
		t.Fatalf("attempts=%d scan=%+v rows=%+v", attempts, persisted, rows)
	}
}

type subprojectBusyError struct{}

func (subprojectBusyError) Error() string { return "database busy" }
func (subprojectBusyError) Code() int     { return 5 }

func TestSubprojectWriteTransactionDeadline(t *testing.T) {
	gdb := dbtest.Open(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempts := 0
	err := subprojectWriteTransaction(ctx, gdb, func(tx *gorm.DB) error {
		attempts++
		if err := tx.Create(&db.Subproject{RepositoryID: 1, Path: "rolled-back"}).Error; err != nil {
			return err
		}
		return subprojectBusyError{}
	})
	if !errors.Is(err, context.DeadlineExceeded) || attempts < 2 {
		t.Fatalf("attempts=%d error=%v", attempts, err)
	}
	var count int64
	subprojectCheck(t, gdb.Model(&db.Subproject{}).Count(&count).Error)
	if count != 0 {
		t.Fatalf("partial writes persisted: %d", count)
	}
}

func TestSubprojectWriteTransactionCancelled(t *testing.T) {
	gdb := dbtest.Open(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := subprojectWriteTransaction(ctx, gdb, func(*gorm.DB) error { t.Fatal("write after cancellation"); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}
