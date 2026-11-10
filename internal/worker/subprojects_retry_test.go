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

func newSubprojectsScanTest(t *testing.T, gdb *gorm.DB) subprojectsScanTest {
	t.Helper()
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
	s := newSubprojectsScanTest(t, dbtest.OpenBusyTimeout(t, 100*time.Millisecond))
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
	s := newSubprojectsScanTest(t, dbtest.Open(t))
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
	s := newSubprojectsScanTest(t, dbtest.Open(t))
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

// A replayed transaction must not reuse ids from the attempt that rolled
// back: another writer can take them in between.
func TestIngestReplaysAfterBusy(t *testing.T) {
	cases := []struct {
		kind, table, report string
		other               func(repoID, scanID uint) any
	}{
		{"packages", "packages", `{"packages":[{"name":"new","ecosystem":"npm","purl":"pkg:npm/new"}]}`,
			func(repoID, _ uint) any { return &db.Package{RepositoryID: repoID, Name: "other"} }},
		{"advisories", "advisories", `{"advisories":[{"uuid":"u1","title":"t"}]}`,
			func(repoID, _ uint) any { return &db.Advisory{RepositoryID: repoID, UUID: "other"} }},
		{"dependencies", "dependencies", depEnvelope(`[{"name":"a","ecosystem":"npm","type":"runtime","manifest_path":"package.json"}]`, ""),
			func(repoID, _ uint) any { return &db.Dependency{RepositoryID: repoID, Name: "other"} }},
		{"compliance", "compliance_controls", `{"schema_version":1,"framework":"openssf-baseline","total":1,"controls":[{"id":"OSPS-AC-01.01","level":1,"status":"FAIL","details":"MFA off","source":"darnit"}]}`,
			func(repoID, scanID uint) any {
				return &db.ComplianceControl{RepositoryID: repoID, ScanID: scanID, ControlID: "other", Level: 1, Status: "PASS", Source: "darnit"}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			s := newSubprojectsScanTest(t, dbtest.Open(t))
			subprojectCheck(t, s.db.Model(&db.Skill{}).Where("id = ?", *s.scan.SkillID).Update("output_kind", tc.kind).Error)
			otherRepo := db.Repository{URL: "https://example.com/other", Name: "other"}
			subprojectCheck(t, s.db.Create(&otherRepo).Error)
			attempts := 0
			concurrent := false
			subprojectCheck(t, s.db.Callback().Create().Before("gorm:create").Register("test:concurrent", func(tx *gorm.DB) {
				if tx.Statement.Table != tc.table || concurrent {
					return
				}
				attempts++
				if attempts == 2 {
					concurrent = true
					_ = tx.AddError(tx.Session(&gorm.Session{NewDB: true}).Create(tc.other(otherRepo.ID, s.scan.ID)).Error)
					concurrent = false
				}
			}))
			subprojectCheck(t, s.db.Callback().Create().After("gorm:create").Register("test:busy", func(tx *gorm.DB) {
				if tx.Statement.Table == tc.table && attempts == 1 {
					_ = tx.AddError(subprojectBusyError{})
				}
			}))
			scan := s.run(t, tc.report)
			var saved int64
			subprojectCheck(t, s.db.Table(tc.table).Where("repository_id = ?", s.scan.RepositoryID).Count(&saved).Error)
			if attempts != 2 || scan.Status != db.ScanDone || saved != 1 {
				t.Fatalf("attempts=%d status=%s error=%q saved=%d", attempts, scan.Status, scan.Error, saved)
			}
		})
	}
}

func TestCriticReplaysAfterBusy(t *testing.T) {
	attempts := 0
	report := `{"production_viability":"VIABLE","source_state":"PRESENT","reason":"Reachable in the default build.","counterevidence":[],"attacker_position":"remote unauthenticated client","preconditions":[],"impact":"input reaches the sink","likelihood":"plausible","applied_adjustments":[],"facts_that_would_change_the_result":[]}`
	f, gdb := runSkillWithFindingOn(t, "critic", report, db.FindingEnriched, func(gdb *gorm.DB) {
		subprojectCheck(t, gdb.Callback().Create().After("gorm:create").Register("test:busy", func(tx *gorm.DB) {
			if tx.Statement.Table != "finding_attack_paths" {
				return
			}
			attempts++
			if attempts == 1 {
				_ = tx.AddError(subprojectBusyError{})
			}
		}))
	})
	var rows int64
	subprojectCheck(t, gdb.Model(&db.FindingAttackPath{}).Where("finding_id = ?", f.ID).Count(&rows).Error)
	if attempts != 2 || rows != 1 || f.ProductionViability != db.ProductionViabilityViable {
		t.Fatalf("attempts=%d rows=%d viability=%q", attempts, rows, f.ProductionViability)
	}
}
