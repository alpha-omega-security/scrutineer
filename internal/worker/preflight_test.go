package worker

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func newPreflightWorker(t *testing.T) *Worker {
	t.Helper()
	// Per-test shared-cache in-memory DB so the gorm and goqite handles
	// see the same tables but tests do not share state with each other.
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	gdb, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	q, err := queue.New(sqldb, log, 1)
	if err != nil {
		t.Fatal(err)
	}
	return &Worker{
		DB:                gdb,
		Log:               log,
		Queue:             q,
		PrereqRetryDelay:  10 * time.Millisecond,
		MaxPrereqAttempts: 3,
	}
}

func seedPreflightFixtures(t *testing.T, w *Worker, requires string) *db.Scan {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo"}
	if err := w.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "deep-dive", Body: "x", Requires: requires}
	if err := w.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		Status:       db.ScanQueued,
		SkillName:    skill.Name,
	}
	scan.SkillID = &skill.ID
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return &scan
}

func seedPrereqSkillAndDoneScan(t *testing.T, w *Worker, repoID uint, prereq string) {
	t.Helper()
	s := db.Skill{Name: prereq, Body: "x"}
	if err := w.DB.Create(&s).Error; err != nil {
		t.Fatal(err)
	}
	done := db.Scan{
		RepositoryID: repoID,
		Kind:         JobSkill,
		Status:       db.ScanDone,
		SkillName:    prereq,
	}
	done.SkillID = &s.ID
	if err := w.DB.Create(&done).Error; err != nil {
		t.Fatal(err)
	}
}

func TestPreflightSkill_noRequires(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "")

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deferred {
		t.Error("scan with no requires should dispatch immediately")
	}
}

func TestPreflightSkill_allSatisfied(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model\nsemgrep")
	seedPrereqSkillAndDoneScan(t, w, scan.RepositoryID, "threat-model")
	seedPrereqSkillAndDoneScan(t, w, scan.RepositoryID, "semgrep")

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deferred {
		t.Error("all prereqs satisfied; scan should dispatch")
	}
}

func TestPreflightSkill_missingPrereqRequeues(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model\nsemgrep")
	seedPrereqSkillAndDoneScan(t, w, scan.RepositoryID, "threat-model")
	// semgrep is registered but has no done scan yet
	semgrepSkill := db.Skill{Name: "semgrep", Body: "x"}
	if err := w.DB.Create(&semgrepSkill).Error; err != nil {
		t.Fatal(err)
	}

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred {
		t.Fatal("unsatisfied prereq should defer the scan")
	}

	var loaded db.Scan
	if err := w.DB.First(&loaded, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if loaded.Status != db.ScanQueued {
		t.Errorf("scan status = %q, want queued (re-queue keeps it queued)", loaded.Status)
	}
	if loaded.Error != "" {
		t.Errorf("scan error should be empty during requeue, got %q", loaded.Error)
	}
}

func TestPreflightSkill_unknownPrereqTreatedSatisfied(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "never-registered")

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deferred {
		t.Error("unknown prereq skill should not block dispatch; treated as satisfied")
	}
}

func TestPreflightSkill_attemptCapFailsScan(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model")
	semg := db.Skill{Name: "threat-model", Body: "x"}
	if err := w.DB.Create(&semg).Error; err != nil {
		t.Fatal(err)
	}

	deferred, err := w.preflightSkill(context.Background(), scan, w.MaxPrereqAttempts)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred {
		t.Fatal("attempt cap should defer (caller skips handler)")
	}

	var loaded db.Scan
	if err := w.DB.First(&loaded, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if loaded.Status != db.ScanFailed {
		t.Errorf("scan status = %q, want failed after attempt cap", loaded.Status)
	}
	if loaded.Error == "" {
		t.Error("scan error should explain the missing prereqs")
	}
}

func TestPreflightSkill_doneScanForDifferentRepoDoesNotSatisfy(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model")
	// Seed a done scan for the prereq, but on a different repo.
	otherRepo := db.Repository{URL: "https://example.com/other", Name: "other"}
	if err := w.DB.Create(&otherRepo).Error; err != nil {
		t.Fatal(err)
	}
	seedPrereqSkillAndDoneScan(t, w, otherRepo.ID, "threat-model")

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred {
		t.Error("done scan for a different repo should not satisfy the gate")
	}
}
