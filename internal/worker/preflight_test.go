package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/queue"
)

func newPreflightWorker(t *testing.T) *Worker {
	t.Helper()
	// Copy the cached schema rather than migrating it for every prerequisite
	// case. GORM and goqite still share one isolated database per test.
	gdb := dbtest.Open(t)
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	q, err := queue.New(sqldb, log, 1, queue.SQLite)
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

func seedPrereqSkill(t *testing.T, w *Worker, prereq string, active bool) *db.Skill {
	t.Helper()
	s := db.Skill{Name: prereq, Body: "x", Active: active}
	if err := w.DB.Create(&s).Error; err != nil {
		t.Fatal(err)
	}
	// Active has default:true, so GORM drops a zero-value false on
	// create; flip it with an explicit update.
	if !active {
		if err := w.DB.Model(&s).Update("active", false).Error; err != nil {
			t.Fatal(err)
		}
	}
	return &s
}

func seedPrereqScan(t *testing.T, w *Worker, s *db.Skill, repoID uint, status db.ScanStatus) {
	t.Helper()
	seedPrereqScanInGroup(t, w, s, repoID, status, "")
}

func seedPrereqScanInGroup(t *testing.T, w *Worker, s *db.Skill, repoID uint, status db.ScanStatus, group string) {
	t.Helper()
	scan := db.Scan{
		RepositoryID: repoID,
		Kind:         JobSkill,
		Status:       status,
		SkillName:    s.Name,
		ScanGroup:    group,
	}
	scan.SkillID = &s.ID
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
}

func seedPrereqSkillAndDoneScan(t *testing.T, w *Worker, repoID uint, prereq string) {
	t.Helper()
	s := seedPrereqSkill(t, w, prereq, true)
	seedPrereqScan(t, w, s, repoID, db.ScanDone)
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

func TestWorkerThreatModelFallbackPrerequisites(t *testing.T) {
	cases := []struct {
		name    string
		change  func(*db.Scan, *db.Scan)
		pending bool
		want    db.ScanStatus
	}{
		{name: "failed prerequisites", want: db.ScanDone},
		{name: "manual threat model", change: func(scan, parent *db.Scan) {
			parent.ScanGroup = ""
			scan.ScanGroup = fmt.Sprintf("focus-%d", parent.ID)
		}, want: db.ScanDone},
		{name: "pending prerequisite", pending: true, want: db.ScanQueued},
		{name: "ordinary audit", change: func(scan, _ *db.Scan) { scan.FallbackFromScanID = nil }, want: db.ScanFailed},
		{name: "focused audit", change: func(scan, _ *db.Scan) { scan.FocusArea = `{"name":"parser"}` }, want: db.ScanFailed},
		{name: "different skill", change: func(scan, _ *db.Scan) { scan.SkillName = "other-audit" }, want: db.ScanFailed},
		{name: "different group", change: func(_, parent *db.Scan) { parent.ScanGroup = "other" }, want: db.ScanFailed},
		{name: "different ref", change: func(_, parent *db.Scan) { parent.Ref = "other" }, want: db.ScanFailed},
		{name: "different subpath", change: func(_, parent *db.Scan) { parent.SubPath = "other" }, want: db.ScanFailed},
		{name: "successful threat model", change: func(_, parent *db.Scan) { parent.Status = db.ScanDone }, want: db.ScanFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newPreflightWorker(t)
			w.DataDir = t.TempDir()
			scan := seedPreflightFixtures(t, w, "threat-model\nembedded-native\nsemgrep")
			tm := seedPrereqSkill(t, w, "threat-model", true)
			native := seedPrereqSkill(t, w, "embedded-native", true)
			scan.SkillName, scan.ScanGroup = "security-deep-dive", "triage-1"
			parent := db.Scan{RepositoryID: scan.RepositoryID, SkillID: &tm.ID, SkillName: tm.Name, Kind: JobSkill, Status: db.ScanFailed, ScanGroup: scan.ScanGroup}
			if err := w.DB.Create(&parent).Error; err != nil {
				t.Fatal(err)
			}
			scan.FallbackFromScanID = &parent.ID
			if tc.change != nil {
				tc.change(scan, &parent)
			}
			if err := w.DB.Save(scan).Error; err != nil {
				t.Fatal(err)
			}
			if err := w.DB.Save(&parent).Error; err != nil {
				t.Fatal(err)
			}
			if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Update("name", scan.SkillName).Error; err != nil {
				t.Fatal(err)
			}
			seedPrereqScanInGroup(t, w, native, scan.RepositoryID, db.ScanFailed, scan.ScanGroup)
			if tc.pending {
				semgrep := seedPrereqSkill(t, w, "semgrep", true)
				seedPrereqScanInGroup(t, w, semgrep, scan.RepositoryID, db.ScanRunning, scan.ScanGroup)
			}
			called := dispatchPrereqTestScan(t, w, scan)
			if scan.Status != tc.want || called != (tc.want == db.ScanDone) {
				t.Fatalf("status = %s, handler called = %v, error = %s; want %s", scan.Status, called, scan.Error, tc.want)
			}
		})
	}
}

func dispatchPrereqTestScan(t *testing.T, w *Worker, scan *db.Scan) bool {
	t.Helper()
	body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = w.wrap(func(context.Context, *db.Scan, func(Event)) (string, error) {
		called = true
		return `{"findings":[]}`, nil
	})(t.Context(), body)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.DB.First(scan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	return called
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

func TestPreflightSkill_scanGroupWaitsOnSiblingPrereqs(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model")
	scan.ScanGroup = "grp-1"
	if err := w.DB.Save(scan).Error; err != nil {
		t.Fatal(err)
	}
	tm := seedPrereqSkill(t, w, "threat-model", true)
	seedPrereqScan(t, w, tm, scan.RepositoryID, db.ScanDone)
	seedPrereqScanInGroup(t, w, tm, scan.RepositoryID, db.ScanQueued, scan.ScanGroup)

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred {
		t.Error("same-group queued prereq should block even when an older prereq scan is done")
	}
}

func TestPreflightSkill_scanGroupSatisfiedBySiblingPrereq(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model")
	scan.ScanGroup = "grp-1"
	if err := w.DB.Save(scan).Error; err != nil {
		t.Fatal(err)
	}
	tm := seedPrereqSkill(t, w, "threat-model", true)
	seedPrereqScanInGroup(t, w, tm, scan.RepositoryID, db.ScanDone, scan.ScanGroup)

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deferred {
		t.Error("same-group done prereq should satisfy the gate")
	}
}

func TestWorkerGroupedPrereqsIgnoreOtherGroups(t *testing.T) {
	for _, status := range []db.ScanStatus{db.ScanFailed, db.ScanCancelled, db.ScanQueued, db.ScanRunning, db.ScanPaused, db.ScanDone} {
		t.Run(string(status), func(t *testing.T) {
			w := newPreflightWorker(t)
			w.DataDir = t.TempDir()
			scan := seedPreflightFixtures(t, w, "embedded-native")
			scan.ScanGroup = "today"
			if err := w.DB.Save(scan).Error; err != nil {
				t.Fatal(err)
			}
			prereq := seedPrereqSkill(t, w, "embedded-native", true)
			seedPrereqScanInGroup(t, w, prereq, scan.RepositoryID, status, "yesterday")
			body, err := json.Marshal(queue.Payload{ScanID: scan.ID})
			if err != nil {
				t.Fatal(err)
			}
			called := false
			err = w.wrap(func(context.Context, *db.Scan, func(Event)) (string, error) {
				called = true
				return `{"findings":[]}`, nil
			})(t.Context(), body)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.DB.First(scan, scan.ID).Error; err != nil {
				t.Fatal(err)
			}
			if !called || scan.Status != db.ScanDone {
				t.Fatalf("handler called = %v, scan status = %s, error = %s", called, scan.Status, scan.Error)
			}
		})
	}
}

func TestWorkerPrereqFailureCallsHookOnce(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "exhausted"}[exhausted], func(t *testing.T) {
			w := newPreflightWorker(t)
			scan := seedPreflightFixtures(t, w, "embedded-native")
			prereq := seedPrereqSkill(t, w, "embedded-native", true)
			status, attempt := db.ScanFailed, 0
			if exhausted {
				status, attempt = db.ScanQueued, w.MaxPrereqAttempts
			}
			seedPrereqScan(t, w, prereq, scan.RepositoryID, status)
			calls := 0
			w.OnScanFailed = func(failed *db.Scan) {
				calls++
				var stored db.Scan
				if err := w.DB.First(&stored, failed.ID).Error; err != nil {
					t.Fatal(err)
				}
				if stored.Status != db.ScanFailed || failed.Status != stored.Status || failed.Error != stored.Error || failed.FinishedAt == nil {
					t.Fatalf("failure callback received an unpersisted failure: %+v", failed)
				}
			}
			body, err := json.Marshal(queue.Payload{ScanID: scan.ID, Attempt: attempt})
			if err != nil {
				t.Fatal(err)
			}
			dispatch := w.wrap(func(context.Context, *db.Scan, func(Event)) (string, error) {
				t.Error("handler ran despite failed prerequisites")
				return "", nil
			})
			for range 2 {
				if err := dispatch(t.Context(), body); err != nil {
					t.Fatal(err)
				}
			}
			if calls != 1 {
				t.Fatalf("failure callbacks = %d, want 1", calls)
			}
		})
	}
}

func TestPreflightSkill_missingPrereqRequeues(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model\nsemgrep")
	seedPrereqSkillAndDoneScan(t, w, scan.RepositoryID, "threat-model")
	// semgrep is enqueued on this repo but has no done scan yet
	semgrepSkill := seedPrereqSkill(t, w, "semgrep", true)
	seedPrereqScan(t, w, semgrepSkill, scan.RepositoryID, db.ScanQueued)

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

func TestPreflightSkill_neverEnqueuedPrereqTreatedSatisfied(t *testing.T) {
	// Bundled skills are always registered, so a prereq that triage
	// decided to skip (e.g. zizmor on a no-workflows repo) shows up
	// as registered with zero scan rows on the repo. That must count as
	// satisfied or every such repo deadlocks its deep-dive.
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "zizmor")
	seedPrereqSkill(t, w, "zizmor", true)

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deferred {
		t.Error("prereq never enqueued for the repo should not block dispatch")
	}
}

func TestPreflightSkill_inactivePrereqTreatedSatisfied(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "semgrep")
	semgrep := seedPrereqSkill(t, w, "semgrep", false)
	seedPrereqScan(t, w, semgrep, scan.RepositoryID, db.ScanQueued)

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deferred {
		t.Error("disabled prereq skill should not block dispatch; it can never complete")
	}
}

func TestPrereqBackoff(t *testing.T) {
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 30 * time.Second},
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{4, MaxPrereqRetryDelay},
		{19, MaxPrereqRetryDelay},
	}
	for _, tc := range cases {
		if got := prereqBackoff(30*time.Second, tc.attempt); got != tc.want {
			t.Errorf("prereqBackoff(30s, %d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestPreflightSkill_attemptCapFailsScan(t *testing.T) {
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model")
	tm := seedPrereqSkill(t, w, "threat-model", true)
	seedPrereqScan(t, w, tm, scan.RepositoryID, db.ScanQueued)

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
	// The prereq is enqueued on this repo (not yet done) and done on a
	// different repo; the other repo's result must not satisfy the gate.
	otherRepo := db.Repository{URL: "https://example.com/other", Name: "other"}
	if err := w.DB.Create(&otherRepo).Error; err != nil {
		t.Fatal(err)
	}
	tm := seedPrereqSkill(t, w, "threat-model", true)
	seedPrereqScan(t, w, tm, scan.RepositoryID, db.ScanQueued)
	seedPrereqScan(t, w, tm, otherRepo.ID, db.ScanDone)

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred {
		t.Error("done scan for a different repo should not satisfy the gate")
	}
}

func TestPreflightSkill_failedPrereqFailsFast(t *testing.T) {
	// Every scan for the prereq on this repo is terminal but not done;
	// it will never recover on its own, so the dependent fails on the
	// first preflight rather than spending the retry budget waiting.
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model")
	tm := seedPrereqSkill(t, w, "threat-model", true)
	seedPrereqScan(t, w, tm, scan.RepositoryID, db.ScanFailed)
	seedPrereqScan(t, w, tm, scan.RepositoryID, db.ScanCancelled)

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred {
		t.Fatal("dead prereq should defer (caller skips handler)")
	}

	var loaded db.Scan
	if err := w.DB.First(&loaded, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if loaded.Status != db.ScanFailed {
		t.Errorf("scan status = %q, want failed immediately on dead prereq", loaded.Status)
	}
	if !strings.Contains(loaded.Error, "threat-model") || !strings.Contains(loaded.Error, "failed") {
		t.Errorf("scan error should name the dead prereq and say it failed, got %q", loaded.Error)
	}
}

func TestPreflightSkill_failedPrereqWithRetryInFlightDefers(t *testing.T) {
	// One failed run plus a queued retry: the prereq can still complete,
	// so defer rather than fail-fast.
	w := newPreflightWorker(t)
	scan := seedPreflightFixtures(t, w, "threat-model")
	tm := seedPrereqSkill(t, w, "threat-model", true)
	seedPrereqScan(t, w, tm, scan.RepositoryID, db.ScanFailed)
	seedPrereqScan(t, w, tm, scan.RepositoryID, db.ScanQueued)

	deferred, err := w.preflightSkill(context.Background(), scan, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred {
		t.Fatal("in-flight retry should defer, not dispatch")
	}

	var loaded db.Scan
	if err := w.DB.First(&loaded, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	if loaded.Status != db.ScanQueued {
		t.Errorf("scan status = %q, want queued (defer while retry is in flight)", loaded.Status)
	}
}
