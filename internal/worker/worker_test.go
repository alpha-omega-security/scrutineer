package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func TestMaybeFireScanFailed(t *testing.T) {
	var calls int
	w := &Worker{OnScanFailed: func(scan *db.Scan) {
		if scan.Status != db.ScanFailed {
			t.Errorf("status = %q, want failed", scan.Status)
		}
		calls++
	}}
	w.maybeFireScanFailed(&db.Scan{Status: db.ScanDone})
	w.maybeFireScanFailed(&db.Scan{Status: db.ScanFailed})
	if calls != 1 {
		t.Fatalf("failure callbacks = %d, want 1", calls)
	}
}

func TestMigrateLegacyState_renamesStateDir(t *testing.T) {
	dataDir := t.TempDir()
	oldDir := filepath.Join(dataDir, legacyHarnessStateDirName, "scan-7")
	if err := os.MkdirAll(oldDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "session.json"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &Worker{DataDir: dataDir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.migrateLegacyState()
	// The scan-7 store must now live under the new name.
	if _, err := os.Stat(filepath.Join(w.harnessStateDirID(7), "session.json")); err != nil {
		t.Fatalf("session store not found under renamed dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, legacyHarnessStateDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy dir still present after migration: %v", err)
	}
	// A second run is a no-op.
	w.migrateLegacyState()
	if _, err := os.Stat(filepath.Join(w.harnessStateDirID(7), "session.json")); err != nil {
		t.Fatalf("second migrateLegacyState clobbered the state dir: %v", err)
	}
}

func TestMigrateLegacyState_rewritesPausePrefix(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://x/r", Name: "r"}
	gdb.Create(&repo)
	// A scan paused with the pre-rename prefix, and one with a plain user
	// pause that must not be touched.
	legacy := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused,
		Error: legacyAccountPausePrefix + " This scan and queued scans were paused; resume once the account recovers."}
	other := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: "paused by user"}
	gdb.Create(&legacy)
	gdb.Create(&other)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	w.migrateLegacyState()

	var got db.Scan
	gdb.First(&got, legacy.ID)
	if !strings.HasPrefix(got.Error, AccountPausePrefix) {
		t.Errorf("legacy prefix not rewritten: %q", got.Error)
	}
	// The single-pattern LIKE the auto-resume queries use must now find it.
	var n int64
	gdb.Model(&db.Scan{}).Where("error LIKE ?", AccountPausePrefix+"%").Count(&n)
	if n != 1 {
		t.Errorf("post-migration LIKE match count = %d, want 1", n)
	}
	var gotOther db.Scan
	gdb.First(&gotOther, other.ID)
	if gotOther.Error != "paused by user" {
		t.Errorf("unrelated pause was rewritten: %q", gotOther.Error)
	}
}

// stubPrepareRepoSrc pretends a clone happened so doSkill's repo-cache
// step never hits the network. Tests exercising the unreachable path
// replace this with a function returning *RepoUnreachableError.
func stubPrepareRepoSrc(_ context.Context, _, _, workRoot string, _ func(Event)) (string, error) {
	return "abc", os.MkdirAll(filepath.Join(workRoot, "src"), 0o755)
}

// fakeRunner stubs the SkillRunner for unit tests: emits a log line so the
// wrap() path is exercised and returns a pre-set result. Shared by the
// skill and parser test files in this package.
type fakeRunner struct {
	skillRes SkillResult
	skillErr error
	session  string
}

func (f fakeRunner) RunSkill(_ context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	emit(Event{Kind: "text", Text: "running skill " + sj.Name})
	if f.session != "" {
		emit(Event{Kind: KindSession, SessionID: f.session})
	}
	return f.skillRes, f.skillErr
}

func (fakeRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

type blockingRunner struct {
	started chan struct{}
}

func (b blockingRunner) RunSkill(ctx context.Context, _ SkillJob, _ func(Event)) (SkillResult, error) {
	close(b.started)
	<-ctx.Done()
	return SkillResult{}, ctx.Err()
}

func (blockingRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func (blockingRunner) Backend() string { return "codex" }

func TestWorker_CancelStopsRunningScan(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "slow", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)

	runner := blockingRunner{started: make(chan struct{})}
	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         runner,
		PrepareRepoSrc: stubPrepareRepoSrc,
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	done := make(chan error, 1)
	go func() { done <- w.wrap(w.doSkill)(context.Background(), body) }()

	<-runner.started
	// Backend is stamped on the row when it transitions to running, before
	// RunSkill returns, so a server restart mid-run leaves it resumable
	// under the same backend.
	var midRun db.Scan
	gdb.First(&midRun, scan.ID)
	if midRun.Backend != "codex" {
		t.Errorf("scan.Backend = %q while RunSkill in flight, want codex", midRun.Backend)
	}
	if !w.Cancel(scan.ID) {
		t.Fatal("Cancel reported scan not running")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("wrap returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("job did not stop after cancel")
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %s, want cancelled (err=%q)", got.Status, got.Error)
	}
	if w.Cancel(scan.ID) {
		t.Error("Cancel returned true after job finished")
	}
}

func TestEffectiveMaxTurns(t *testing.T) {
	tests := []struct {
		perSkill, global, want int
	}{
		{50, 200, 50},
		{0, 200, 200},
		{0, 0, DefaultSkillMaxTurns},
		{10, 0, 10},
	}
	for _, tc := range tests {
		got := effectiveMaxTurns(tc.perSkill, tc.global)
		if got != tc.want {
			t.Errorf("effectiveMaxTurns(%d, %d) = %d, want %d", tc.perSkill, tc.global, got, tc.want)
		}
	}
}

func TestWorker_maxTurnsReachedCompletesNotFails(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "mt.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "capped", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1, MaxTurns: 5}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)

	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillRes: SkillResult{Report: `{"partial":true}`}, skillErr: &MaxTurnsReachedError{}, session: "sess-1"},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Errorf("status = %s, want done", got.Status)
	}
	if got.Report != `{"partial":true}` {
		t.Errorf("report = %q, want partial report preserved", got.Report)
	}
	if !got.MaxTurnsHit {
		t.Error("MaxTurnsHit = false, want true")
	}
	if got.SessionID != "sess-1" {
		t.Errorf("session id = %q, want preserved max-turns session", got.SessionID)
	}
}

func TestWorker_claudeAccountErrorPausesScanAndQueue(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "limit.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "limited", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)
	// A second queued scan (e.g. from a "scan all subprojects" batch) that
	// has not started yet; it must be paused, not left to hit the same wall.
	other := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&other)

	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillErr: &AccountError{Detail: "usage limit reached"}},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanPaused {
		t.Errorf("triggering scan status = %s, want paused", got.Status)
	}
	if !strings.Contains(got.Error, AccountPausePrefix) {
		t.Errorf("error = %q", got.Error)
	}

	var gotOther db.Scan
	gdb.First(&gotOther, other.ID)
	if gotOther.Status != db.ScanPaused {
		t.Errorf("other queued scan status = %s, want paused", gotOther.Status)
	}
	if !strings.Contains(gotOther.Error, AccountPausePrefix) {
		t.Errorf("other scan error = %q, want account-pause prefix", gotOther.Error)
	}
}

func TestWorker_claudeAccountErrorRecordsResetTime(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "limit-reset.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "limited", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)
	other := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&other)

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	resetAt := now.Add(15 * time.Minute)
	w := &Worker{
		DB:               gdb,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:          t.TempDir(),
		Runner:           fakeRunner{skillErr: &AccountError{Detail: "rate limit reached", ResetAt: &resetAt}},
		PrepareRepoSrc:   stubPrepareRepoSrc,
		Now:              func() time.Time { return now },
		LogFlushInterval: time.Hour,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	for _, id := range []uint{scan.ID, other.ID} {
		var got db.Scan
		gdb.First(&got, id)
		if got.PausedUntil == nil || !got.PausedUntil.Equal(resetAt) {
			t.Fatalf("scan %d paused_until = %v, want %v", id, got.PausedUntil, resetAt)
		}
		if !strings.Contains(got.Error, "Auto-resume after 2026-07-01T12:15:00Z") {
			t.Errorf("scan %d error = %q, want auto-resume timestamp", id, got.Error)
		}
		if id == scan.ID && !strings.Contains(got.Log, "rate limit reset detected; auto-resume after 2026-07-01T12:15:00Z") {
			t.Errorf("trigger log = %q, want persisted reset diagnostic", got.Log)
		}
	}
}

func TestWorker_claudeAccountErrorRejectsFarFutureReset(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "limit-far-reset.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "limited", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)
	other := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&other)

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	resetAt := now.Add(9 * 24 * time.Hour) // beyond the 8-day auto-resume cap
	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillErr: &AccountError{Detail: "rate limit reached", ResetAt: &resetAt}},
		PrepareRepoSrc: stubPrepareRepoSrc,
		Now:            func() time.Time { return now },
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	for _, id := range []uint{scan.ID, other.ID} {
		var got db.Scan
		gdb.First(&got, id)
		if got.PausedUntil != nil {
			t.Fatalf("scan %d paused_until = %v, want nil for far reset", id, got.PausedUntil)
		}
	}
}

func TestWorker_applyAccountPauseResetExtendsBatchForward(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "extend-batch.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	fiveHour := now.Add(15 * time.Minute)
	sevenDay := now.Add(7 * 24 * time.Hour)
	later := sevenDay.Add(24 * time.Hour)
	wantReset := later

	paused1 := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: accountPauseReason(&fiveHour), PausedUntil: &fiveHour}
	paused2 := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: accountPauseReason(&fiveHour), PausedUntil: &fiveHour}
	// Prior trigger row with its own Claude detail.
	triggerAErr := appendAutoResume((&AccountError{Detail: "rate limit reached"}).Error(), &fiveHour)
	triggerA := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: triggerAErr, PausedUntil: &fiveHour}
	triggerD := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: AccountPausePrefix + " Provider reported: rate limit", PausedUntil: nil}
	manual := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: "paused by user", PausedUntil: &fiveHour}
	longPaused := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: accountPauseReason(&later), PausedUntil: &later}
	gdb.Create(&paused1)
	gdb.Create(&paused2)
	gdb.Create(&triggerA)
	gdb.Create(&triggerD)
	gdb.Create(&manual)
	gdb.Create(&longPaused)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	effective, err := w.applyAccountPauseReset(triggerD.ID, triggerD.Error, &sevenDay)
	if err != nil {
		t.Fatal(err)
	}
	if effective == nil || !effective.Equal(wantReset) {
		t.Fatalf("effective reset = %v, want %v", effective, wantReset)
	}

	get := func(id uint) db.Scan {
		var s db.Scan
		gdb.First(&s, id)
		return s
	}
	if d := get(triggerD.ID); d.PausedUntil == nil || !d.PausedUntil.Equal(wantReset) {
		t.Errorf("trigger paused_until = %v, want %v", d.PausedUntil, wantReset)
	}
	for _, id := range []uint{paused1.ID, paused2.ID} {
		if s := get(id); s.PausedUntil == nil || !s.PausedUntil.Equal(wantReset) {
			t.Errorf("paused scan %d paused_until = %v, want extended to %v", id, s.PausedUntil, wantReset)
		}
	}
	if a := get(triggerA.ID); a.PausedUntil == nil || !a.PausedUntil.Equal(wantReset) {
		t.Errorf("earlier trigger paused_until = %v, want extended to %v", a.PausedUntil, wantReset)
	}
	if a := get(triggerA.ID); !strings.Contains(a.Error, "Provider reported: rate limit reached") {
		t.Errorf("earlier trigger lost its detail: %q", a.Error)
	}
	if a := get(triggerA.ID); !strings.Contains(a.Error, "Auto-resume after "+wantReset.UTC().Format(time.RFC3339)) ||
		strings.Contains(a.Error, fiveHour.UTC().Format(time.RFC3339)) {
		t.Errorf("earlier trigger suffix not swapped to effective reset: %q", a.Error)
	}
	if s := get(manual.ID); s.PausedUntil == nil || !s.PausedUntil.Equal(fiveHour) || s.Error != "paused by user" {
		t.Errorf("manual pause modified: paused_until=%v error=%q", s.PausedUntil, s.Error)
	}
	if s := get(longPaused.ID); s.PausedUntil == nil || !s.PausedUntil.Equal(later) {
		t.Errorf("long-paused row paused_until = %v, want unchanged %v", s.PausedUntil, later)
	}
}

func TestWorker_applyAccountPauseResetTriggerForwardOnly(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "trigger-forward.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	fiveHour := now.Add(15 * time.Minute)
	sevenDay := now.Add(7 * 24 * time.Hour)

	// A concurrent finalizer already pushed this scan's own row to seven days.
	triggerErr := appendAutoResume((&AccountError{Detail: "rate limit reached"}).Error(), &sevenDay)
	trigger := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: triggerErr, PausedUntil: &sevenDay}
	gdb.Create(&trigger)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	// This finalizer's own reset is an earlier five-hour: it must not pull the
	// row back, and must return the row's actual later reset.
	effective, err := w.applyAccountPauseReset(trigger.ID, (&AccountError{Detail: "rate limit reached"}).Error(), &fiveHour)
	if err != nil {
		t.Fatal(err)
	}
	if effective == nil || !effective.Equal(sevenDay) {
		t.Fatalf("effective = %v, want seven-day %v (re-read)", effective, sevenDay)
	}
	var got db.Scan
	gdb.First(&got, trigger.ID)
	if got.PausedUntil == nil || !got.PausedUntil.Equal(sevenDay) {
		t.Errorf("trigger pulled back to %v, want kept at %v", got.PausedUntil, sevenDay)
	}
}

func TestWorker_applyAccountPauseResetIgnoresFarFutureRow(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "far-future.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	fiveHour := now.Add(15 * time.Minute)
	farFuture := now.Add(30 * 24 * time.Hour) // beyond the 8-day auto-resume cap

	// A stale/manual account-paused row far beyond the auto-resume window.
	far := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: accountPauseReason(&farFuture), PausedUntil: &farFuture}
	trigger := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: (&AccountError{Detail: "rate limit reached"}).Error(), PausedUntil: nil}
	gdb.Create(&far)
	gdb.Create(&trigger)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	effective, err := w.applyAccountPauseReset(trigger.ID, trigger.Error, &fiveHour)
	if err != nil {
		t.Fatal(err)
	}
	// The far-future row must not drag the batch out; effective stays five-hour.
	if effective == nil || !effective.Equal(fiveHour) {
		t.Fatalf("effective = %v, want five-hour %v (far row ignored)", effective, fiveHour)
	}
	var gotFar db.Scan
	gdb.First(&gotFar, far.ID)
	if gotFar.PausedUntil == nil || !gotFar.PausedUntil.Equal(farFuture) {
		t.Errorf("far row modified: %v, want unchanged %v", gotFar.PausedUntil, farFuture)
	}
}

func TestWorker_applyAccountPauseResetMaxUsesUTCComparison(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "max-utc.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)

	nowUTC := time.Date(2026, 7, 1, 12, 1, 0, 0, time.UTC)
	nowLocal := nowUTC.In(time.FixedZone("PDT", -7*60*60))
	fiveHour := nowUTC.Add(15 * time.Minute)
	validLater := nowUTC.Add(8*24*time.Hour - time.Minute)

	longPaused := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: accountPauseReason(&validLater), PausedUntil: &validLater}
	trigger := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, Error: (&AccountError{Detail: "rate limit reached"}).Error(), PausedUntil: nil}
	gdb.Create(&longPaused)
	gdb.Create(&trigger)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return nowLocal }}
	effective, err := w.applyAccountPauseReset(trigger.ID, trigger.Error, &fiveHour)
	if err != nil {
		t.Fatal(err)
	}
	if effective == nil || !effective.Equal(validLater) {
		t.Fatalf("effective = %v, want valid later reset %v", effective, validLater)
	}
}

func TestWorker_applyAccountPauseResetSkipsResumedTrigger(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "resumed-trigger.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	fiveHour := now.Add(15 * time.Minute)

	// The trigger was manually resumed (queued, no reset) before this reset
	// landed: the reset must not revive it, and effective must not be bumped off
	// its stale value.
	trigger := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, Error: "", PausedUntil: nil}
	gdb.Create(&trigger)

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}
	effective, err := w.applyAccountPauseReset(trigger.ID, (&AccountError{Detail: "rate limit reached"}).Error(), &fiveHour)
	if err != nil {
		t.Fatal(err)
	}
	if effective == nil || !effective.Equal(fiveHour) {
		t.Fatalf("effective = %v, want five-hour %v (no stale bump)", effective, fiveHour)
	}
	var got db.Scan
	gdb.First(&got, trigger.ID)
	if got.Status != db.ScanQueued || got.PausedUntil != nil {
		t.Errorf("resumed trigger resurrected: status=%s paused_until=%v", got.Status, got.PausedUntil)
	}
}

func TestWorker_recordRateLimitStatus(t *testing.T) {
	w := &Worker{}
	if len(w.RateLimitStatus()) != 0 {
		t.Fatal("empty worker should report no rate-limit status")
	}
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", Status: "allowed", ResetsAt: 100})
	w.recordRateLimit(RateLimitInfo{Type: "seven_day", Status: "allowed", ResetsAt: 200})
	w.recordRateLimit(RateLimitInfo{Type: "five_hour", Status: "rejected", ResetsAt: 300}) // latest wins per type
	w.recordRateLimit(RateLimitInfo{Type: ""})                                             // no type: ignored

	got := w.RateLimitStatus()
	if len(got) != 2 {
		t.Fatalf("status count = %d, want 2", len(got))
	}
	byType := map[string]RateLimitInfo{}
	for _, s := range got {
		byType[s.Type] = s
	}
	if byType["five_hour"].Status != "rejected" || byType["five_hour"].ResetsAt != 300 {
		t.Errorf("five_hour = %+v, want latest rejected/300", byType["five_hour"])
	}
	if byType["seven_day"].ResetsAt != 200 {
		t.Errorf("seven_day = %+v, want 200", byType["seven_day"])
	}
}

func TestWorker_resumeAccountPaused(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "resume-account.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	q, err := queue.New(sqldb, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "limited", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	due := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, SkillID: &skill.ID, Error: accountPauseReason(&past), PausedUntil: &past}
	notDue := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, SkillID: &skill.ID, Error: accountPauseReason(&future), PausedUntil: &future}
	manual := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, SkillID: &skill.ID, Error: "paused by user", PausedUntil: &past}
	gdb.Create(&due)
	gdb.Create(&notDue)
	gdb.Create(&manual)

	w := &Worker{
		DB:    gdb,
		Queue: q,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:   func() time.Time { return now },
	}
	resumed, err := w.resumeAccountPaused(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resumed != 1 {
		t.Fatalf("resumed = %d, want 1", resumed)
	}

	var gotDue, gotNotDue, gotManual db.Scan
	gdb.First(&gotDue, due.ID)
	gdb.First(&gotNotDue, notDue.ID)
	gdb.First(&gotManual, manual.ID)
	if gotDue.Status != db.ScanQueued || gotDue.PausedUntil != nil || gotDue.Error != "" {
		t.Errorf("due scan = status %s paused_until %v error %q", gotDue.Status, gotDue.PausedUntil, gotDue.Error)
	}
	if gotNotDue.Status != db.ScanPaused {
		t.Errorf("notDue status = %s, want paused", gotNotDue.Status)
	}
	if gotManual.Status != db.ScanPaused {
		t.Errorf("manual status = %s, want paused", gotManual.Status)
	}
}

func TestWorker_resumeAccountPausedUsesUTCComparison(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "resume-account-utc.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	q, err := queue.New(sqldb, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "limited", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)

	resetAt := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	nowLocal := resetAt.Add(time.Minute).In(time.FixedZone("PDT", -7*60*60))
	due := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, SkillID: &skill.ID, Error: accountPauseReason(&resetAt), PausedUntil: &resetAt}
	gdb.Create(&due)

	w := &Worker{
		DB:    gdb,
		Queue: q,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:   func() time.Time { return nowLocal },
	}
	resumed, err := w.resumeAccountPaused(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resumed != 1 {
		t.Fatalf("resumed = %d, want 1", resumed)
	}
}

func TestAppendAutoResumeFailure(t *testing.T) {
	reset := time.Date(2026, 7, 1, 12, 15, 0, 0, time.UTC)
	base := (&AccountError{Detail: "rate limit reached"}).Error()
	enqErr := errors.New("enqueue: closed")

	// A row carrying an auto-resume timestamp: the stale timestamp is dropped
	// so the message doesn't claim resume-at-past alongside a failure.
	withReset := appendAutoResume(base, &reset)
	got := appendAutoResumeFailure(withReset, enqErr)
	if strings.Contains(got, autoResumeAfterPrefix) || strings.Contains(got, "2026-07-01T12:15:00Z") {
		t.Errorf("stale auto-resume timestamp kept: %q", got)
	}
	if !strings.Contains(got, "rate limit reached") {
		t.Errorf("Claude detail lost: %q", got)
	}
	if !strings.HasSuffix(got, autoResumeFailurePrefix+"enqueue: closed") {
		t.Errorf("failure suffix = %q", got)
	}

	// A prior failure suffix is replaced, not stacked.
	got2 := appendAutoResumeFailure(got, errors.New("enqueue: still closed"))
	if strings.Count(got2, autoResumeFailurePrefix) != 1 || strings.Contains(got2, "enqueue: closed"+autoResumeFailurePrefix) {
		t.Errorf("failure suffix stacked: %q", got2)
	}
	if !strings.HasSuffix(got2, "enqueue: still closed") {
		t.Errorf("second failure = %q", got2)
	}

	// Empty message falls through to the shared account-pause reason.
	if got := appendAutoResumeFailure("", enqErr); !strings.HasPrefix(got, AccountPausePrefix) {
		t.Errorf("empty msg = %q, want account-pause prefix", got)
	}

	// Oversized detail is truncated.
	long := strings.Repeat("x", maxAutoResumeErrorBytes+100)
	if got := appendAutoResumeFailure(base, errors.New(long)); len(got) > len(base)+len(autoResumeFailurePrefix)+maxAutoResumeErrorBytes+10 {
		t.Errorf("failure detail not truncated: %d bytes", len(got))
	}
}

func TestWorker_resumeAccountPausedRestoreOnEnqueueError(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "resume-account-restore.db"))
	if err != nil {
		t.Fatal(err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	q, err := queue.New(sqldb, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "limited", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Minute)
	errText := accountPauseReason(&past) + autoResumeFailurePrefix + "old error"
	due := db.Scan{
		RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, SkillID: &skill.ID,
		Error: errText, PausedUntil: &past,
	}
	gdb.Create(&due)

	w := &Worker{
		DB:    gdb,
		Queue: q,
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:   func() time.Time { return now },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resumed, err := w.resumeAccountPaused(ctx)
	if err == nil {
		t.Fatal("resumeAccountPaused error = nil, want enqueue error")
	}
	if resumed != 0 {
		t.Fatalf("resumed = %d, want 0", resumed)
	}

	var got db.Scan
	gdb.First(&got, due.ID)
	if got.Status != db.ScanPaused {
		t.Fatalf("status = %s, want paused", got.Status)
	}
	if got.FinishedAt == nil {
		t.Fatal("finished_at = nil, want restored pause timestamp")
	}
	if strings.Count(got.Error, autoResumeFailurePrefix) != 1 {
		t.Fatalf("error = %q, want one auto-resume failure suffix", got.Error)
	}
	if strings.Contains(got.Error, "old error") {
		t.Fatalf("error = %q, old failure detail should have been replaced", got.Error)
	}
	if strings.Contains(got.Error, autoResumeAfterPrefix) {
		t.Fatalf("error = %q, stale auto-resume timestamp should have been dropped", got.Error)
	}
}

func TestWorker_skipsPausedScan(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "paused.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "paused", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanPaused, SkillID: &skill.ID}
	gdb.Create(&scan)

	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillErr: errors.New("should not run")},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanPaused {
		t.Errorf("status = %s, want paused", got.Status)
	}
	if got.Error != "" {
		t.Errorf("paused scan should not run; error = %q", got.Error)
	}
}

func TestWorker_workspaceCleanup(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "wc.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "noop", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)

	dataDir := t.TempDir()
	run := func(r SkillRunner) (db.Scan, string) {
		scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
		gdb.Create(&scan)
		w := &Worker{
			DB:             gdb,
			Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
			DataDir:        dataDir,
			Runner:         r,
			PrepareRepoSrc: stubPrepareRepoSrc,
		}
		body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
		if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
			t.Fatalf("wrap: %v", err)
		}
		gdb.First(&scan, scan.ID)
		return scan, w.workRoot(scan.ID)
	}

	// Successful scan: workspace removed.
	ok, okRoot := run(fakeRunner{skillRes: SkillResult{Report: ""}})
	if ok.Status != db.ScanDone {
		t.Fatalf("status = %s, want done (err=%q)", ok.Status, ok.Error)
	}
	if _, err := os.Stat(okRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace %s not removed after successful scan", okRoot)
	}

	// Failed scan: workspace also removed (prevents disk exhaustion).
	fail, failRoot := run(fakeRunner{skillErr: errors.New("boom")})
	if fail.Status != db.ScanFailed {
		t.Fatalf("status = %s, want failed", fail.Status)
	}
	if _, err := os.Stat(failRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("workspace %s not removed after failed scan", failRoot)
	}
}

// TestScanEmitter_batchesDBWrites pins the batching behaviour: with a long
// flush interval, the append buffer grows while scan.Log and the DB log column
// stay at the value from the most recent snapshot. SSE publish fires on every
// event regardless of the flush cadence so the live UI stays real-time. The
// explicit snapshot models wrap()'s final persistence boundary.
func TestScanEmitter_batchesDBWrites(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "emit.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanRunning}
	gdb.Create(&scan)

	var published int
	w := &Worker{
		DB:               gdb,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		LogFlushInterval: time.Hour,
		OnEvent:          func(_, _ uint, _, _ string) { published++ },
	}
	emit, snapshot := w.scanEmitter(&scan)

	for i := 0; i < 5; i++ {
		emit(Event{Kind: "text", Text: "line"})
	}
	snapshot()

	if strings.Count(scan.Log, "line") != 5 {
		t.Errorf("in-memory scan.Log should hold all 5 events, got %q", scan.Log)
	}
	if published != 5 {
		t.Errorf("publish should fire on every event regardless of flush cadence: got %d, want 5", published)
	}
	var row db.Scan
	gdb.First(&row, scan.ID)
	if row.Log != "" {
		t.Errorf("DB log should be empty until interval elapses, got %q", row.Log)
	}
}

func TestScanEmitter_preservesManyEventsAcrossFlushes(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "emit_many.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanRunning}
	gdb.Create(&scan)

	w := &Worker{
		DB:               gdb,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		LogFlushInterval: time.Nanosecond,
	}
	emit, snapshot := w.scanEmitter(&scan)

	var want strings.Builder
	for i := 0; i < 256; i++ {
		e := Event{Kind: KindText, Text: fmt.Sprintf("line-%03d", i)}
		emit(e)
		want.WriteString(FormatEvent(e))
		want.WriteByte('\n')
	}
	snapshot()

	if scan.Log != want.String() {
		t.Fatalf("in-memory log does not contain every event in order")
	}
	var row db.Scan
	gdb.First(&row, scan.ID)
	if row.Log != want.String() {
		t.Fatalf("persisted log does not contain every event in order")
	}
}

// TestScanEmitter_flushesWhenIntervalElapses checks the positive case:
// a zero-or-tiny interval triggers the DB UPDATE on every event so a
// stuck/long-running scan still streams its log to disk.
func TestScanEmitter_flushesWhenIntervalElapses(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "emit_short.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanRunning}
	gdb.Create(&scan)

	w := &Worker{
		DB:               gdb,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		LogFlushInterval: time.Nanosecond,
	}
	emit, _ := w.scanEmitter(&scan)
	// Sleep past the interval so the very first event triggers a flush.
	time.Sleep(time.Microsecond)
	emit(Event{Kind: "text", Text: "first"})

	var row db.Scan
	gdb.First(&row, scan.ID)
	if !strings.Contains(row.Log, "first") {
		t.Errorf("DB log should be flushed after interval elapses, got %q", row.Log)
	}
}

// TestScanEmitter_sessionWritesBypassBatching confirms that a session id
// hits the DB on the event it arrives in even when the log-flush window
// is open. A crash between batched flushes must still leave the scan
// resumable via the persisted session id.
func TestScanEmitter_sessionWritesBypassBatching(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "emit_session.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanRunning}
	gdb.Create(&scan)

	w := &Worker{
		DB:               gdb,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		LogFlushInterval: time.Hour,
	}
	emit, _ := w.scanEmitter(&scan)
	emit(Event{Kind: KindSession, SessionID: "sess-123"})

	var row db.Scan
	gdb.First(&row, scan.ID)
	if row.SessionID != "sess-123" {
		t.Errorf("session id should persist immediately, got %q", row.SessionID)
	}
}

// TestScanEmitter_finalSaveCoversUnflushedTail walks the full wrap() path
// with a long flush interval to prove the closing Save persists the
// buffered log tail. Without that, a scan that finishes in under
// LogFlushInterval would land in the DB with an empty log column.
func TestScanEmitter_finalSaveCoversUnflushedTail(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "tail.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "fast", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)

	w := &Worker{
		DB:               gdb,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:          t.TempDir(),
		Runner:           fakeRunner{skillRes: SkillResult{Report: ""}},
		PrepareRepoSrc:   stubPrepareRepoSrc,
		LogFlushInterval: time.Hour,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if !strings.Contains(got.Log, "running skill fast") {
		t.Errorf("final Save should persist the buffered log tail; got %q", got.Log)
	}
}

func TestScanEmitter_failedFinalSaveCoversUnflushedTail(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "failed_tail.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "fast", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)

	w := &Worker{
		DB:               gdb,
		Log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:          t.TempDir(),
		Runner:           fakeRunner{skillErr: errors.New("boom")},
		PrepareRepoSrc:   stubPrepareRepoSrc,
		LogFlushInterval: time.Hour,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanFailed {
		t.Errorf("status = %s, want failed", got.Status)
	}
	if !strings.Contains(got.Log, "running skill fast") {
		t.Errorf("failed final Save should persist the buffered log tail; got %q", got.Log)
	}
}

// TestWorker_maxTurnsParseFailureLogged pins the contract that a partial
// report from a max-turns run is parsed best-effort and a malformed
// payload surfaces as a warn log instead of being silently dropped. The
// scan still completes as ScanDone because the max-turns path treats a
// hit cap as completion, not failure; the log line is the only signal
// to operators that the partial wasn't usable.
func TestWorker_maxTurnsParseFailureLogged(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "mtparse.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{Name: "maint", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1, OutputKind: "maintainers", MaxTurns: 5}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID}
	gdb.Create(&scan)

	var logBuf bytes.Buffer
	w := &Worker{
		DB:             gdb,
		Log:            slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})),
		DataDir:        t.TempDir(),
		Runner:         fakeRunner{skillRes: SkillResult{Report: "not json"}, skillErr: &MaxTurnsReachedError{}},
		PrepareRepoSrc: stubPrepareRepoSrc,
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Errorf("status = %s, want done (max-turns still completes)", got.Status)
	}
	if !strings.Contains(logBuf.String(), "parse partial skill output after max turns") {
		t.Errorf("expected warn log about partial parse, got: %s", logBuf.String())
	}
}
