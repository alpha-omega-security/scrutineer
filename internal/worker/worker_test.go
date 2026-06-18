package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

type blockingRunner struct {
	started chan struct{}
}

func (b blockingRunner) RunSkill(ctx context.Context, _ SkillJob, _ func(Event)) (SkillResult, error) {
	close(b.started)
	<-ctx.Done()
	return SkillResult{}, ctx.Err()
}

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

func TestWorker_claudePlanLimitPausesScanAndQueue(t *testing.T) {
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
		Runner:         fakeRunner{skillErr: &ClaudePlanLimitError{Detail: "usage limit reached"}},
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
	if !strings.Contains(got.Error, "Claude plan limit reached") {
		t.Errorf("error = %q", got.Error)
	}

	var gotOther db.Scan
	gdb.First(&gotOther, other.ID)
	if gotOther.Status != db.ScanPaused {
		t.Errorf("other queued scan status = %s, want paused", gotOther.Status)
	}
	if !strings.Contains(gotOther.Error, "Claude plan limit reached") {
		t.Errorf("other scan error = %q, want plan-limit prefix", gotOther.Error)
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
// flush interval, in-memory scan.Log grows on every event but the DB log
// column stays at the value from the most recent flush. SSE publish fires
// on every event regardless of the flush cadence so the live UI stays
// real-time. wrap()'s final Save persists scan.Log along with every other
// column, so a scan that finishes mid-batch still lands its full log.
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
	emit := w.scanEmitter(&scan)

	for i := 0; i < 5; i++ {
		emit(Event{Kind: "text", Text: "line"})
	}

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
	emit := w.scanEmitter(&scan)
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
	emit := w.scanEmitter(&scan)
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
