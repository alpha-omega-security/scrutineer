package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// reportRunner stands in for an agent run: it records whether the workspace
// already held report.json, optionally writes one, announces a session and
// returns what is in report.json afterwards, as the real runners do.
type reportRunner struct {
	session string
	write   string
	symlink string
	err     error
	seen    string
	got     SkillJob
}

func (r *reportRunner) RunSkill(_ context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	r.got = sj
	path := filepath.Join(sj.WorkRoot, defaultSkillOutputFile)
	if data, err := os.ReadFile(path); err == nil {
		r.seen = string(data)
	}
	switch {
	case r.symlink != "":
		if err := os.Symlink(r.symlink, path); err != nil {
			return SkillResult{}, err
		}
	case r.write != "":
		if err := os.WriteFile(path, []byte(r.write), 0o600); err != nil {
			return SkillResult{}, err
		}
	}
	if r.session != "" {
		emit(Event{Kind: KindSession, SessionID: r.session})
	}
	return SkillResult{Report: readCappedReport(path, emit), SessionID: r.session}, r.err
}

func (*reportRunner) SkillDir(workRoot, name string) string {
	return ClaudeHarness{}.SkillDir(workRoot, name)
}

func createSkillScan(t *testing.T, w *Worker, skill *db.Skill, repoID uint, scan db.Scan) db.Scan {
	t.Helper()
	scan.RepositoryID = repoID
	scan.Kind = JobSkill
	scan.Status = db.ScanQueued
	scan.SkillID = &skill.ID
	if err := w.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return scan
}

func retryOf(t *testing.T, w *Worker, skill *db.Skill, repoID uint, parent db.Scan) db.Scan {
	t.Helper()
	root := workspaceScanID(&parent)
	return createSkillScan(t, w, skill, repoID, db.Scan{SessionID: parent.SessionID, ResumedFromScanID: &root})
}

func savedResumeReport(w *Worker, rootID uint) string {
	data, err := os.ReadFile(filepath.Join(w.resumeReportDirID(rootID), defaultSkillOutputFile))
	if err != nil {
		return ""
	}
	return string(data)
}

const partialReport = `{"findings":[{"title":"partial"}]}`

func TestResumeReportCarriedToResumedRetry(t *testing.T) {
	runner := &reportRunner{session: "sess-1", write: partialReport, err: errors.New("container killed")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	first := createSkillScan(t, w, skill, repoID, db.Scan{})

	got := runScan(t, w, first.ID)
	if got.Status != db.ScanFailed || got.SessionID != "sess-1" {
		t.Fatalf("first attempt = %s session %q, want failed with its session", got.Status, got.SessionID)
	}
	assertPathMissing(t, w.workRoot(first.ID))
	if saved := savedResumeReport(w, first.ID); saved != partialReport {
		t.Fatalf("saved report = %q, want the partial report", saved)
	}
	if !strings.Contains(got.Log, "kept the partial ./report.json") {
		t.Errorf("log does not say the report was kept:\n%s", got.Log)
	}

	*runner = reportRunner{session: "sess-1", err: errors.New("still stuck")}
	second := retryOf(t, w, skill, repoID, got)
	got = runScan(t, w, second.ID)
	if runner.seen != partialReport {
		t.Fatalf("resumed run saw report.json = %q, want the restored partial report", runner.seen)
	}
	if runner.got.restoredReport != partialReport || runner.got.ResumeSessionID != "sess-1" {
		t.Fatalf("job = restored %q resume %q", runner.got.restoredReport, runner.got.ResumeSessionID)
	}
	if !strings.Contains(got.Log, "restored the partial ./report.json") {
		t.Errorf("log does not say the report was restored:\n%s", got.Log)
	}
	if saved := savedResumeReport(w, first.ID); saved != partialReport {
		t.Fatalf("saved report after a second failure = %q, want it kept", saved)
	}
}

func TestResumeReportKeepsEarlierCopyWhenAttemptWritesNothing(t *testing.T) {
	runner := &reportRunner{session: "sess-1", write: partialReport, err: errors.New("timeout")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	first := runScan(t, w, createSkillScan(t, w, skill, repoID, db.Scan{}).ID)

	// removingRunner deletes the restored copy before the run, modelling an
	// attempt that leaves no output behind.
	*runner = reportRunner{session: "sess-1", err: errors.New("timeout")}
	second := retryOf(t, w, skill, repoID, first)
	w.Runner = removingRunner{runner}
	runScan(t, w, second.ID)
	if saved := savedResumeReport(w, first.ID); saved != partialReport {
		t.Fatalf("saved report = %q, want the earlier attempt's copy", saved)
	}
}

// removingRunner deletes report.json before delegating, so the attempt ends
// with no output file in the workspace.
type removingRunner struct{ *reportRunner }

func (r removingRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	_ = os.Remove(filepath.Join(sj.WorkRoot, defaultSkillOutputFile))
	return r.reportRunner.RunSkill(ctx, sj, emit)
}

func TestResumeReportReplacedByNewerAttempt(t *testing.T) {
	runner := &reportRunner{session: "sess-1", write: partialReport, err: errors.New("timeout")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	first := runScan(t, w, createSkillScan(t, w, skill, repoID, db.Scan{}).ID)

	const newer = `{"findings":[{"title":"partial"},{"title":"more"}]}`
	*runner = reportRunner{session: "sess-1", write: newer, err: errors.New("timeout")}
	runScan(t, w, retryOf(t, w, skill, repoID, first).ID)
	if saved := savedResumeReport(w, first.ID); saved != newer {
		t.Fatalf("saved report = %q, want the newer attempt's report", saved)
	}
}

func TestResumeReportDroppedWhenSessionRestartsFresh(t *testing.T) {
	runner := &reportRunner{session: "sess-1", write: partialReport, err: errors.New("timeout")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	first := runScan(t, w, createSkillScan(t, w, skill, repoID, db.Scan{}).ID)

	// The harness lost the conversation and started a new session. That
	// agent finished without touching the restored file.
	*runner = reportRunner{session: "sess-2"}
	got := runScan(t, w, retryOf(t, w, skill, repoID, first).ID)
	if runner.seen != partialReport {
		t.Fatalf("run saw report.json = %q, want the restored copy", runner.seen)
	}
	if got.Status != db.ScanDone || got.Report != "" {
		t.Fatalf("scan = %s report %q, want done without the stale report", got.Status, got.Report)
	}
	if !strings.Contains(got.Log, "ignoring it") {
		t.Errorf("log does not say the stale report was ignored:\n%s", got.Log)
	}
	// A clean finish ends the lineage's resume state.
	if saved := savedResumeReport(w, first.ID); saved != "" {
		t.Fatalf("saved report after a clean finish = %q, want removed", saved)
	}
}

func TestResumeReportKeptWhenSessionResumes(t *testing.T) {
	runner := &reportRunner{session: "sess-1", write: partialReport, err: errors.New("timeout")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	first := runScan(t, w, createSkillScan(t, w, skill, repoID, db.Scan{}).ID)

	*runner = reportRunner{session: "sess-1"}
	got := runScan(t, w, retryOf(t, w, skill, repoID, first).ID)
	if got.Status != db.ScanDone || got.Report != partialReport {
		t.Fatalf("scan = %s report %q, want the resumed session's report", got.Status, got.Report)
	}
}

func TestResumeReportNotSavedForCleanFinishOrNoSession(t *testing.T) {
	runner := &reportRunner{write: partialReport, err: errors.New("failed before a session")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	noSession := runScan(t, w, createSkillScan(t, w, skill, repoID, db.Scan{}).ID)
	if saved := savedResumeReport(w, noSession.ID); saved != "" {
		t.Fatalf("saved report without a session = %q", saved)
	}

	*runner = reportRunner{session: "sess-1", write: partialReport}
	done := runScan(t, w, createSkillScan(t, w, skill, repoID, db.Scan{}).ID)
	if done.Status != db.ScanDone {
		t.Fatalf("status = %s, want done", done.Status)
	}
	assertPathMissing(t, w.resumeReportDirID(done.ID))
}

func TestResumeReportRefusesSymlink(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte(`{"secret":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.Symlink(outside, probe); err != nil {
		t.Skip("symlinks unavailable")
	}
	runner := &reportRunner{session: "sess-1", symlink: outside, err: errors.New("timeout")}
	w, skill, repoID := newResumeTestWorker(t, runner)
	got := runScan(t, w, createSkillScan(t, w, skill, repoID, db.Scan{}).ID)
	if got.Status != db.ScanFailed {
		t.Fatalf("status = %s, want failed", got.Status)
	}
	assertPathMissing(t, w.resumeReportDirID(got.ID))
}

func TestRemoveScanArtifactsRemovesResumeReport(t *testing.T) {
	w := &Worker{DataDir: t.TempDir()}
	if err := writeResumeReport(w.resumeReportDirID(4), defaultSkillOutputFile, partialReport); err != nil {
		t.Fatal(err)
	}
	if err := w.RemoveScanArtifacts(4); err != nil {
		t.Fatal(err)
	}
	assertPathMissing(t, w.resumeReportDirID(4))
}

func TestSweepOrphanScanArtifactsResumeReport(t *testing.T) {
	w, skill, repoID := newResumeTestWorker(t, &reportRunner{})
	resumable := createSkillScan(t, w, skill, repoID, db.Scan{})
	finished := createSkillScan(t, w, skill, repoID, db.Scan{})
	w.DB.Model(&resumable).Updates(map[string]any{"status": db.ScanFailed, "session_id": "sess-1"})
	w.DB.Model(&finished).Updates(map[string]any{"status": db.ScanDone})
	for _, id := range []uint{resumable.ID, finished.ID} {
		if err := writeResumeReport(w.resumeReportDirID(id), defaultSkillOutputFile, partialReport); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := w.sweepOrphanScanArtifacts(); err != nil {
		t.Fatal(err)
	}
	assertPathExists(t, w.resumeReportDirID(resumable.ID))
	assertPathMissing(t, w.resumeReportDirID(finished.ID))
}
