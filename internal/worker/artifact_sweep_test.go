package worker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

func TestSweepOrphanScanArtifacts(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	createScan := func(scan db.Scan) db.Scan {
		t.Helper()
		scan.RepositoryID = repo.ID
		scan.Kind = JobSkill
		if err := gdb.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		return scan
	}

	crashed := createScan(db.Scan{Status: db.ScanRunning, SessionID: "crashed-session"})
	historical := createScan(db.Scan{Status: db.ScanFailed})
	maxTurns := createScan(db.Scan{
		Status: db.ScanDone, SessionID: "max-turns-session", MaxTurnsHit: true,
	})
	queuedRoot := createScan(db.Scan{Status: db.ScanFailed})
	createScan(db.Scan{Status: db.ScanQueued, ResumedFromScanID: &queuedRoot.ID})
	pausedRoot := createScan(db.Scan{Status: db.ScanFailed})
	createScan(db.Scan{Status: db.ScanPaused, ResumedFromScanID: &pausedRoot.ID})
	queued := createScan(db.Scan{Status: db.ScanQueued})
	stateOnly := createScan(db.Scan{Status: db.ScanFailed, SessionID: "state-only-session"})

	w := &Worker{DB: gdb, DataDir: t.TempDir()}
	withArtifacts := []uint{
		crashed.ID,
		historical.ID,
		maxTurns.ID,
		queuedRoot.ID,
		pausedRoot.ID,
		queued.ID,
	}
	for _, id := range withArtifacts {
		writeScanArtifact(t, w.workRoot(id))
		writeScanArtifact(t, w.harnessStateDirID(id))
	}
	writeScanArtifact(t, w.harnessStateDirID(stateOnly.ID))
	writeScanArtifact(t, filepath.Join(w.DataDir, "scan-not-an-id"))
	if err := os.WriteFile(filepath.Join(w.DataDir, "scan-9999"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := db.SweepRunning(gdb); err != nil {
		t.Fatal(err)
	}
	removed, err := w.sweepOrphanScanArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 3 {
		t.Fatalf("removed = %d, want 3", removed)
	}

	for _, id := range []uint{crashed.ID, historical.ID, maxTurns.ID} {
		assertPathMissing(t, w.workRoot(id))
	}
	assertPathExists(t, w.harnessStateDirID(crashed.ID))
	assertPathExists(t, w.harnessStateDirID(maxTurns.ID))
	assertPathMissing(t, w.harnessStateDirID(historical.ID))
	for _, id := range []uint{queuedRoot.ID, pausedRoot.ID, queued.ID} {
		assertPathExists(t, w.workRoot(id))
		assertPathExists(t, w.harnessStateDirID(id))
	}
	assertPathExists(t, w.harnessStateDirID(stateOnly.ID))
	assertPathExists(t, filepath.Join(w.DataDir, "scan-not-an-id"))
	assertPathExists(t, filepath.Join(w.DataDir, "scan-9999"))
}

func TestSweepOrphanScanArtifactsRemovesNonResumableState(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		Status:       db.ScanCancelled,
		SessionID:    "not-resumable",
	}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	w := &Worker{DB: gdb, DataDir: t.TempDir()}
	writeScanArtifact(t, w.harnessStateDirID(scan.ID))
	removed, err := w.sweepOrphanScanArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	assertPathMissing(t, w.harnessStateDirID(scan.ID))
}

func TestSweepOrphanScanArtifactsRemovesMissingScanRow(t *testing.T) {
	gdb := dbtest.Open(t)
	w := &Worker{DB: gdb, DataDir: t.TempDir()}
	const missingScanID = 404
	writeScanArtifact(t, w.workRoot(missingScanID))
	writeScanArtifact(t, w.harnessStateDirID(missingScanID))

	removed, err := w.sweepOrphanScanArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	assertPathMissing(t, w.workRoot(missingScanID))
	assertPathMissing(t, w.harnessStateDirID(missingScanID))
}

func TestSweepOrphanScanArtifactsMissingRootIsNoop(t *testing.T) {
	gdb := dbtest.Open(t)
	w := &Worker{DB: gdb, DataDir: filepath.Join(t.TempDir(), "missing")}
	removed, err := w.sweepOrphanScanArtifacts()
	if err != nil {
		t.Fatal(err)
	}
	if removed != 0 {
		t.Fatalf("removed = %d, want 0", removed)
	}
}

func writeScanArtifact(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "artifact"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected %s to be removed, stat error = %v", path, err)
	}
}
