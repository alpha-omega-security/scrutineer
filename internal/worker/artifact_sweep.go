package worker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"scrutineer/internal/db"
)

// sweepOrphanScanArtifacts removes workspaces left behind when a process exits
// before finalizeScan reaches its terminal cleanup. A workspace that still
// backs an active resume must survive so the resumed harness can find its
// source tree and session store. A resumable terminal scan can shed its stale
// workspace, but keeps the harness state needed by a future retry.
func (w *Worker) sweepOrphanScanArtifacts() (int, error) {
	if w.DB == nil || w.DataDir == "" {
		return 0, nil
	}
	workspaceIDs, workspaceErr := scanArtifactIDs(w.DataDir)
	stateIDs, stateErr := scanArtifactIDs(filepath.Join(w.DataDir, harnessStateDirName))
	candidates := make(map[uint]bool, len(workspaceIDs)+len(stateIDs))
	for scanID := range workspaceIDs {
		candidates[scanID] = true
	}
	for scanID := range stateIDs {
		if _, ok := candidates[scanID]; !ok {
			candidates[scanID] = false
		}
	}

	var removed int
	sweepErr := errors.Join(workspaceErr, stateErr)
	for scanID, hasWorkspace := range candidates {
		reap, preserveState, err := w.scanArtifactSweepDecision(scanID)
		if err != nil {
			sweepErr = errors.Join(sweepErr, err)
			continue
		}
		if !reap {
			continue
		}
		if preserveState && !hasWorkspace {
			continue
		}
		var removeErr error
		if preserveState {
			removeErr = os.RemoveAll(w.workRoot(scanID))
		} else {
			removeErr = w.RemoveScanArtifacts(scanID)
		}
		if removeErr != nil {
			sweepErr = errors.Join(sweepErr, fmt.Errorf("remove scan %d artifacts: %w", scanID, removeErr))
			continue
		}
		removed++
	}
	return removed, sweepErr
}

func scanArtifactIDs(root string) (map[uint]struct{}, error) {
	ids := make(map[uint]struct{})
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return ids, nil
		}
		return ids, fmt.Errorf("read scan artifact root %s: %w", root, err)
	}
	for _, entry := range entries {
		if scanID, ok := scanArtifactEntryID(entry); ok {
			ids[scanID] = struct{}{}
		}
	}
	return ids, nil
}

func scanArtifactEntryID(entry os.DirEntry) (uint, bool) {
	if !entry.IsDir() {
		return 0, false
	}
	rawID, ok := strings.CutPrefix(entry.Name(), "scan-")
	if !ok || rawID == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(rawID, 10, strconv.IntSize)
	if err != nil || id == 0 {
		return 0, false
	}
	return uint(id), true
}

func (w *Worker) scanArtifactSweepDecision(scanID uint) (reap, preserveState bool, err error) {
	var scan db.Scan
	if err := w.DB.Model(&db.Scan{}).
		Select("id, status, session_id, max_turns_hit, cost_capped").
		Where("id = ?", scanID).
		Limit(1).
		Find(&scan).Error; err != nil {
		return false, false, fmt.Errorf("load scan %d for artifact sweep: %w", scanID, err)
	}
	if scan.ID != 0 && !scan.Status.Terminal() {
		return false, false, nil
	}

	var activeResumes int64
	if err := w.DB.Model(&db.Scan{}).
		Where("resumed_from_scan_id = ? AND status IN ?", scanID, []db.ScanStatus{
			db.ScanQueued,
			db.ScanRunning,
			db.ScanPaused,
		}).
		Count(&activeResumes).Error; err != nil {
		return false, false, fmt.Errorf("check scan %d resume references: %w", scanID, err)
	}
	if activeResumes > 0 {
		return false, false, nil
	}
	if scan.ID == 0 {
		return true, false, nil
	}

	return true, scan.Resumable(), nil
}
