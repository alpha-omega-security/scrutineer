package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

const (
	diffPatchFile          = "diff.patch"
	changedFilesFile       = "changed_files.json"
	oldThreatModelFile     = "old_threat_model.json"
	maxDiffPatchBytes      = 1 << 20
	maxDiffChangedFileRows = 200
	nameStatusMinColumns   = 2
	nameStatusRenameCols   = 3
)

type diffStats struct {
	BaseCommit        string         `json:"base_commit"`
	HeadCommit        string         `json:"head_commit"`
	ChangedFiles      int            `json:"changed_files"`
	PatchBytes        int            `json:"patch_bytes"`
	StatusCounts      map[string]int `json:"status_counts"`
	Files             []changedFile  `json:"files,omitempty"`
	ChangedFilesFile  string         `json:"changed_files_file,omitempty"`
	DiffFile          string         `json:"diff_file,omitempty"`
	ThreatModelScanID uint           `json:"threat_model_scan_id,omitempty"`
	Limits            map[string]int `json:"limits"`
}

type changedFile struct {
	Status string `json:"status"`
	Path   string `json:"path"`
	Old    string `json:"old,omitempty"`
}

func (w *Worker) prepareDiffRescan(ctx context.Context, scan *db.Scan, workRoot string, emit func(Event)) error {
	if scan.RescanMode != db.ScanRescanModeDiff {
		return nil
	}
	if scan.Commit == "" {
		w.fallbackDiffScan(scan, "current scan has no git commit identity")
		return nil
	}

	baseline, ok := w.diffBaseline(scan)
	if !ok {
		w.fallbackDiffScan(scan, "no compatible baseline scan with a commit")
		return nil
	}
	if baseline.Commit == scan.Commit {
		w.fallbackDiffScan(scan, "baseline commit equals current commit")
		return nil
	}
	scan.DiffBaseScanID = &baseline.ID
	scan.DiffBaseCommit = baseline.Commit

	diffDir := filepath.Join(workRoot, "src")
	if !scan.Repository.IsLocal() {
		if err := w.EnsureCommit(ctx, scan.Repository.URL, baseline.Commit); err != nil {
			w.fallbackDiffScan(scan, "baseline commit could not be fetched: "+err.Error())
			return nil
		}
		diffDir = filepath.Join(RepoCacheRoot(w.DataDir, scan.Repository.URL), "src")
	}
	if !commitReachable(ctx, diffDir, baseline.Commit) {
		w.fallbackDiffScan(scan, "baseline commit is unreachable")
		return nil
	}
	if !commitReachable(ctx, diffDir, scan.Commit) {
		w.fallbackDiffScan(scan, "current commit is unreachable")
		return nil
	}

	rangeSpec := baseline.Commit + ".." + scan.Commit
	nameStatusArgs := diffGitArgs(diffDir, rangeSpec, scan.SubPath, "--name-status")
	nameStatus, err := git(ctx, nameStatusArgs...)
	if err != nil {
		w.fallbackDiffScan(scan, "could not list changed files: "+strings.TrimSpace(nameStatus))
		return nil
	}
	changed := parseChangedFiles(nameStatus)
	if len(changed) == 0 {
		w.fallbackDiffScan(scan, "diff is empty")
		return nil
	}
	if len(changed) > maxDiffChangedFileRows {
		w.fallbackDiffScan(scan, fmt.Sprintf("diff changed %d files; limit is %d", len(changed), maxDiffChangedFileRows))
		return nil
	}

	patchArgs := diffGitArgs(diffDir, rangeSpec, scan.SubPath)
	patch, err := git(ctx, patchArgs...)
	if err != nil {
		w.fallbackDiffScan(scan, "could not generate diff: "+strings.TrimSpace(patch))
		return nil
	}
	if len(patch) > maxDiffPatchBytes {
		w.fallbackDiffScan(scan, fmt.Sprintf("diff patch is %d bytes; limit is %d", len(patch), maxDiffPatchBytes))
		return nil
	}

	if err := stageDiffFiles(workRoot, patch, changed); err != nil {
		return err
	}
	tmID, err := w.stageOldThreatModel(workRoot, scan)
	if err != nil {
		return err
	}
	scan.DiffThreatModelScanID = tmID
	scan.DiffStats = mustJSON(diffStats{
		BaseCommit:        baseline.Commit,
		HeadCommit:        scan.Commit,
		ChangedFiles:      len(changed),
		PatchBytes:        len(patch),
		StatusCounts:      countChangedStatuses(changed),
		Files:             changed,
		ChangedFilesFile:  changedFilesFile,
		DiffFile:          diffPatchFile,
		ThreatModelScanID: uintValue(tmID),
		Limits: map[string]int{
			"patch_bytes":   maxDiffPatchBytes,
			"changed_files": maxDiffChangedFileRows,
		},
	})
	// The changed-file list the worker staged itself is the only scope it
	// knows independently of the skill, so it is the only scope a
	// completeness verdict can honestly be reconciled against. No receipts
	// exist yet at staging time, so this starts partial and names why.
	setCoverage(scan, coverage.Record{
		RequestedMode: db.ScanRescanModeDiff,
		ActualMode:    db.ScanRescanModeDiff,
		Completeness:  coverage.CompletenessPartial,
		Reason:        "scan has not reported receipts for the staged changed files",
		IncludedPaths: changedPaths(changed),
	})
	if err := w.DB.Model(scan).Updates(map[string]any{
		"rescan_mode":               scan.RescanMode,
		"diff_base_scan_id":         scan.DiffBaseScanID,
		"diff_base_commit":          scan.DiffBaseCommit,
		"diff_threat_model_scan_id": scan.DiffThreatModelScanID,
		"diff_stats":                scan.DiffStats,
		"coverage":                  scan.Coverage,
		"completeness":              scan.Completeness,
	}).Error; err != nil {
		return fmt.Errorf("save diff rescan metadata: %w", err)
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("diff rescan: staged %d changed file(s), %d byte patch", len(changed), len(patch))})
	return nil
}

func (w *Worker) diffBaseline(scan *db.Scan) (db.Scan, bool) {
	// Not(map) lets GORM's dialector quote the reserved-word column
	// (`commit` on SQLite, "commit" on Postgres) instead of hardcoding one style.
	q := w.DB.Where("repository_id = ? AND status = ?", scan.RepositoryID, db.ScanDone).
		Not(map[string]any{"commit": ""})
	if scan.DiffBaseScanID != nil {
		q = q.Where("id = ?", *scan.DiffBaseScanID)
	} else {
		q = q.Where("skill_name = ? AND sub_path = ? AND ref = ? AND focus_area = ? AND id <> ?", scan.SkillName, scan.SubPath, scan.Ref, scan.FocusArea, scan.ID).
			Order("id desc")
	}
	var baseline db.Scan
	if err := q.First(&baseline).Error; err != nil {
		return db.Scan{}, false
	}
	if baseline.RepositoryID != scan.RepositoryID || baseline.SubPath != scan.SubPath || baseline.Ref != scan.Ref {
		return db.Scan{}, false
	}
	if baseline.SkillName != scan.SkillName || baseline.FocusArea != scan.FocusArea {
		return db.Scan{}, false
	}
	return baseline, true
}

func diffGitArgs(diffDir, rangeSpec, subPath string, opts ...string) []string {
	args := []string{"-C", diffDir, "diff"}
	args = append(args, opts...)
	args = append(args, "--find-renames", rangeSpec)
	if pathspec := diffSubPathspec(subPath); pathspec != "" {
		args = append(args, "--", pathspec)
	}
	return args
}

func diffSubPathspec(subPath string) string {
	subPath = filepath.ToSlash(filepath.Clean(strings.TrimSpace(subPath)))
	if subPath == "." || subPath == ".." || strings.HasPrefix(subPath, "../") {
		return ""
	}
	return strings.TrimPrefix(subPath, "/")
}

func (w *Worker) fallbackDiffScan(scan *db.Scan, reason string) {
	scan.RescanMode = db.ScanRescanModeFull
	scan.DiffBaseScanID = nil
	scan.DiffBaseCommit = ""
	scan.DiffThreatModelScanID = nil
	scan.DiffStats = ""
	// A fallback ran as a full scan, and a full scan has no enumerable
	// scope until #20's work manifest exists, so the honest verdict is
	// unknown rather than complete.
	setCoverage(scan, coverage.Record{
		RequestedMode:  db.ScanRescanModeDiff,
		ActualMode:     db.ScanRescanModeFull,
		FallbackReason: reason,
		Completeness:   coverage.CompletenessUnknown,
		Reason:         "no enumerable scope for a full scan",
	})
	if err := w.DB.Model(scan).Updates(map[string]any{
		"rescan_mode":               db.ScanRescanModeFull,
		"diff_base_scan_id":         nil,
		"diff_base_commit":          "",
		"diff_threat_model_scan_id": nil,
		"diff_stats":                "",
		"coverage":                  scan.Coverage,
		"completeness":              scan.Completeness,
	}).Error; err != nil && w.Log != nil {
		w.Log.Warn("save diff rescan fallback", "scan", scan.ID, "reason", reason, "err", err)
	}
}

func stageDiffFiles(workRoot, patch string, changed []changedFile) error {
	if err := os.WriteFile(filepath.Join(workRoot, diffPatchFile), []byte(patch), filePerm); err != nil {
		return fmt.Errorf("stage diff patch: %w", err)
	}
	raw, err := json.MarshalIndent(changed, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(workRoot, changedFilesFile), raw, filePerm); err != nil {
		return fmt.Errorf("stage changed files: %w", err)
	}
	return nil
}

func (w *Worker) stageOldThreatModel(workRoot string, scan *db.Scan) (*uint, error) {
	var tm db.Scan
	err := w.DB.Where("repository_id = ? AND skill_name = ? AND status = ? AND report <> ''", scan.RepositoryID, "threat-model", db.ScanDone).
		Where("id <> ?", scan.ID).
		Order("id desc").
		First(&tm).Error
	if err != nil {
		return nil, nil
	}
	if err := os.WriteFile(filepath.Join(workRoot, oldThreatModelFile), []byte(tm.Report), filePerm); err != nil {
		return nil, fmt.Errorf("stage old threat model: %w", err)
	}
	return &tm.ID, nil
}

func parseChangedFiles(raw string) []changedFile {
	var out []changedFile
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < nameStatusMinColumns {
			continue
		}
		status := parts[0]
		if status == "" {
			continue
		}
		if strings.HasPrefix(status, "R") && len(parts) >= nameStatusRenameCols {
			out = append(out, changedFile{Status: "R", Old: parts[1], Path: parts[2]})
			continue
		}
		out = append(out, changedFile{Status: status[:1], Path: parts[1]})
	}
	return out
}

func countChangedStatuses(changed []changedFile) map[string]int {
	out := map[string]int{}
	for _, f := range changed {
		out[f.Status]++
	}
	return out
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func uintValue(v *uint) uint {
	if v == nil {
		return 0
	}
	return *v
}

// setCoverage renders a coverage record onto the scan and keeps the indexed
// Completeness column in step with it, so the two can never disagree.
func setCoverage(scan *db.Scan, rec coverage.Record) {
	raw, err := coverage.Marshal(rec)
	if err != nil {
		return
	}
	scan.Coverage = raw
	scan.Completeness = rec.Completeness
	if scan.Completeness == "" {
		scan.Completeness = coverage.CompletenessUnknown
	}
}

// changedPaths is the staged diff's file set as a plain path list, which is
// what a receipt reconciliation matches against. Renames are recorded under
// their new path, matching how the skill sees the tree at the head commit.
func changedPaths(changed []changedFile) []string {
	if len(changed) == 0 {
		return nil
	}
	paths := make([]string, 0, len(changed))
	for _, f := range changed {
		if f.Path != "" {
			paths = append(paths, f.Path)
		}
	}
	return paths
}
