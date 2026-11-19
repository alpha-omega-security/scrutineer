package worker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"scrutineer/internal/db"
)

const resumeReportDirName = "resume-report"

func (w *Worker) resumeReportDirID(scanID uint) string {
	return filepath.Join(w.DataDir, resumeReportDirName, fmt.Sprintf("scan-%d", scanID))
}

// resumeReportDir is keyed by the resume lineage root, like the workspace and
// harness state, so every retry in a lineage finds the same copy.
func (w *Worker) resumeReportDir(scan *db.Scan) string {
	return w.resumeReportDirID(workspaceScanID(scan))
}

// keepsResumeState reports whether a finished run leaves a session a retry or
// an auto-resume will continue.
func keepsResumeState(scan *db.Scan) bool {
	return scan.Resumable() || (scan.Status == db.ScanPaused && scan.SessionID != "")
}

func (w *Worker) saveResumeReport(scan *db.Scan, emit func(Event)) {
	if scan.Kind != JobSkill || scan.SkillID == nil || !keepsResumeState(scan) {
		return
	}
	w.saveLineageReport(workspaceScanID(scan), *scan.SkillID, emit)
}

// saveLineageReport keeps the earlier copy when the workspace holds no output file.
func (w *Worker) saveLineageReport(rootID, skillID uint, emit func(Event)) {
	var skill db.Skill
	if err := w.DB.Select("id, name, output_file").First(&skill, skillID).Error; err != nil {
		w.Log.Warn("resume report: load skill", "scan", rootID, "err", err)
		return
	}
	if skill.OutputFile == "" || validateSkillPaths(skill.Name, skill.OutputFile) != nil {
		return
	}
	name := skill.OutputFile
	report := readCappedReport(filepath.Join(w.workRoot(rootID), name), emit)
	if report == "" {
		return
	}
	if err := writeResumeReport(w.resumeReportDirID(rootID), name, report); err != nil {
		w.Log.Warn("resume report: save", "scan", rootID, "err", err)
		return
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("kept the partial ./%s (%d bytes) for a retry to resume from", name, len(report))})
}

// writeResumeReport goes through a temporary file so a crash never leaves a truncated copy.
func writeResumeReport(dir, name, report string) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(report); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// restoreResumeReport returns what it wrote so dropStaleRestoredReport can spot untouched bytes.
func (w *Worker) restoreResumeReport(workRoot string, scan *db.Scan, skill *db.Skill, emit func(Event)) string {
	if scan.SessionID == "" || skill.OutputFile == "" {
		return ""
	}
	name := skill.OutputFile
	report := readCappedReport(filepath.Join(w.resumeReportDir(scan), name), emit)
	if report == "" {
		return ""
	}
	if err := replaceWorkspaceFile(workRoot, name, []byte(report)); err != nil {
		emit(Event{Kind: KindError, Text: fmt.Sprintf("restore partial ./%s: %v", name, err)})
		return ""
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("restored the partial ./%s (%d bytes) from the previous attempt", name, len(report))})
	return report
}

// dropStaleRestoredReport removes both copies because a fresh session would otherwise get the
// old bytes back as its own on the next retry.
func (w *Worker) dropStaleRestoredReport(scan *db.Scan, sj SkillJob, report string, emit func(Event)) string {
	if sj.restoredReport == "" || report != sj.restoredReport || scan.SessionID == sj.ResumeSessionID {
		return report
	}
	emit(Event{Kind: KindText, Text: "the session was not resumed and the restored partial report was left unchanged; ignoring it"})
	if err := removeWorkspaceEntry(sj.WorkRoot, sj.OutputFile); err != nil {
		emit(Event{Kind: KindError, Text: fmt.Sprintf("remove stale ./%s: %v", sj.OutputFile, err)})
	}
	w.removeResumeReport(scan)
	return ""
}

// removeWorkspaceEntry goes through os.Root so an agent-planted link cannot redirect it.
func removeWorkspaceEntry(workRoot, name string) error {
	if name == "" || !filepath.IsLocal(name) {
		return nil
	}
	root, err := os.OpenRoot(workRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.RemoveAll(name)
}

// removeResumeReport drops the saved copy once the lineage no longer needs it.
func (w *Worker) removeResumeReport(scan *db.Scan) {
	if err := os.RemoveAll(w.resumeReportDir(scan)); err != nil && !errors.Is(err, os.ErrNotExist) {
		w.Log.Warn("resume report cleanup failed", "scan", scan.ID, "err", err)
	}
}
