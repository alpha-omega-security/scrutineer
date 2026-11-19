package worker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"scrutineer/internal/db"
)

// A scan that fails partway (a timeout, a killed container, an error) keeps its
// harness session so a retry can resume the conversation, but finalizeScan
// deletes the workspace and the retry starts from a reset one. Without help the
// resumed agent remembers writing ./report.json and finds it gone, so it redoes
// the work. The partial output file is the one piece of agent work that is
// carried across: finalizeScan copies it out of the workspace into a host-only
// directory, then doSkill writes it back after the reset. Nothing else in the
// workspace is carried, so the reset still removes anything the agent planted.

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

// saveResumeReport copies the skill's output file out of a workspace that is
// about to be deleted when the run leaves a session to resume. An attempt that
// wrote no output keeps the copy an earlier attempt saved. The read accepts
// only a regular file, so a link the agent left under that name saves nothing.
func (w *Worker) saveResumeReport(scan *db.Scan, emit func(Event)) {
	if scan.Kind != JobSkill || scan.SkillID == nil || !keepsResumeState(scan) {
		return
	}
	var skill db.Skill
	if err := w.DB.Select("id, name, output_file").First(&skill, *scan.SkillID).Error; err != nil {
		w.Log.Warn("resume report: load skill", "scan", scan.ID, "err", err)
		return
	}
	if validateSkillPaths(skill.Name, skill.OutputFile) != nil {
		return
	}
	name := skillOutputFile(&skill)
	report := readCappedReport(filepath.Join(w.scanWorkRoot(scan), name), emit)
	if report == "" {
		return
	}
	if err := writeResumeReport(w.resumeReportDir(scan), name, report); err != nil {
		w.Log.Warn("resume report: save", "scan", scan.ID, "err", err)
		return
	}
	emit(Event{Kind: KindText, Text: fmt.Sprintf("kept the partial ./%s (%d bytes) for a retry to resume from", name, len(report))})
}

// writeResumeReport replaces dir/name through a temporary file so a crash
// mid-write never leaves a truncated copy for the next retry. dir is under
// DataDir and never mounted into a container.
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

// restoreResumeReport writes the saved partial output file into a freshly
// reset workspace when the scan resumes a session. It returns what it wrote
// so the run can tell a report the agent left untouched from a new one.
func (w *Worker) restoreResumeReport(workRoot string, scan *db.Scan, skill *db.Skill, emit func(Event)) string {
	if scan.SessionID == "" {
		return ""
	}
	name := skillOutputFile(skill)
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

// dropStaleRestoredReport discards a restored report the run never changed
// when the run did not continue the resumed session. The harness restarts
// fresh when the session store has lost the conversation. That agent
// never knew about the earlier attempt, so the bytes it left in place are not
// its output.
func dropStaleRestoredReport(scan *db.Scan, sj SkillJob, report string, emit func(Event)) string {
	if sj.restoredReport == "" || report != sj.restoredReport || scan.SessionID == sj.ResumeSessionID {
		return report
	}
	emit(Event{Kind: KindText, Text: "the session was not resumed and the restored partial report was left unchanged; ignoring it"})
	return ""
}

// removeResumeReport drops the saved copy once the lineage no longer needs it.
func (w *Worker) removeResumeReport(scan *db.Scan) {
	if err := os.RemoveAll(w.resumeReportDir(scan)); err != nil && !errors.Is(err, os.ErrNotExist) {
		w.Log.Warn("resume report cleanup failed", "scan", scan.ID, "err", err)
	}
}
