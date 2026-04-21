package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// patchReport is the subset of the patch skill's report.json shape the UI
// needs. Mirrors skills/patch/schema.json.
type patchReport struct {
	Patch        string   `json:"patch"`
	Rationale    string   `json:"rationale"`
	FilesChanged []string `json:"files_changed"`
	BaseCommit   string   `json:"base_commit"`
	TestsAdded   bool     `json:"tests_added"`
	Notes        string   `json:"notes"`
	Error        string   `json:"error"`
}

// latestPatchScan returns the most recent done patch-skill scan for a finding
// along with its parsed report. Returns (nil, nil, nil) when no patch scan
// has completed for this finding — the UI uses that to hide the section.
func (s *Server) latestPatchScan(findingID uint) (*db.Scan, *patchReport, error) {
	var scan db.Scan
	err := s.DB.
		Where("finding_id = ? AND kind = ? AND skill_name = ? AND status = ?",
			findingID, worker.JobSkill, patchSkillName, db.ScanDone).
		Order("finished_at desc").
		First(&scan).Error
	if err != nil {
		return nil, nil, nil
	}
	if scan.Report == "" {
		return &scan, nil, nil
	}
	var rep patchReport
	if err := json.Unmarshal([]byte(scan.Report), &rep); err != nil {
		return &scan, nil, fmt.Errorf("parse patch report: %w", err)
	}
	return &scan, &rep, nil
}

// findingPatchDownload serves the latest patch scan's diff as a .patch file.
// No .patch scan done -> 404; done but empty diff (the skill refused) -> 404
// with a small message so the download link never yields a confusing empty
// file.
func (s *Server) findingPatchDownload(w http.ResponseWriter, r *http.Request) {
	var f db.Finding
	if err := s.DB.First(&f, r.PathValue("id")).Error; err != nil {
		http.NotFound(w, r)
		return
	}
	_, rep, err := s.latestPatchScan(f.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rep == nil || strings.TrimSpace(rep.Patch) == "" {
		http.Error(w, "no patch available for this finding", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/x-diff; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="finding-%d.patch"`, f.ID))
	_, _ = w.Write([]byte(rep.Patch))
}
