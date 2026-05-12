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

// findingPatchDownload serves Finding.SuggestedFix as a .patch file. The
// column is only ever populated by parsePatchOutput after the applicability
// gate passes, so a download is always a diff that parsed, targeted real
// files, overlapped Location, and survived git apply --check.
func (s *Server) findingPatchDownload(w http.ResponseWriter, r *http.Request) {
	f, ok := loadByID[db.Finding](s, w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(f.SuggestedFix) == "" {
		http.Error(w, "no gated patch stored for this finding", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/x-diff; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="finding-%d.patch"`, f.ID))
	_, _ = w.Write([]byte(f.SuggestedFix))
}
