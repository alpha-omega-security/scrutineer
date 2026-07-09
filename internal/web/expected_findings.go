package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/findingnorm"
)

type expectedFindingResponse struct {
	ID           uint   `json:"id"`
	RepositoryID uint   `json:"repository_id"`
	File         string `json:"file"`
	CWE          string `json:"cwe"`
	CVE          string `json:"cve,omitempty"`
	Note         string `json:"note,omitempty"`
}

func (s *Server) apiListExpectedFindings(w http.ResponseWriter, r *http.Request) {
	repoID, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	var rows []db.ExpectedFinding
	if err := s.DB.Where("repository_id = ?", repoID).Order("file, cwe").Find(&rows).Error; err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, expectedFindingResponses(rows))
}

func (s *Server) repoExpectedFindingCreate(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	row, err := buildExpectedFinding(repo.ID, r.FormValue("file"), r.FormValue("cwe"), r.FormValue("cve"), r.FormValue("note"))
	if err != nil {
		setFlash(w, Flash{Category: errorKey, Title: err.Error()})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt13", repo.ID))
		return
	}
	if err := s.DB.Create(&row).Error; err != nil {
		setFlash(w, Flash{Category: errorKey, Title: "Expected finding not saved", Description: err.Error()})
		s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt13", repo.ID))
		return
	}
	setFlash(w, Flash{Category: successKey, Title: "Expected finding saved"})
	s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt13", repo.ID))
}

func (s *Server) repoExpectedFindingDelete(w http.ResponseWriter, r *http.Request) {
	repo, ok := loadByID[db.Repository](s, w, r)
	if !ok {
		return
	}
	expectedID, err := strconv.Atoi(r.PathValue("expected_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	res := s.DB.Where("repository_id = ? AND id = ?", repo.ID, expectedID).Delete(&db.ExpectedFinding{})
	if res.Error != nil {
		setFlash(w, Flash{Category: errorKey, Title: "Expected finding not deleted", Description: res.Error.Error()})
	} else if res.RowsAffected > 0 {
		setFlash(w, Flash{Category: successKey, Title: "Expected finding deleted"})
	}
	s.redirect(w, r, fmt.Sprintf("/repositories/%d#rt13", repo.ID))
}

func buildExpectedFinding(repoID uint, file, cwe, cve, note string) (db.ExpectedFinding, error) {
	cleanFile, err := cleanExpectedFileInput(file)
	if err != nil {
		return db.ExpectedFinding{}, err
	}
	row := db.ExpectedFinding{
		RepositoryID: repoID,
		File:         cleanFile,
		CWE:          findingnorm.CWE(cwe),
		CVE:          strings.TrimSpace(cve),
		Note:         strings.TrimSpace(note),
	}
	if row.CWE == "" {
		return row, fmt.Errorf("cwe is required")
	}
	return row, nil
}

func expectedFindingResponses(rows []db.ExpectedFinding) []expectedFindingResponse {
	out := make([]expectedFindingResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, expectedFindingResponse{
			ID:           row.ID,
			RepositoryID: row.RepositoryID,
			File:         row.File,
			CWE:          row.CWE,
			CVE:          row.CVE,
			Note:         row.Note,
		})
	}
	return out
}

func skillSchemaVersion(skill db.Skill) int {
	if skill.Metadata == "" {
		return 0
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(skill.Metadata), &meta); err != nil {
		return 0
	}
	switch v := meta["scrutineer.version"].(type) {
	case float64:
		return int(v)
	default:
		return 0
	}
}

type expectedFindingStatus struct {
	Expected  db.ExpectedFinding
	Matched   bool
	FindingID uint
}

type expectedMatchSet struct {
	Expected             []expectedFindingStatus
	MatchedTotal         int
	FindingTotal         int
	TruePositiveFindings int
}

type repoExpectedView struct {
	Matches       expectedMatchSet
	FindingStatus map[uint]bool
}

func loadRepoExpectedView(gdb *gorm.DB, repoID uint, latest *db.Scan, rf repoFindings) repoExpectedView {
	var expected []db.ExpectedFinding
	gdb.Where("repository_id = ?", repoID).Order("file, cwe").Find(&expected)
	latestScanID := uint(0)
	if scan := latestBenchmarkScan(gdb, repoID, "", "", ""); scan != nil {
		latestScanID = scan.ID
	}
	visibleCap := len(rf.DeepDive) + len(rf.Scanners)
	if latest != nil {
		visibleCap += len(latest.Findings)
	}
	visibleFindings := make([]db.Finding, 0, visibleCap)
	visibleFindings = append(visibleFindings, rf.DeepDive...)
	visibleFindings = append(visibleFindings, rf.Scanners...)
	if latest != nil {
		visibleFindings = append(visibleFindings, latest.Findings...)
	}
	return repoExpectedView{
		Matches:       expectedMatchesForRows(gdb, repoID, latestScanID, expected),
		FindingStatus: expectedStatusForFindings(visibleFindings, expected),
	}
}

func expectedMatchesForRows(gdb *gorm.DB, repoID, scanID uint, expected []db.ExpectedFinding) expectedMatchSet {
	out := expectedMatchSet{
		Expected: make([]expectedFindingStatus, 0, len(expected)),
	}
	for _, row := range expected {
		out.Expected = append(out.Expected, expectedFindingStatus{Expected: row})
	}
	if scanID == 0 || len(expected) == 0 {
		return out
	}
	var findings []db.Finding
	gdb.Where("repository_id = ? AND scan_id = ?", repoID, scanID).Find(&findings)
	for _, f := range findings {
		if !db.SeverityAtLeast(f.Severity, "Medium") {
			continue
		}
		out.FindingTotal++
		findingMatched := false
		for i := range out.Expected {
			if findingMatchesExpected(f, out.Expected[i].Expected) {
				findingMatched = true
				if !out.Expected[i].Matched {
					out.Expected[i].Matched = true
					out.Expected[i].FindingID = f.ID
					out.MatchedTotal++
				}
			}
		}
		if findingMatched {
			out.TruePositiveFindings++
		}
	}
	return out
}

func expectedStatusForFindings(findings []db.Finding, expected []db.ExpectedFinding) map[uint]bool {
	out := make(map[uint]bool, len(findings))
	for _, f := range findings {
		for _, row := range expected {
			if findingMatchesExpected(f, row) {
				out[f.ID] = true
				break
			}
		}
	}
	return out
}

func findingMatchesExpected(f db.Finding, expected db.ExpectedFinding) bool {
	if findingnorm.CWE(f.CWE) != findingnorm.CWE(expected.CWE) {
		return false
	}
	want := findingnorm.RepoPath(expected.File)
	for _, loc := range findingLocations(f) {
		if findingnorm.LocationFile(loc) == want {
			return true
		}
	}
	return false
}

func findingLocations(f db.Finding) []string {
	locs := f.LocationList()
	if len(locs) > 0 {
		return locs
	}
	if strings.TrimSpace(f.Location) == "" {
		return nil
	}
	return []string{f.Location}
}

func cleanExpectedFileInput(file string) (string, error) {
	raw := strings.TrimSpace(strings.ReplaceAll(file, "\\", "/"))
	if raw == "" {
		return "", fmt.Errorf("file is required")
	}
	if path.IsAbs(raw) || findingnorm.HasParentPathSegment(raw) {
		return "", fmt.Errorf("file must be relative to the repository root")
	}
	clean := findingnorm.RepoPath(raw)
	if clean == "" || clean == "." || path.IsAbs(clean) || findingnorm.HasParentPathSegment(clean) {
		return "", fmt.Errorf("file must be relative to the repository root")
	}
	return clean, nil
}
