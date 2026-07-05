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

func (s *Server) apiAddExpectedFinding(w http.ResponseWriter, r *http.Request) {
	repoID, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	var body struct {
		File string `json:"file"`
		CWE  string `json:"cwe"`
		CVE  string `json:"cve"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeAPIError(w, http.StatusBadRequest, "body must be JSON")
		return
	}
	row, err := buildExpectedFinding(repoID, body.File, body.CWE, body.CVE, body.Note)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.DB.Create(&row).Error; err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, expectedFindingResponseFrom(row))
}

func (s *Server) apiDeleteExpectedFinding(w http.ResponseWriter, r *http.Request) {
	repoID, ok := s.repoScopedID(w, r)
	if !ok {
		return
	}
	expectedID, err := strconv.Atoi(r.PathValue("expected_id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid expected finding id")
		return
	}
	res := s.DB.Where("repository_id = ? AND id = ?", repoID, expectedID).Delete(&db.ExpectedFinding{})
	if res.Error != nil {
		writeAPIError(w, http.StatusInternalServerError, res.Error.Error())
		return
	}
	if res.RowsAffected == 0 {
		writeAPIError(w, http.StatusNotFound, "expected finding not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	row := db.ExpectedFinding{
		RepositoryID: repoID,
		File:         normalizeExpectedFile(file),
		CWE:          strings.ToUpper(strings.TrimSpace(cwe)),
		CVE:          strings.TrimSpace(cve),
		Note:         strings.TrimSpace(note),
	}
	if row.File == "" || row.File == "." {
		return row, fmt.Errorf("file is required")
	}
	if row.CWE == "" {
		return row, fmt.Errorf("cwe is required")
	}
	return row, nil
}

func expectedFindingResponses(rows []db.ExpectedFinding) []expectedFindingResponse {
	out := make([]expectedFindingResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, expectedFindingResponseFrom(row))
	}
	return out
}

func expectedFindingResponseFrom(row db.ExpectedFinding) expectedFindingResponse {
	return expectedFindingResponse{
		ID:           row.ID,
		RepositoryID: row.RepositoryID,
		File:         row.File,
		CWE:          row.CWE,
		CVE:          row.CVE,
		Note:         row.Note,
	}
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
	case int:
		return v
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
	Expected      []expectedFindingStatus
	FindingStatus map[uint]bool
	MatchedTotal  int
	FindingTotal  int
}

type repoExpectedView struct {
	Matches       expectedMatchSet
	FindingStatus map[uint]bool
}

func loadRepoExpectedView(gdb *gorm.DB, repoID uint, latest *db.Scan, rf repoFindings) repoExpectedView {
	var expected []db.ExpectedFinding
	gdb.Where("repository_id = ?", repoID).Order("file, cwe").Find(&expected)
	latestScanID := uint(0)
	if latest != nil {
		latestScanID = latest.ID
	}
	visibleFindings := make([]db.Finding, 0, len(rf.DeepDive)+len(rf.Scanners))
	visibleFindings = append(visibleFindings, rf.DeepDive...)
	visibleFindings = append(visibleFindings, rf.Scanners...)
	return repoExpectedView{
		Matches:       expectedMatchesForRows(gdb, repoID, latestScanID, expected),
		FindingStatus: expectedStatusForFindings(visibleFindings, expected),
	}
}

func expectedMatchesForScan(gdb *gorm.DB, repoID, scanID uint) expectedMatchSet {
	var expected []db.ExpectedFinding
	gdb.Where("repository_id = ?", repoID).Order("file, cwe").Find(&expected)
	return expectedMatchesForRows(gdb, repoID, scanID, expected)
}

func expectedMatchesForRows(gdb *gorm.DB, repoID, scanID uint, expected []db.ExpectedFinding) expectedMatchSet {
	out := expectedMatchSet{
		Expected:      make([]expectedFindingStatus, 0, len(expected)),
		FindingStatus: map[uint]bool{},
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
		if db.SeverityAtLeast(f.Severity, "Medium") {
			out.FindingTotal++
		}
		for i := range out.Expected {
			if findingMatchesExpected(f, out.Expected[i].Expected) {
				out.FindingStatus[f.ID] = true
				if !out.Expected[i].Matched {
					out.Expected[i].Matched = true
					out.Expected[i].FindingID = f.ID
					out.MatchedTotal++
				}
			}
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
	if strings.TrimSpace(f.CWE) != strings.TrimSpace(expected.CWE) {
		return false
	}
	want := normalizeExpectedFile(expected.File)
	for _, loc := range findingLocations(f) {
		if normalizeLocationFile(loc) == want {
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

func normalizeExpectedFile(file string) string {
	return cleanRepoPath(file)
}

func normalizeLocationFile(loc string) string {
	loc = strings.TrimSpace(strings.Split(strings.TrimSpace(loc), "\n")[0])
	for {
		i := strings.LastIndexByte(loc, ':')
		if i < 0 || !allDigits(loc[i+1:]) {
			break
		}
		loc = loc[:i]
	}
	return cleanRepoPath(loc)
}

func cleanRepoPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.TrimPrefix(p, "./")
	if p == "" {
		return ""
	}
	return path.Clean(p)
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
