package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func TestAutoUpdateThreatModelFullScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		Report:       `{"spec_version":1}`,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	s.autoUpdateThreatModel(&scan)

	var got db.Repository
	if err := s.DB.First(&got, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.ThreatModel, `"spec_version": 1`) {
		t.Fatalf("ThreatModel = %q, want full threat-model report", got.ThreatModel)
	}
}

func TestAutoUpdateThreatModelSmallDiffSkips(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo", ThreatModel: `{"old":true}`}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		RescanMode:   db.ScanRescanModeDiff,
		DiffStats:    `{"changed_files":1,"files":[{"path":"README.md"}]}`,
		Coverage:     `{"requested_mode":"diff","actual_mode":"diff"}`,
		Report:       `{"spec_version":2}`,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	s.autoUpdateThreatModel(&scan)

	var gotRepo db.Repository
	if err := s.DB.First(&gotRepo, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if gotRepo.ThreatModel != repo.ThreatModel {
		t.Fatalf("ThreatModel = %q, want unchanged %q", gotRepo.ThreatModel, repo.ThreatModel)
	}
	var gotScan db.Scan
	if err := s.DB.First(&gotScan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(gotScan.Coverage)
	if !ok || rec.ThreatModel == nil {
		t.Fatalf("coverage = %q, want a threat-model state", gotScan.Coverage)
	}
	if rec.ThreatModel.Update != "skipped_small_diff" || rec.ThreatModel.Material {
		t.Fatalf("threat model = %+v, want skipped non-material diff", *rec.ThreatModel)
	}
}

func TestAutoUpdateThreatModelMaterialDiffUpdates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo", ThreatModel: `{"old":true}`}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		RescanMode:   db.ScanRescanModeDiff,
		DiffStats:    `{"changed_files":1,"files":[{"path":"internal/auth/session.go"}]}`,
		Coverage:     `{"requested_mode":"diff","actual_mode":"diff"}`,
		Report:       `{"spec_version":2}`,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	s.autoUpdateThreatModel(&scan)

	var gotRepo db.Repository
	if err := s.DB.First(&gotRepo, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotRepo.ThreatModel, `"spec_version": 2`) {
		t.Fatalf("ThreatModel = %q, want material diff report", gotRepo.ThreatModel)
	}
	var gotScan db.Scan
	if err := s.DB.First(&gotScan, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(gotScan.Coverage)
	if !ok || rec.ThreatModel == nil {
		t.Fatalf("coverage = %q, want a threat-model state", gotScan.Coverage)
	}
	if rec.ThreatModel.Update != "updated" || !rec.ThreatModel.Material {
		t.Fatalf("threat model = %+v, want updated material diff", *rec.ThreatModel)
	}
}

// A full threat-model scan carries no prior coverage, so Parse returns
// ok=false and a zero Record. Marshal defaults Completeness on its own copy,
// which used to leave the indexed column empty while the stored blob said
// "unknown" — the exact drift the typed contract exists to prevent.
func TestMarkThreatModelUpdateKeepsCompletenessColumnInStep(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/repo", Name: "repo"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		Report:       `{"spec_version":1}`,
	}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}

	s.autoUpdateThreatModel(&scan)

	var got db.Scan
	if err := s.DB.First(&got, scan.ID).Error; err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(got.Coverage)
	if !ok {
		t.Fatalf("Parse(%q) not ok", got.Coverage)
	}
	if rec.Completeness != coverage.CompletenessUnknown {
		t.Fatalf("record Completeness = %q, want %q", rec.Completeness, coverage.CompletenessUnknown)
	}
	if got.Completeness != rec.Completeness {
		t.Fatalf("column Completeness = %q, record says %q — the two disagree", got.Completeness, rec.Completeness)
	}
}

func TestThreatModelRefreshKeepsPromotedFeedbackAndReflection(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/promoted-refresh", Name: "promoted-refresh"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	reviewID := eligibleRejectionReview(t, s, repo.ID)
	// "host" is backed by a still-rejected decision. "retired" names a decision
	// that is no longer eligible, so the refresh must not carry it over.
	previous := fmt.Sprintf(`{"reflection_notes":[{"summary":"retained"}],"known_non_findings":[`+
		`{"reported_as":"old model","why_safe":"w"},`+
		`{"reported_as":"host","why_safe":"guarded","promoted_from":{"review_id":%d,"finding_id":3,"source_commit":"abc","confirmations":[{"scan_id":1,"commit":"d"}]}},`+
		`{"reported_as":"retired","why_safe":"w","promoted_from":{"review_id":%d}}]}`, reviewID, reviewID+1000)
	if err := s.DB.Model(&repo).Update("threat_model", previous).Error; err != nil {
		t.Fatal(err)
	}
	report := `{"description":"new","reflection_notes":[{"summary":"invented"}],"known_non_findings":[` +
		`{"reported_as":"new model","why_safe":"w"},` +
		`{"reported_as":"forged","why_safe":"w","promoted_from":{"review_id":99}}]}`
	scan := db.Scan{RepositoryID: repo.ID, SkillName: threatModelSkillName, Status: db.ScanDone, Report: report}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	s.autoUpdateThreatModel(&scan)
	if err := s.DB.First(&repo, repo.ID).Error; err != nil {
		t.Fatal(err)
	}
	var got struct {
		Notes []map[string]string `json:"reflection_notes"`
		Items []map[string]any    `json:"known_non_findings"`
	}
	if err := json.Unmarshal([]byte(repo.ThreatModel), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Notes) != 1 || got.Notes[0]["summary"] != "retained" {
		t.Fatalf("reflection notes = %v", got.Notes)
	}
	if len(got.Items) != 2 || got.Items[0]["reported_as"] != "new model" || got.Items[1]["reported_as"] != "host" {
		t.Fatalf("items = %v", got.Items)
	}
	if strings.Contains(repo.ThreatModel, "forged") || strings.Contains(repo.ThreatModel, "old model") || strings.Contains(repo.ThreatModel, "retired") {
		t.Fatalf("model = %s", repo.ThreatModel)
	}
}

// eligibleRejectionReview records a still-rejected false-positive decision with
// a source snapshot, which is what makes a promotion eligible.
func eligibleRejectionReview(t *testing.T, s *Server, repoID uint) uint {
	t.Helper()
	scan := db.Scan{RepositoryID: repoID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "abc"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	f := db.Finding{ScanID: scan.ID, RepositoryID: repoID, Title: "overflow", Severity: sevHigh, Location: "parse.go:10", Commit: "abc"}
	if err := s.DB.Create(&f).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.RejectFinding(s.DB, f.ID, "false_positive", "bounded at parse.go:5", "analyst"); err != nil {
		t.Fatal(err)
	}
	reviews, err := db.ListFindingReviews(s.DB, f.ID)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("reviews = %v, %v", reviews, err)
	}
	return reviews[0].ID
}
