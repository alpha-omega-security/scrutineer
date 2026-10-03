package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

const promotedReport = `{"known_non_findings":[{"reported_as":"model","why_safe":"m"},{"reported_as":"p","why_safe":"w","promoted_from":{"review_id":7}}]}`

// Skills read raw threat-model reports through the scan API, so a promotion a
// model copied into its report must not reach them. Other reports are served
// unchanged.
func TestAPIGetScan_stripsPromotionsFromThreatModelReports(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)
	for _, tc := range []struct {
		skill     string
		promotion bool
	}{
		{"threat-model", false},
		{deepDiveSkillName, true},
	} {
		prior := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: tc.skill, Report: promotedReport}
		if err := s.DB.Create(&prior).Error; err != nil {
			t.Fatal(err)
		}
		w := apiReq(t, s, "GET", fmt.Sprintf("/api/scans/%d", prior.ID), auth.APIToken, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", tc.skill, w.Code, w.Body)
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		report, _ := got["report"].(string)
		if strings.Contains(report, "promoted_from") != tc.promotion || !strings.Contains(report, `"model"`) {
			t.Errorf("%s: report = %s", tc.skill, report)
		}
	}
}

// confirmationFixture rejects a source finding, then records a confirmation by
// a different finding that relies on the source's review.
func confirmationFixture(t *testing.T, s *Server) (db.Repository, db.Finding) {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/confirm", Name: "confirm"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "src"}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	source := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "source", Severity: sevHigh, Location: "parse.go:10", Commit: "src"}
	confirming := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "again", Severity: sevHigh, Location: "parse.go:20"}
	for _, f := range []*db.Finding{&source, &confirming} {
		if err := s.DB.Create(f).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RejectFinding(s.DB, source.ID, "false_positive", "bounded at parse.go:5", "analyst"); err != nil {
		t.Fatal(err)
	}
	reviews, err := db.ListFindingReviews(s.DB, source.ID)
	if err != nil || len(reviews) != 1 {
		t.Fatalf("reviews = %v, %v", reviews, err)
	}
	c := db.FeedbackConfirmation{ReviewID: reviews[0].ID, ScanID: scan.ID, FindingID: confirming.ID, Commit: "c1"}
	if _, err := db.RecordFeedbackConfirmation(s.DB, &c); err != nil {
		t.Fatal(err)
	}
	return repo, source
}

func confirmationCount(t *testing.T, s *Server) int64 {
	t.Helper()
	var n int64
	if err := s.DB.Model(&db.FeedbackConfirmation{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// Deleting the reviewed finding deletes the confirmations that relied on its
// review, even though they belong to a different, surviving finding.
func TestDeleteFindingDeletesConfirmationsOfItsReviews(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, source := confirmationFixture(t, s)
	if _, err := s.deleteFinding(source); err != nil {
		t.Fatal(err)
	}
	if n := confirmationCount(t, s); n != 0 {
		t.Fatalf("confirmations = %d, want 0 after deleting the reviewed finding", n)
	}
}

func TestDeleteFindingChildrenDeletesConfirmationsOfRepoReviews(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, _ := confirmationFixture(t, s)
	if err := s.DB.Transaction(func(tx *gorm.DB) error { return deleteFindingChildren(tx, repo.ID) }); err != nil {
		t.Fatal(err)
	}
	if n := confirmationCount(t, s); n != 0 {
		t.Fatalf("confirmations = %d, want 0 after deleting the repository's findings", n)
	}
}
