package web

import (
	"testing"

	"scrutineer/internal/db"
)

// TestFindingClassification_advisoryDeepDiveIsCurated verifies that
// advisory-deep-dive findings land in the curated Findings bucket alongside
// security-deep-dive rather than the Scanners bucket, while a tool scanner
// (semgrep) stays a scanner. Regression guard for the PR #556 review: the
// split keyed on a single skill name, so advisory-deep-dive output was
// miscategorised as scanner noise. Exercises both classification paths: the
// findingsScanIDs GORM subquery (via loadRepoFindings) and the raw
// scannerScanFilter SQL (via findingToggleCounts).
func TestFindingClassification_advisoryDeepDiveIsCurated(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)

	ddScan := newScan(t, s, repo.ID, "security-deep-dive")
	advScan := newScan(t, s, repo.ID, "advisory-deep-dive")
	semScan := newScan(t, s, repo.ID, "semgrep")
	newFindingUnder(t, s, repo.ID, ddScan.ID, db.FindingNew)
	newFindingUnder(t, s, repo.ID, advScan.ID, db.FindingNew)
	newFindingUnder(t, s, repo.ID, semScan.ID, db.FindingNew)

	rf := loadRepoFindings(s.DB, repo.ID, "")
	if rf.DeepDiveTotal != 2 {
		t.Errorf("DeepDiveTotal = %d, want 2 (security-deep-dive + advisory-deep-dive)", rf.DeepDiveTotal)
	}
	if rf.ScannersTotal != 1 {
		t.Errorf("ScannersTotal = %d, want 1 (semgrep only)", rf.ScannersTotal)
	}

	inBucket := func(fs []db.Finding, scanID uint) bool {
		for _, f := range fs {
			if f.ScanID == scanID {
				return true
			}
		}
		return false
	}
	if !inBucket(rf.DeepDive, advScan.ID) {
		t.Error("advisory-deep-dive finding missing from the Findings bucket")
	}
	if inBucket(rf.Scanners, advScan.ID) {
		t.Error("advisory-deep-dive finding wrongly in the Scanners bucket")
	}
	if !inBucket(rf.Scanners, semScan.ID) {
		t.Error("semgrep finding missing from the Scanners bucket")
	}

	// The raw scannerScanFilter path must agree: only the semgrep finding counts
	// as a scanner.
	if _, scannerTotal := s.findingToggleCounts(localReq("GET", "/findings"), false); scannerTotal != 1 {
		t.Errorf("findingToggleCounts scannerTotal = %d, want 1 (semgrep only)", scannerTotal)
	}
}
