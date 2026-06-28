package web

import (
	"testing"

	"scrutineer/internal/db"
)

// findingIDs collects the IDs of a finding slice for membership assertions.
func findingIDs(fs []db.Finding) map[uint]bool {
	ids := make(map[uint]bool, len(fs))
	for _, f := range fs {
		ids[f.ID] = true
	}
	return ids
}

// TestVulnScanBucketedAsFinding pins issue #458: findings produced by the
// LLM-driven vuln-scan skill belong in the curated Findings bucket alongside
// security-deep-dive, not in the Scanners tab with semgrep/zizmor noise. It
// covers both bucket paths — the repo Findings tab (findingsScanIDs, via
// loadRepoFindings) and the cross-repo findings index totals (scannerScanFilter,
// via findingToggleCounts) — so the two definitions of "scanner" stay in sync.
func TestVulnScanBucketedAsFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)

	vulnScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: vulnScanSkillName, Commit: "deadbee"}
	s.DB.Create(&vulnScan)
	vulnFinding := db.Finding{RepositoryID: repo.ID, ScanID: vulnScan.ID,
		Title: "vuln-scan candidate", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&vulnFinding)

	semgrepScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: "semgrep", Commit: "deadbee"}
	s.DB.Create(&semgrepScan)
	semgrepFinding := db.Finding{RepositoryID: repo.ID, ScanID: semgrepScan.ID,
		Title: "semgrep lint", Severity: "Low", Status: db.FindingNew}
	s.DB.Create(&semgrepFinding)

	// Repo Findings tab: vuln-scan lands in Findings, semgrep stays in Scanners.
	rf := loadRepoFindings(s.DB, repo.ID, "")
	dd, sc := findingIDs(rf.DeepDive), findingIDs(rf.Scanners)
	if !dd[vulnFinding.ID] {
		t.Errorf("vuln-scan finding should be in the Findings bucket; DeepDive=%v", rf.DeepDive)
	}
	if sc[vulnFinding.ID] {
		t.Errorf("vuln-scan finding should not be in the Scanners bucket")
	}
	if !sc[semgrepFinding.ID] {
		t.Errorf("semgrep finding should remain in the Scanners bucket")
	}
	if dd[semgrepFinding.ID] {
		t.Errorf("semgrep finding should not be in the Findings bucket")
	}

	// Cross-repo findings index: the scanner total counts only the semgrep
	// finding, confirming the vuln-scan finding is excluded from scannerScanFilter
	// and its positional SQL args still line up after dropping the bound skill.
	_, scannerTotal := s.findingToggleCounts(localReq("GET", "/findings"), false)
	if scannerTotal != 1 {
		t.Errorf("findings index scanner total = %d, want 1 (semgrep only)", scannerTotal)
	}
}
