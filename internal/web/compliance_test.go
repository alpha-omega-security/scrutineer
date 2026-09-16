package web

import (
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// TestRepoShow_complianceTab pins that the Compliance tab renders the attained
// level and one row per control, drops the level badge when nothing was
// attained, and stays hidden for a repository without compliance rows.
func TestRepoShow_complianceTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/compliance", Name: "compliance", BaselineLevel: 1}
	s.DB.Create(&repo)
	s.DB.Create(&db.ComplianceControl{RepositoryID: repo.ID, ControlID: "OSPS-AC-01.01", Level: 1, Status: "PASS", Details: "MFA enforced", Source: "darnit"})
	s.DB.Create(&db.ComplianceControl{RepositoryID: repo.ID, ControlID: "OSPS-GV-01.01", Level: 2, Status: "WARN", Details: "GOVERNANCE.md names no roles", Source: "agent"})

	body := getRepoPage(t, s, repo.ID)
	for _, want := range []string{"L1", "OpenSSF Baseline level 1 attained.", "OSPS-AC-01.01", "OSPS-GV-01.01", "GOVERNANCE.md names no roles", "WARN"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}

	s.DB.Model(&repo).Update("baseline_level", 0)
	body = getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "No OpenSSF Baseline level attained.") || strings.Contains(body, "L0") {
		t.Error("level 0 should render the no-level sentence and no badge")
	}

	bare := db.Repository{URL: "https://github.com/o/bare", Name: "bare"}
	s.DB.Create(&bare)
	if body := getRepoPage(t, s, bare.ID); strings.Contains(body, "A level counts as attained only when") {
		t.Error("Compliance tab rendered for a repository with no compliance rows")
	}
}
