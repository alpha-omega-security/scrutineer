package web

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// seedRepoWithReport creates a repo with a completed security-deep-dive scan,
// two findings with six-step prose + labels + notes + comms + refs, a
// package, a dependent, an advisory, a dependency, and a maintainer.
// Used by the report tests to exercise every section end to end.
func seedRepoWithReport(t *testing.T, s *Server) db.Repository {
	t.Helper()
	repo := db.Repository{
		URL: "https://github.com/acme/thing", Name: "thing",
		FullName: "acme/thing", Description: "The thing, for testing",
		Languages: "Go", License: "MIT", Stars: 42,
	}
	s.DB.Create(&repo)

	now := time.Now()
	report := `{
		"repository":"https://github.com/acme/thing","commit":"abcdef1234","spec_version":10,
		"model":"t","date":"2026-04-20","languages":["Go"],
		"boundaries":[{"actor":"caller","trusted":"yes","controls":"arg","source":"README"}],
		"inventory":[{"id":"S1","class":"Command execution","location":"main.go:12","consumes":"arg","primitive":"os.Exec"}],
		"ruled_out":[{"sinks":["S2"],"step":2,"reason":"internal path, no caller provides"}],
		"prior_art":"Searched issues. Nothing.",
		"reach":"No dependents yet.",
		"findings":[]
	}`
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "abcdef1234567", Report: report,
		FinishedAt: &now, CreatedAt: now,
	}
	s.DB.Create(&scan)

	finding := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: scan.Commit,
		FindingID: "F1", Title: "OS command injection via arg",
		Severity: "High", Status: db.FindingEnriched, CWE: "CWE-78",
		Location: "main.go:12", Affected: ">=1.0,<1.4",
		Trace: "arg comes in, hits os.Exec", Boundary: "crosses caller boundary",
		Validation: "`echo $(cat repro.sh)` triggers", Rating: "High because X",
		CVEID: "CVE-2026-00042", CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CVSSScore: 9.8, FixVersion: "1.4.0", FixCommit: "abcd1234",
		Resolution: db.ResolutionFix,
	}
	s.DB.Create(&finding)

	label := db.FindingLabel{Name: "regression", Color: "#dc2626"}
	s.DB.Create(&label)
	_ = s.DB.Model(&finding).Association("Labels").Append(&label)

	if _, err := db.AddFindingNote(s.DB, finding.ID, "Triage note: confirmed by verify skill", "analyst"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFindingCommunication(s.DB, finding.ID, "email", "outbound",
		"security@acme.example", "Initial report email body", "pr", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddFindingReference(s.DB, finding.ID,
		"https://github.com/acme/thing/issues/42", "issue", "upstream tracking"); err != nil {
		t.Fatal(err)
	}

	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "acme-thing",
		Ecosystem: "npm", LatestVersion: "1.3.2", Downloads: 10000, DependentRepos: 12})
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "downstream",
		Ecosystem: "npm", Downloads: 50, DependentRepos: 2})
	s.DB.Create(&db.Advisory{RepositoryID: repo.ID, UUID: "u1",
		URL: "https://ghsa.io/x", Title: "Old CVE", Severity: "HIGH",
		CVSSScore: 7.5, Packages: "acme-thing"})
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "leftpad",
		Ecosystem: "npm", ManifestPath: "package.json"})

	m := db.Maintainer{Login: "alice", Name: "Alice", Email: "alice@example.com",
		Status: db.MaintainerActive, Notes: "lead"}
	s.DB.Create(&m)
	_ = s.DB.Model(&repo).Association("Maintainers").Append(&m)

	return repo
}

func TestRepoReport_includesEverySection(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedRepoWithReport(t, s)

	path := "/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/report.md"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("content-type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".md") {
		t.Errorf("content-disposition = %q", cd)
	}

	body := w.Body.String()
	wants := []string{
		"# acme/thing",
		"https://github.com/acme/thing",
		"## Repository metadata",
		"| Languages | Go |",
		"| License | MIT |",
		"## Threat model",
		"### Trust boundaries",
		"| caller | yes | arg | README |",
		"### Sink inventory",
		"Command execution",
		"### Ruled out",
		"internal path, no caller provides",
		"## Findings",
		"### Finding #1: OS command injection via arg",
		"| CVE | CVE-2026-00042 |",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
		"#### Trace",
		"arg comes in, hits os.Exec",
		"#### Notes",
		"Triage note: confirmed by verify skill",
		"#### Communications",
		"**email outbound**",
		"(offered pr)",
		"#### References",
		"https://github.com/acme/thing/issues/42",
		"#### Labels",
		"regression",
		"## Packages",
		"| acme-thing | npm | 1.3.2 | 10000 | 12 |",
		"## Published advisories",
		"| HIGH | 7.5 | Old CVE |",
		"## Top dependents",
		"| downstream | npm | 50 | 2 |",
		"## Dependencies",
		"**npm**: 1",
		"## Maintainers",
		"| alice | Alice | alice@example.com | active | lead |",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestRepoReport_emptyRepoStillRenders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET",
		"/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/report.md"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"## Repository metadata",
		"## Threat model",
		"No completed security-deep-dive scan yet.",
		"## Findings",
		"No findings recorded for this repository.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("empty-repo report missing %q", want)
		}
	}
	// Sections that only render when data is present should be absent.
	for _, not := range []string{"## Packages", "## Maintainers", "## Top dependents"} {
		if strings.Contains(body, not) {
			t.Errorf("empty-repo report unexpectedly contained %q", not)
		}
	}
}

func TestRepoReport_notFoundFor404Repo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/repositories/999/report.md"))
	if w.Code != 404 {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
