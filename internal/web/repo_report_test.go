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
// a finding carrying six-step prose, snippet, disclosure draft, suggested fix,
// labels, notes, comms, and refs, plus a package, a dependent, an advisory, a
// dependency, and a maintainer. Used by the report tests to exercise every
// section end to end (and, for the upstream audience, which ones drop).
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
		Location: "main.go:12", Sinks: "S1", Affected: ">=1.0,<1.4",
		Trace: "arg comes in, hits os.Exec", Boundary: "crosses caller boundary",
		Validation: "`echo $(cat repro.sh)` triggers", Rating: "High because X",
		PriorArt: "No prior CVE for this sink", Reach: "Reachable from the public CLI",
		Snippet:         "func run(arg string) {\n\texec.Command(arg)\n}",
		DisclosureDraft: "GHSA draft: command injection in acme/thing via arg",
		SuggestedFix:    "--- a/main.go\n+++ b/main.go\n@@\n-exec.Command(arg)\n+exec.Command(\"/bin/echo\", arg)",
		CVEID:           "CVE-2026-00042", CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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
		"## Summary",
		"1 findings: 0 critical, 1 high, 0 medium, 0 low",
		"## Repository metadata",
		"| Languages | Go |",
		"| License | MIT |",
		"## Threat model",
		"### Trust boundaries",
		"| caller | yes | arg | README |",
		"### Sink inventory",
		"Disposition",
		"Command execution",
		"→ Finding #",
		"### Ruled out",
		"internal path, no caller provides",
		"## Findings",
		"### Finding #1: OS command injection via arg",
		"| CVE | CVE-2026-00042 |",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
		"#### Trace",
		"arg comes in, hits os.Exec",
		"#### Prior art",
		"#### Reach",
		"#### Source",
		"#### Disclosure draft",
		"#### Suggested fix",
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
		"| Alice | alice | alice@example.com | active | lead |",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
}

func TestRepoReport_upstreamAudienceTrimsToMaintainerView(t *testing.T) {
	// ?audience=upstream drops the analyst's internal workspace (notes,
	// communications, labels, disclosure draft) and the repo-wide inventory
	// the maintainer already owns (packages, dependents, dependencies,
	// maintainers), keeping the security-actionable content (#427).
	s, done := newTestServer(t)
	defer done()
	repo := seedRepoWithReport(t, s)

	path := "/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/report.md?audience=upstream"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	// The filename hint distinguishes the upstream export from the full one.
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "-upstream.md") {
		t.Errorf("content-disposition = %q, want -upstream.md suffix", cd)
	}

	body := w.Body.String()

	// Kept: the maintainer-actionable view. Each heading below only renders
	// from the per-finding section or a kept repo-wide section, so its
	// presence really proves that content survived the trim.
	for _, want := range []string{
		"## Summary",
		"## Threat model",
		"### Sink inventory",
		"→ Finding #", // disposition column, sink joined to its finding
		"#### Trace",
		"#### Prior art",
		"#### Reach",
		"#### Source", // snippet, kept (#426)
		"#### Suggested fix",
		"#### References",         // external corroboration, kept on purpose
		"## Published advisories", // already-public CVEs, kept on purpose
	} {
		if !strings.Contains(body, want) {
			t.Errorf("upstream report missing kept section %q", want)
		}
	}

	// Dropped: internal chatter and repo-wide inventory the maintainer owns.
	for _, drop := range []string{
		"#### Notes",
		"#### Communications",
		"#### Labels",
		"#### Disclosure draft",
		"## Packages",
		"## Top dependents",
		"## Dependencies",
		"## Maintainers",
	} {
		if strings.Contains(body, drop) {
			t.Errorf("upstream report should drop %q", drop)
		}
	}
}

func TestRepoReport_unknownAudienceFallsBackToFull(t *testing.T) {
	// An unrecognised ?audience value is not the upstream view: it renders
	// the full analyst report, with no -upstream filename suffix.
	s, done := newTestServer(t)
	defer done()
	repo := seedRepoWithReport(t, s)

	path := "/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/report.md?audience=bogus"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if cd := w.Header().Get("Content-Disposition"); strings.Contains(cd, "-upstream") {
		t.Errorf("content-disposition = %q, unexpected -upstream suffix for unknown audience", cd)
	}
	body := w.Body.String()
	// Sections the upstream view drops are still present in the fallback.
	for _, want := range []string{"#### Notes", "#### Disclosure draft", "## Packages", "## Maintainers"} {
		if !strings.Contains(body, want) {
			t.Errorf("fallback report missing %q (should be the full analyst view)", want)
		}
	}
}

func TestRepoReport_rendersSourceSnippet(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	now := time.Now()
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "abcdef1234567",
		Report: `{"version":1}`, FinishedAt: &now, CreatedAt: now,
	}
	s.DB.Create(&scan)

	s.DB.Create(&db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: scan.Commit,
		FindingID: "F1", Title: "has snippet", Severity: "High", Status: db.FindingNew,
		Location: "main.go:12", Snippet: "func vulnerable() {\n\texec.Command(arg)\n}",
		Trace: "arg reaches exec",
	})
	// A finding without a captured snippet (older row, or location that did
	// not resolve) must render no Source block: an empty snippet leaves no
	// dangling heading.
	s.DB.Create(&db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: scan.Commit,
		FindingID: "F2", Title: "no snippet", Severity: "Low", Status: db.FindingNew,
		Location: "other.go:3", Trace: "nothing captured",
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET",
		"/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/report.md"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	if !strings.Contains(body, "#### Source\n\n```go\nfunc vulnerable() {") {
		t.Errorf("expected go-fenced source block for the finding with a snippet:\n%s", body)
	}
	if n := strings.Count(body, "#### Source"); n != 1 {
		t.Errorf("#### Source count = %d, want 1 (empty snippet must render no block)", n)
	}
}

func TestRepoReport_includesSkillsRepoSHA(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	now := time.Now()
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "abcdef1234567",
		SkillsRepoSHA: "feedface0123456789abcdef0123456789abcdef",
		Report:        `{"version":1}`, FinishedAt: &now, CreatedAt: now,
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET",
		"/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/report.md"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "skills repo `feedface0123`") {
		t.Errorf("report missing skills repo sha line:\n%s", body)
	}
}

func TestRepoReport_omitsSkillsRepoSHAWhenUnset(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	now := time.Now()
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "abcdef1234567",
		Report: `{"version":1}`, FinishedAt: &now, CreatedAt: now,
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET",
		"/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/report.md"))
	body := w.Body.String()
	if strings.Contains(body, "skills repo") {
		t.Errorf("expected no skills-repo mention, got:\n%s", body)
	}
}

func TestRepoReport_summaryAndSinkDisposition(t *testing.T) {
	// A repository with three sinks: S1 becomes a Critical finding, S2
	// is ruled out at step 3, S3 appears in neither. The report must
	// open with a summary (severity counts, top finding pointer, sink
	// coverage) and the inventory table must carry a Disposition column
	// joining each sink to its outcome.
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/acme/three", Name: "three"}
	s.DB.Create(&repo)

	now := time.Now()
	report := `{
		"repository":"https://github.com/acme/three","commit":"feedfacecafe",
		"spec_version":10,"model":"t","date":"2026-06-01","languages":["Go"],
		"boundaries":[{"actor":"user","trusted":"no","controls":"input","source":"docs"}],
		"inventory":[
			{"id":"S1","class":"Command execution","location":"a.go:10","consumes":"arg","primitive":"os.Exec"},
			{"id":"S2","class":"Filesystem write","location":"b.go:20","consumes":"path","primitive":"os.Create"},
			{"id":"S3","class":"Network egress","location":"c.go:30","consumes":"url","primitive":"http.Get"}
		],
		"ruled_out":[{"sinks":["S2"],"step":3,"reason":"path is a compile-time constant. No caller controls it."}],
		"findings":[]
	}`
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "feedfacecafebeef", Report: report,
		FinishedAt: &now, CreatedAt: now,
	}
	s.DB.Create(&scan)

	crit := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: scan.Commit,
		FindingID: "F1", Title: "Argument injection into os.Exec",
		Severity: "Critical", Status: db.FindingReady, Sinks: "S1",
		Location: "a.go:10", Trace: "user input reaches exec",
	}
	s.DB.Create(&crit)
	med := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: scan.Commit,
		FindingID: "F2", Title: "Verbose error leaks path",
		Severity: "Medium", Status: db.FindingEnriched,
		Location: "d.go:5",
	}
	s.DB.Create(&med)

	body := renderRepoReport(s.DB, &repo, audienceAnalyst)

	// Summary block precedes the metadata table.
	if i, j := strings.Index(body, "## Summary"), strings.Index(body, "## Repository metadata"); i < 0 || i > j {
		t.Errorf("summary missing or after metadata; idx summary=%d metadata=%d", i, j)
	}
	wants := []string{
		"## Summary",
		"2 findings: 1 critical, 0 high, 1 medium, 0 low",
		"Argument injection into os.Exec",
		"Sink coverage: 3 catalogued, 1 ruled out, 1 became findings, 1 unresolved",
		"Start with Finding #" + strconv.FormatUint(uint64(crit.ID), 10),
		"`feedfacecaf",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("summary missing %q", want)
		}
	}

	// Disposition column on the inventory table.
	if !strings.Contains(body, "| # | Class | Primitive | Location | Consumes | Disposition |") {
		t.Error("inventory header missing Disposition column")
	}
	for _, want := range []string{
		"| S1 |", "→ Finding #" + strconv.FormatUint(uint64(crit.ID), 10),
		"| S2 |", "ruled out, step 3 — path is a compile-time constant",
		"| S3 |", "unresolved",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("inventory row missing %q", want)
		}
	}
}

func TestRepoReport_sinkDispositionScopedToLatestScan(t *testing.T) {
	// Sink ids are only unique within one report. An older deep-dive scan
	// produced a finding for its "S1"; the latest scan's inventory also has
	// an "S1" but no finding for it. The disposition must read "unresolved"
	// for the latest S1, not point at the older scan's finding.
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/acme/two-scans", Name: "two-scans"}
	s.DB.Create(&repo)

	now := time.Now()
	old := now.Add(-time.Hour)
	oldReport := `{"repository":"r","commit":"old","spec_version":10,"model":"t","date":"2026-05-01","languages":["Go"],
		"inventory":[{"id":"S1","class":"Command execution","location":"old.go:1","consumes":"a","primitive":"exec"}],
		"ruled_out":[],"findings":[]}`
	oldScan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "oldcommit", Report: oldReport,
		FinishedAt: &old, CreatedAt: old,
	}
	s.DB.Create(&oldScan)
	// The older scan's finding claims its own S1.
	oldFinding := db.Finding{
		ScanID: oldScan.ID, RepositoryID: repo.ID, Commit: oldScan.Commit,
		FindingID: "OLD1", Title: "Old scan command injection",
		Severity: "Critical", Status: db.FindingReady, Sinks: "S1", Location: "old.go:1",
	}
	s.DB.Create(&oldFinding)

	latestReport := `{"repository":"r","commit":"new","spec_version":10,"model":"t","date":"2026-06-01","languages":["Go"],
		"inventory":[{"id":"S1","class":"Network egress","location":"new.go:9","consumes":"url","primitive":"http.Get"}],
		"ruled_out":[],"findings":[]}`
	latestScan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "newcommit", Report: latestReport,
		FinishedAt: &now, CreatedAt: now,
	}
	s.DB.Create(&latestScan)

	body := renderRepoReport(s.DB, &repo, audienceAnalyst)

	// The latest S1 row must be unresolved; its disposition must not point
	// at the older scan's finding. (The older finding is still open, so it
	// legitimately appears in the findings list — what must not happen is
	// its id showing up as a disposition pointer.)
	if !strings.Contains(body, "| S1 |") || !strings.Contains(body, "unresolved") {
		t.Errorf("latest S1 should be unresolved; body:\n%s", body)
	}
	oldPointer := "→ Finding #" + strconv.FormatUint(uint64(oldFinding.ID), 10)
	if strings.Contains(body, oldPointer) {
		t.Errorf("older scan's finding %q leaked into a disposition cell", oldPointer)
	}
}

func TestFirstClause(t *testing.T) {
	cases := []struct{ in, want string }{
		{"single sentence", "single sentence"},
		{"first. second.", "first"},
		{"first; second", "first"},
		{"  spaced  ", "spaced"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := firstClause(tc.in); got != tc.want {
			t.Errorf("firstClause(%q) = %q, want %q", tc.in, got, tc.want)
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

func TestLocationLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		// Same file, numeric ordering across magnitudes
		{"x.html:5", "x.html:33", true},
		{"x.html:33", "x.html:5", false},
		{"x.html:110", "x.html:5", false},
		{"x.html:5", "x.html:110", true},
		// Different files: path comparison wins
		{"a.html:99", "b.html:1", true},
		{"b.html:1", "a.html:99", false},
		// Equal paths and lines
		{"x.html:5", "x.html:5", false},
		// Missing line number degrades gracefully (treated as 0)
		{"x.html", "x.html:1", true},
	}
	for _, tc := range cases {
		if got := locationLess(tc.a, tc.b); got != tc.want {
			t.Errorf("locationLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
