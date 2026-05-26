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

// seedScanWithFindings creates a repo + a findings-kind skill + a completed
// scan with two findings. Used to exercise the findings dispatch path of
// scanReport.
func seedScanWithFindings(t *testing.T, s *Server) (db.Repository, db.Skill, db.Scan) {
	t.Helper()
	repo := db.Repository{
		URL: "https://github.com/acme/thing", Name: "thing", FullName: "acme/thing",
	}
	s.DB.Create(&repo)

	skill := db.Skill{
		Name: "semgrep", OutputKind: "findings", OutputFile: "report.json",
		Version: 1, Active: true, Source: "ui",
	}
	s.DB.Create(&skill)

	now := time.Now()
	started := now.Add(-90 * time.Second)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: skill.Name, Commit: "deadbeef1234567",
		Model: "claude-opus-4-6", CostUSD: 0.15, Turns: 9, FindingsCount: 2,
		StartedAt: &started, FinishedAt: &now, CreatedAt: started,
		Report: `{"findings":[]}`,
	}
	s.DB.Create(&scan)

	high := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: scan.Commit,
		FindingID: "F1", Title: "python.lang.security.use-defused-xml",
		Severity: "High", Status: db.FindingNew, CWE: "CWE-611",
		Location: "src/typestubs/py_serializable/__init__.pyi:5",
		Trace:    "xml.etree.ElementTree is vulnerable to XXE",
	}
	// medium is the grouped multi-location case from #193 — same rule
	// firing at several template positions, collapsed into one row.
	// Locations are intentionally not pre-sorted, and include numbers
	// that would mis-order under lexicographic comparison (:33 < :5),
	// to exercise the natural-sort path in writeReportFinding.
	medium := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: scan.Commit,
		FindingID: "F2", Title: "generic.html-templates.security.var-in-href",
		Severity: "Medium", Status: db.FindingNew, CWE: "CWE-79",
		Location:  "src/atr/templates/topnav.html:5",
		Locations: "src/atr/templates/topnav.html:5\nsrc/atr/templates/topnav.html:110\nsrc/atr/templates/topnav.html:33\nsrc/atr/templates/index.html:88",
		Trace:     "template variable in href; subject to javascript: URI XSS",
	}
	s.DB.Create(&high)
	s.DB.Create(&medium)

	return repo, skill, scan
}

func TestScanReport_findingsDispatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, _, scan := seedScanWithFindings(t, s)

	path := "/scans/" + strconv.FormatUint(uint64(scan.ID), 10) + "/report.md"
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
	// Filename should encode repo, scan id, and skill so a directory of
	// downloaded reports stays unambiguous without renaming.
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "scan-") || !strings.Contains(cd, "semgrep") {
		t.Errorf("content-disposition missing scan/skill in filename: %q", cd)
	}

	body := w.Body.String()
	wants := []string{
		"# semgrep — scan #",
		"acme/thing",
		"## Scan metadata",
		"| Skill | semgrep |",
		"| Output kind | findings |",
		"| Cost | $0.1500 |",
		"## Findings",
		"2 finding(s).",
		// Summary table row
		"| python.lang.security.use-defused-xml |",
		// Per-finding section heading
		"### Finding #",
		"python.lang.security.use-defused-xml",
		"#### Trace",
		"xml.etree.ElementTree is vulnerable to XXE",
		"### Finding #",
		"generic.html-templates.security.var-in-href",
		"template variable in href",
		// Grouped multi-location finding shows the additional positions
		"#### Additional locations",
		"`src/atr/templates/topnav.html:33`",
		"`src/atr/templates/topnav.html:110`",
		"`src/atr/templates/index.html:88`",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	// Single-location finding (the High XXE one) should NOT get the
	// "Additional locations" block, only the multi-location one should.
	if strings.Count(body, "#### Additional locations") != 1 {
		t.Errorf("expected exactly one Additional locations block (multi-location finding only), got %d",
			strings.Count(body, "#### Additional locations"))
	}

	// Additional locations must be naturally sorted: index.html comes
	// alphabetically before topnav.html, and within topnav.html line 33
	// must precede line 110 (numeric, not lexicographic, where "110" < "33").
	indexAt := strings.Index(body, "`src/atr/templates/index.html:88`")
	topnav33At := strings.Index(body, "`src/atr/templates/topnav.html:33`")
	topnav110At := strings.Index(body, "`src/atr/templates/topnav.html:110`")
	if indexAt < 0 || topnav33At < 0 || topnav110At < 0 {
		t.Fatalf("expected all three sorted locations in body; got positions index=%d t33=%d t110=%d",
			indexAt, topnav33At, topnav110At)
	}
	if indexAt >= topnav33At || topnav33At >= topnav110At {
		t.Errorf("additional locations not naturally sorted: index=%d t33=%d t110=%d",
			indexAt, topnav33At, topnav110At)
	}
}

func TestScanReport_freeformRendersAsTable(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/thing", Name: "thing"}
	s.DB.Create(&repo)
	skill := db.Skill{
		Name: "maintainers", OutputKind: "maintainers", OutputFile: "report.json",
		Version: 1, Active: true, Source: "ui",
	}
	s.DB.Create(&skill)
	now := time.Now()
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: skill.Name, Commit: "abcdef0123456",
		FinishedAt: &now, CreatedAt: now,
		Report: `{"maintainers":[{"login":"alice","email":"alice@example.org"},{"login":"bob","email":"bob@example.org"}]}`,
	}
	s.DB.Create(&scan)

	path := "/scans/" + strconv.FormatUint(uint64(scan.ID), 10) + "/report.md"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	wants := []string{
		"# maintainers — scan #",
		"## Scan metadata",
		"| Output kind | maintainers |",
		"## Report (maintainers)",
		"### maintainers (2)",
		"| login | email |",
		"| alice | alice@example.org |",
		"| bob | bob@example.org |",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\nbody:\n%s", want, body)
		}
	}
	// We replaced the raw JSON dump with table rendering. The fenced
	// block should be gone, and we should not see a Findings section
	// either (different output kind).
	if strings.Contains(body, "```json") {
		t.Errorf("freeform with table-shaped JSON should not emit a json code block")
	}
	if strings.Contains(body, "## Findings") {
		t.Errorf("non-findings kind should not produce a Findings section")
	}
}

func TestScanReport_cycloneDXHeading(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/thing", Name: "thing"}
	s.DB.Create(&repo)
	skill := db.Skill{
		Name: "sbom", OutputKind: "freeform", OutputFile: "report.json",
		Version: 1, Active: true, Source: "ui",
	}
	s.DB.Create(&skill)
	now := time.Now()
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: skill.Name, Commit: "abcdef0123456",
		FinishedAt: &now, CreatedAt: now,
		Report: `{
			"version":1,"bomFormat":"CycloneDX","specVersion":"1.5",
			"metadata":{"timestamp":"2026-05-08T19:09:06Z"},
			"components":[
				{"type":"library","name":"actions/checkout","version":"de0fac2","purl":"pkg:githubactions/actions/checkout","licenses":[{"id":"MIT"}]},
				{"type":"library","name":"actions/cache","version":"27d5ce7","purl":"pkg:githubactions/actions/cache","licenses":[{"id":"MIT"}]}
			]
		}`,
	}
	s.DB.Create(&scan)

	path := "/scans/" + strconv.FormatUint(uint64(scan.ID), 10) + "/report.md"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	wants := []string{
		"## SBOM (CycloneDX 1.5)",
		"| bomFormat | CycloneDX |",
		"### components (2)",
		"| name | version | type | licenses | purl |",
		"| actions/checkout | de0fac2 | library | MIT |",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\nbody:\n%s", want, body)
		}
	}
}

func TestScanReport_rawFallbackForUntabulatableJSON(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/thing", Name: "thing"}
	s.DB.Create(&repo)
	skill := db.Skill{
		Name: "weird", OutputKind: "freeform", OutputFile: "report.json",
		Version: 1, Active: true, Source: "ui",
	}
	s.DB.Create(&skill)
	now := time.Now()
	// Bare array at top level — can't be classified as scalars+arrays
	// because the writer expects a top-level object. Should fall through
	// to the raw JSON block path.
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: skill.Name, Commit: "abcdef0123456",
		FinishedAt: &now, CreatedAt: now,
		Report: `["one","two","three"]`,
	}
	s.DB.Create(&scan)

	path := "/scans/" + strconv.FormatUint(uint64(scan.ID), 10) + "/report.md"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "## Raw report (freeform)") {
		t.Errorf("untabulatable JSON should fall through to raw block; body:\n%s", body)
	}
	if !strings.Contains(body, "```json") {
		t.Errorf("raw fallback should fence as json; body:\n%s", body)
	}
}

func TestScanReport_findsReObservedFindings(t *testing.T) {
	// Regression test for the case where every finding in a scan is a
	// re-observation: scan_id points at an earlier scan, last_seen_scan_id
	// points at this one. Querying by scan_id alone returns nothing and
	// the markdown export erroneously says "No findings recorded".
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/acme/thing", Name: "thing"}
	s.DB.Create(&repo)
	skill := db.Skill{
		Name: "semgrep", OutputKind: "findings", OutputFile: "report.json",
		Version: 1, Active: true, Source: "ui",
	}
	s.DB.Create(&skill)
	now := time.Now()

	// Earlier scan that first introduced the finding.
	earlier := &db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: skill.Name, Commit: "old123",
		FinishedAt: &now, CreatedAt: now,
	}
	s.DB.Create(earlier)

	// Current scan that re-observed the same finding.
	current := &db.Scan{
		RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: skill.Name, Commit: "new456",
		FinishedAt: &now, CreatedAt: now, FindingsCount: 1,
	}
	s.DB.Create(current)

	// Finding first-observed earlier, last-observed now.
	f := db.Finding{
		ScanID: earlier.ID, RepositoryID: repo.ID, Commit: earlier.Commit,
		FindingID: "F1", Title: "python.lang.security.use-defused-xml",
		Severity: "High", Status: db.FindingNew, CWE: "CWE-611",
		Location:       "src/typestubs/py_serializable/__init__.pyi:5",
		Trace:          "xml.etree.ElementTree is vulnerable to XXE",
		LastSeenScanID: current.ID,
		LastSeenCommit: current.Commit,
		SeenCount:      2,
	}
	s.DB.Create(&f)

	path := "/scans/" + strconv.FormatUint(uint64(current.ID), 10) + "/report.md"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if strings.Contains(body, "No findings recorded") {
		t.Errorf("re-observed finding should render, not the empty-state message; body:\n%s", body)
	}
	if !strings.Contains(body, "python.lang.security.use-defused-xml") {
		t.Errorf("re-observed finding title missing from body:\n%s", body)
	}
}

func TestScanReport_notFoundFor404Scan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans/999999/report.md"))
	if w.Code != 404 {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
