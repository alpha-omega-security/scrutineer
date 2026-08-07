package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

const deepDiveReport = `{
  "boundaries":[{"actor":"library caller","trusted":"yes","controls":"all parameters","source":"README.md:1"}],
  "method":{"scope":"./src","grep_patterns":[{"class":"Memory safety","primitive":"realloc","command":"grep -rn realloc ./src","hit_count":1,"inventory_sinks":["S1"],"excluded_hits":[]}],"inventory_count":1,"ruled_out_count":0,"unresolved_count":0},
  "inventory":[{"id":"S1","location":"lib/x.rb:7","class":"Command execution","boundary":"library caller","consumes":"argv"}]
}`

const threatModelReport = `{
  "spec_version":1,
  "description":"Sample compressor library.",
  "components":[{"name":"core","entry_points":["inflate"],"touches":[],"in_scope":true,"provenance":"inferred"}],
  "trust_boundaries":[{"component":"core","boundary":"public API surface","reachability_precondition":"reachable from input bytes","provenance":"inferred"}],
  "entry_points":[{"entry_point":"gzopen","parameter":"path","attacker_controllable":"no","caller_must_enforce":"sanitise path","provenance":"documented","source":"zlib.h:1400"}],
  "adversaries":{"in_scope":["input supplier"],"out_of_scope":["host process"],"provenance":"inferred"},
  "properties_provided":[{"property":"memory safety on bounded input","violation_symptom":"OOB write","severity_tier":"security","provenance":"documented","source":"SECURITY.md:8"}],
  "properties_not_provided":[{"property":"bounded output size","reason":"caller's job","false_friend":false,"provenance":"inferred"}],
  "downstream_responsibilities":["cap decompressed output"],
  "known_non_findings":[{"reported_as":"strcpy in gzlib.c","why_safe":"length bounded","cites":"properties_provided[0]"}],
  "open_questions":[{"claim":"path is caller-trusted","field":"entry_points","proposed":"yes"}]
}`

func getRepoPage(t *testing.T, s *Server, id uint) string {
	t.Helper()
	return getRepoPagePath(t, s, fmt.Sprintf("/repositories/%d", id))
}

func getRepoPagePath(t *testing.T, s *Server, path string) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	return w.Body.String()
}

func TestRepoShow_scanAllButton(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)

	// No subprojects: the Subprojects section (and its Scan all button) is hidden.
	body := getRepoPage(t, s, repo.ID)
	if strings.Contains(body, "/scan-all") {
		t.Error("repo with no subprojects should not render the Scan all button")
	}

	// With subprojects, the bulk button posts to the repo-scoped scan-all route.
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "pkg/a", Name: "a"})
	body = getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, fmt.Sprintf("/repositories/%d/scan-all", repo.ID)) {
		t.Errorf("Scan all button should post to the repo-scoped scan-all route; body=%s", body)
	}
	if !strings.Contains(body, "Scan all") {
		t.Error("Subprojects section should render a Scan all button label")
	}
}

func TestRepoShow_threatModelTab_deepDiveOnly(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "deadbee", Report: deepDiveReport})

	body := getRepoPage(t, s, repo.ID)
	for _, want := range []string{"library caller", "all parameters", "lib/x.rb:7", "<th>Boundary</th>", "Inventory method", "grep -rn realloc ./src"} {
		if !strings.Contains(body, want) {
			t.Errorf("deep-dive-only repo page missing %q", want)
		}
	}
	if strings.Contains(body, "Entry-point trust table") {
		t.Errorf("deep-dive-only repo page rendered threat-model-skill section")
	}
}

func TestRepoShow_threatModelTab_legacyInventoryOmitsBoundary(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/legacy", Name: "legacy"}
	s.DB.Create(&repo)
	legacyReport := strings.Replace(deepDiveReport, `,"boundary":"library caller"`, "", 1)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "deadbee", Report: legacyReport})

	body := getRepoPage(t, s, repo.ID)
	if strings.Contains(body, "no value") {
		t.Errorf("legacy inventory rendered missing boundary marker: %s", body)
	}
	if !strings.Contains(body, "lib/x.rb:7") {
		t.Errorf("legacy inventory row missing location: %s", body)
	}
}

func TestRepoShow_threatModelTab_prefersThreatModelSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "deadbee", Report: deepDiveReport})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: threatModelSkillName, Commit: "abc1234", Report: threatModelReport})

	body := getRepoPage(t, s, repo.ID)
	for _, want := range []string{
		"Sample compressor library",
		"Entry-point trust table", "gzopen", "sanitise path", "zlib.h:1400",
		"public API surface", "input supplier",
		"memory safety on bounded input", "OOB write",
		"bounded output size",
		"cap decompressed output",
		"strcpy in gzlib.c", "length bounded",
		"path is caller-trusted",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("threat-model repo page missing %q", want)
		}
	}
	for _, gone := range []string{"library caller", "lib/x.rb:7"} {
		if strings.Contains(body, gone) {
			t.Errorf("threat-model repo page still showing deep-dive content %q", gone)
		}
	}
}

func TestRepoShow_dependenciesTab_linksManifests(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "dependencies", OutputKind: "dependencies"}
	s.DB.Create(&skill)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: "dependencies", Commit: "deadbee"})
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "left-pad", Ecosystem: "npm",
		Requirement: "^1.0.0", DependencyType: "direct",
		ManifestPath: "app/package.json", ManifestKind: "manifest"})

	body := getRepoPage(t, s, repo.ID)
	want := fmt.Sprintf(`href="/repositories/%d/blob/deadbee/app/package.json"`, repo.ID)
	if !strings.Contains(body, want) {
		t.Errorf("dependencies tab missing manifest code-browser link %q", want)
	}
}

func TestRepoShow_dependenciesTab_plainManifestWithoutDoneScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	// Dependency rows exist but no completed dependencies scan provides a
	// commit to pin the blob link to, so the path renders as plain text.
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "left-pad", Ecosystem: "npm",
		ManifestPath: "package.json", ManifestKind: "manifest"})

	body := getRepoPage(t, s, repo.ID)
	if strings.Contains(body, "/blob/") {
		t.Errorf("expected no manifest blob link without a completed dependencies scan")
	}
	if !strings.Contains(body, "package.json") {
		t.Errorf("expected manifest path to still render as text")
	}
}

func TestRepoShow_dependenciesTabHiddenWhenNoDependencies(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)

	body := getRepoPage(t, s, repo.ID)
	for _, hidden := range []string{
		`id="rt5"`,
		`id="rp5"`,
	} {
		if strings.Contains(body, hidden) {
			t.Errorf("repo with no dependencies should not render %q", hidden)
		}
	}
}

func TestRepoShow_dependenciesTab_hidesNonRuntimeByDefault(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "runtime-lib", Ecosystem: "npm",
		DependencyType: db.DependencyRuntime, ManifestPath: "package.json", ManifestKind: "manifest"})
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "test-helper", Ecosystem: "npm",
		DependencyType: db.DependencyTest, ManifestPath: "package.json", ManifestKind: "manifest"})

	body := getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "runtime-lib") {
		t.Errorf("runtime dependency should render in default view")
	}
	if strings.Contains(body, "test-helper") {
		t.Errorf("test dependency should be hidden by default")
	}
	if !strings.Contains(body, "Include test/build/dev") {
		t.Errorf("default view should render non-runtime toggle")
	}
	if !strings.Contains(body, `id="rt5"`) || !strings.Contains(body, `id="rp5"`) {
		t.Errorf("dependencies tab should still render when only filtered dependency rows are hidden")
	}

	body = getRepoPagePath(t, s, fmt.Sprintf("/repositories/%d?deps=all", repo.ID))
	if !strings.Contains(body, "test-helper") {
		t.Errorf("deps=all should render non-runtime dependencies")
	}
	if !strings.Contains(body, "Runtime only") {
		t.Errorf("deps=all should render runtime-only toggle")
	}
}

func TestRepoShow_threatModelTab_fallsBackWhenSkillScanRunning(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "deadbee", Report: deepDiveReport})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning,
		SkillName: threatModelSkillName, Commit: "abc1234", Report: ""})

	body := getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "library caller") {
		t.Errorf("expected fallback to deep-dive boundaries while threat-model scan is running")
	}
}

// The row swap the SSE payload carries can only update a scan already on
// screen: a scan queued after the page was rendered has no row, and the
// Cancel/Resume/Retry counts sit outside the table. The tab therefore
// re-requests its own table on the same event.
func TestRepoShow_scansTabRefreshesItsTable(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/tab", Name: "tab"}
	s.DB.Create(&repo)

	body := getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, fmt.Sprintf(`hx-get="/repositories/%d/scans"`, repo.ID)) {
		t.Errorf("Scans tab does not re-request its table on a status event:\n%s", body)
	}
	if !strings.Contains(body, `hx-target="#repo-scans"`) {
		t.Error("refresh is not aimed at the Scans tab table")
	}
	// The listener has to sit outside the swapped table, or the swap drops the
	// EventSource it relies on. Both markers are located first: a missing one
	// yields -1, which would satisfy the ordering check on its own.
	table, listener := strings.Index(body, `id="repo-scans"`), strings.Index(body, "sse-connect")
	if table < 0 || listener < 0 {
		t.Fatalf("expected both the table and the SSE listener; table=%d listener=%d", table, listener)
	}
	if table > listener {
		t.Error("the SSE listener must be declared after (outside) the table it replaces")
	}
}

func TestRepoScansFragment(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/frag", Name: "frag"}
	s.DB.Create(&repo)
	running := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit",
		Status: db.ScanRunning, StatusPriority: db.StatusPriorityFor(db.ScanRunning)}
	s.DB.Create(&running)
	failed := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "triage",
		Status: db.ScanFailed, StatusPriority: db.StatusPriorityFor(db.ScanFailed)}
	s.DB.Create(&failed)

	r := localReq("GET", fmt.Sprintf("/repositories/%d/scans", repo.ID))
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	if !strings.Contains(body, `id="repo-scans"`) {
		t.Errorf("fragment missing its swap target:\n%s", body)
	}
	if strings.Contains(body, "<html") || strings.Contains(body, "sse-connect") {
		t.Error("the fragment must be the table alone, not the repo page")
	}
	for _, id := range []uint{running.ID, failed.ID} {
		if !strings.Contains(body, fmt.Sprintf(`id="scan-%d"`, id)) {
			t.Errorf("scan %d missing from the fragment", id)
		}
	}
	// The counts live outside the rows, which is why a row swap alone cannot
	// keep this tab honest.
	if !strings.Contains(body, "Cancel all (1)") {
		t.Errorf("running scan not reflected in the Cancel all count:\n%s", body)
	}
	if !strings.Contains(body, "Retry failed (1)") {
		t.Errorf("failed scan not reflected in the Retry failed count:\n%s", body)
	}
}

// The fragment reads a narrowed projection (scanRowColumns) while the page reads
// whole rows, so a column the projection forgets renders blank on refresh and
// correct on load. Comparing the same row from both paths is what catches it.
func TestRepoScansFragment_rowMatchesTheFullPage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/parity", Name: "parity"}
	s.DB.Create(&repo)

	startedAt := time.Now().Add(-5 * time.Minute)
	finishedAt := startedAt.Add(2 * time.Minute)
	// Every field scan-row and scan-actions read is populated, so a dropped
	// column shows up as a difference rather than as two identical blanks.
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", SubPath: "pkg/api",
		Status: db.ScanFailed, StatusPriority: db.StatusPriorityFor(db.ScanFailed),
		Ref: "release-1.2", RescanMode: "diff", MaxTurnsHit: true, RefusalAuditWarning: true,
		FindingsCount: 3, Model: "claude-opus-5", CostUSD: 1.25, Commit: "deadbeefcafe",
		StartedAt: &startedAt, FinishedAt: &finishedAt,
		Log: strings.Repeat("log line\n", 100), Report: `{"big":"report"}`,
	}
	s.DB.Create(&scan)
	skill := db.Skill{Name: "audit", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	s.DB.Model(&db.Scan{}).Where("id = ?", scan.ID).Update("skill_id", skill.ID)

	r := localReq("GET", fmt.Sprintf("/repositories/%d/scans", repo.ID))
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	marker := fmt.Sprintf(`<tr id="scan-%d"`, scan.ID)
	fromFragment := scanRow(t, w.Body.String(), marker)
	fromPage := scanRow(t, getRepoPage(t, s, repo.ID), marker)
	if fromFragment != fromPage {
		t.Errorf("the narrowed projection drops a column the table renders\nfragment: %s\npage:     %s",
			fromFragment, fromPage)
	}
	// The point of the projection: the table never reads these.
	if strings.Contains(w.Body.String(), "log line") || strings.Contains(w.Body.String(), "big") {
		t.Error("fragment leaked a large text column into the response")
	}
}

func scanRow(t *testing.T, body, marker string) string {
	t.Helper()
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatalf("row %q not found in:\n%s", marker, body)
	}
	end := strings.Index(body[start:], "</tr>")
	if end < 0 {
		t.Fatalf("row %q is unterminated", marker)
	}
	return body[start : start+end]
}

func TestRepoScansFragment_unknownRepository(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	r := localReq("GET", "/repositories/4242/scans")
	r.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 404 {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// Only htmx wants a layout-less table. A stray visit is sent to the tab itself
// rather than being served bare markup, which also keeps it from popping the
// flash cookie into a fragment that cannot display it.
func TestRepoScansFragment_plainVisitRedirectsToTheTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/plain", Name: "plain"}
	s.DB.Create(&repo)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d/scans", repo.ID)))

	if w.Code != 303 {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if got, want := w.Header().Get("Location"), fmt.Sprintf("/repositories/%d#rt3", repo.ID); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
	if cookies := w.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("a redirect must not touch the flash cookie: %v", cookies)
	}
}
