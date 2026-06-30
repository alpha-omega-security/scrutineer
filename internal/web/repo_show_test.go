package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

const deepDiveReport = `{
  "boundaries":[{"actor":"library caller","trusted":"yes","controls":"all parameters","source":"README.md:1"}],
  "inventory":[{"id":"S1","location":"lib/x.rb:7","class":"Command execution","consumes":"argv"}]
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
	for _, want := range []string{"library caller", "all parameters", "lib/x.rb:7"} {
		if !strings.Contains(body, want) {
			t.Errorf("deep-dive-only repo page missing %q", want)
		}
	}
	if strings.Contains(body, "Entry-point trust table") {
		t.Errorf("deep-dive-only repo page rendered threat-model-skill section")
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
