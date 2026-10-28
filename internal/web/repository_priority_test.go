package web

import (
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

func priorityTestRepo(t *testing.T, s *Server, name string) db.Repository {
	t.Helper()
	repo := db.Repository{Name: name, URL: "https://example.com/" + name}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func priorityTestInventory(t *testing.T, s *Server, repo db.Repository, skill db.Skill, result string, at time.Time) db.Scan {
	t.Helper()
	scan := db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, SkillName: skill.Name, Kind: "skill", Status: db.ScanDone, FinishedAt: &at,
		Report: `{"analyses":{"inventory":{"status":"ok","result":` + result + `}}}`}
	if err := s.DB.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return scan
}

func priorityTestSBOM(t *testing.T, s *Server, scan db.Scan, owner uint, scope string) {
	t.Helper()
	upload := db.SBOMUpload{Origin: db.SBOMOriginGenerated, Current: true, RepositoryID: &scan.RepositoryID, ScanID: &scan.ID}
	if err := s.DB.Create(&upload).Error; err != nil {
		t.Fatal(err)
	}
	pkg := db.SBOMPackage{SBOMUploadID: upload.ID, Name: "owner/lib", Ecosystem: "actions", PURL: "pkg:githubactions/owner/lib@v1", SourceRepositoryID: &owner, Scope: scope}
	if err := s.DB.Create(&pkg).Error; err != nil {
		t.Fatal(err)
	}
}

func priorityTestPage(t *testing.T, s *Server, query string) string {
	t.Helper()
	w := httptest.NewRecorder()
	values, err := url.ParseQuery(strings.TrimPrefix(query, "&"))
	if err != nil {
		t.Fatal(err)
	}
	if values.Get("sort") == "" {
		values.Set("sort", "consumers")
	}
	values.Set("view", "priorities")
	s.Handler().ServeHTTP(w, localReq("GET", "/?"+values.Encode()))
	if w.Code != 200 {
		t.Fatalf("GET priorities: %d %s", w.Code, w.Body)
	}
	return html.UnescapeString(w.Body.String())
}

func TestRepoPrioritiesConsumerEvidence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	skill := db.Skill{Name: "inventory", OutputKind: "dependencies"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	lib := priorityTestRepo(t, s, "library")
	app := priorityTestRepo(t, s, "application")
	fixture := priorityTestRepo(t, s, "fixtures-only")
	scan := priorityTestInventory(t, s, app, skill, `[
 {"name":"owner/lib","ecosystem":"github-actions","purl":"pkg:githubactions/owner/lib","manifest_path":"ci.yml"},
 {"name":"owner/lib","ecosystem":"github-actions","purl":"pkg:githubactions/owner/lib@v2","manifest_path":"release.yml"}]`, time.Now())
	priorityTestSBOM(t, s, scan, lib.ID, "direct")
	fs := priorityTestInventory(t, s, fixture, skill, `[{"name":"owner/lib","ecosystem":"actions","manifest_path":"testdata/fixture.yml"}]`, time.Now())
	priorityTestSBOM(t, s, fs, lib.ID, "transitive")
	self := priorityTestInventory(t, s, lib, skill, `[{"name":"owner/lib","ecosystem":"actions","manifest_path":"self.yml"}]`, time.Now())
	priorityTestSBOM(t, s, self, lib.ID, "")
	failed := db.Scan{RepositoryID: app.ID, SkillID: &skill.ID, Status: db.ScanDone, Report: `{"error":"inventory failed"}`}
	if err := s.DB.Create(&failed).Error; err != nil {
		t.Fatal(err)
	}
	row := requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if !strings.Contains(row, "1 consumers") || !strings.Contains(row, "1 proven direct") {
		t.Fatal(row)
	}
	if err := s.DB.Model(&db.SBOMUpload{}).Where("repository_id = ?", app.ID).Update("scan_id", failed.ID).Error; err != nil {
		t.Fatal(err)
	}
	row = requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if !strings.Contains(row, "1 consumers") || !strings.Contains(row, "0 proven direct") {
		t.Fatal(row)
	}
	other := priorityTestRepo(t, s, "conflicting-library")
	if err := s.DB.Model(&db.SBOMPackage{}).Where("sbom_upload_id IN (?)", s.DB.Model(&db.SBOMUpload{}).Select("id").Where("repository_id = ?", fixture.ID)).Update("source_repository_id", other.ID).Error; err != nil {
		t.Fatal(err)
	}
	row = requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if !strings.Contains(row, "0 consumers") {
		t.Fatal(row)
	}
}

func TestRepoPrioritiesReadsOnlyNeededReports(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	app := priorityTestRepo(t, s, "application")
	lib := priorityTestRepo(t, s, "library")
	skill := db.Skill{Name: "deps", OutputKind: "dependencies"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	result := `[{"name":"owner/lib","ecosystem":"actions","manifest_path":"ci.yml"}]`
	for range 24 {
		priorityTestInventory(t, s, app, skill, result, time.Now())
	}
	latest := priorityTestInventory(t, s, app, skill, result, time.Now())
	priorityTestSBOM(t, s, latest, lib.ID, "direct")
	capped := priorityTestInventory(t, s, app, skill, result, time.Now())
	if err := s.DB.Model(&capped).Update("cost_capped", true).Error; err != nil {
		t.Fatal(err)
	}
	var reports int
	if err := s.DB.Callback().Query().After("gorm:query").Register("priority-report-count", func(tx *gorm.DB) {
		switch dest := tx.Statement.Dest.(type) {
		case *[]db.Scan:
			for _, scan := range *dest {
				if scan.Report != "" {
					reports++
				}
			}
		case *db.Scan:
			if dest.Report != "" {
				reports++
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	row := requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if !strings.Contains(row, "1 consumers") || reports != 1 {
		t.Fatalf("expected one consumer from one report, read %d reports: %s", reports, row)
	}
	if err := s.DB.Model(&latest).Update("report", `{"error":"unusable"}`).Error; err != nil {
		t.Fatal(err)
	}
	reports = 0
	row = requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if !strings.Contains(row, "1 consumers") || !strings.Contains(row, "0 proven direct") || reports != 2 {
		t.Fatalf("expected fallback without newer directness, read %d reports: %s", reports, row)
	}
}

func TestRepoPrioritiesNavigation(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	for i := 0; i < perPage+1; i++ {
		priorityTestRepo(t, s, fmt.Sprintf("repo-%02d", i))
	}
	lib := priorityTestRepo(t, s, "z-library")
	if err := s.DB.Model(&lib).Updates(map[string]any{"languages": "Go", "archived": true, "ecosystems_packages_data": `[{"name":"owner/lib","ecosystem":"actions","versions_count":0},{"name":"unrelated","ecosystem":"npm","versions_count":0}]`}).Error; err != nil {
		t.Fatal(err)
	}
	app := priorityTestRepo(t, s, "app")
	skill := db.Skill{Name: "deps", OutputKind: "dependencies"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan := priorityTestInventory(t, s, app, skill, `[{"name":"owner/lib","ecosystem":"actions","manifest_path":"ci.yml"}]`, time.Now())
	priorityTestSBOM(t, s, scan, lib.ID, "")
	body := priorityTestPage(t, s, "")
	row := requireRepoListRow(t, body, lib.ID)
	for _, expected := range []string{"owner/lib: registry reports no releases", "Archived", "1 consumers"} {
		if !strings.Contains(row, expected) {
			t.Errorf("missing %q", expected)
		}
	}
	if strings.Contains(row, "unrelated: registry reports no releases") {
		t.Fatal("unrelated package affected priority signals")
	}
	for _, expected := range []string{"Inventory", "Consumers", "Signals", "view=priorities", "page=2"} {
		if !strings.Contains(body, expected) {
			t.Errorf("missing existing list feature %q", expected)
		}
	}
	if strings.Contains(body, "sort=priority") || strings.Contains(body, ">Rescan</button>") {
		t.Fatal("priority view was replaced by sorting the standard table")
	}
	asc := priorityTestPage(t, s, "&sort=consumers.asc")
	if strings.Contains(asc, fmt.Sprintf(`<tr id="repo-%d">`, lib.ID)) {
		t.Fatal("ascending priority did not sort before pagination")
	}
	filtered := priorityTestPage(t, s, "&language=go&q=Z-LIBRARY")
	requireRepoListRow(t, filtered, lib.ID)
	if strings.Count(filtered, `<tr id="repo-`) != 1 {
		t.Fatal("existing filters were ignored")
	}
	if !strings.Contains(filtered, `href="/?view=priorities&q=Z-LIBRARY&queue=&sort=consumers" aria-label="Clear language filter: go"`) {
		t.Fatal("carried language filter must be visible and removable")
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/?sort=newest&q=z-library"))
	plain := html.UnescapeString(w.Body.String())
	if !strings.Contains(plain, `role="menuitem" href="/?view=priorities&q=z-library&language=">Priority view</a>`) {
		t.Fatal("missing priority-view navigation in the existing dropdown")
	}
	if strings.Contains(plain, "sort=priority") || strings.Contains(requireRepoListRow(t, plain, lib.ID), "consumers") {
		t.Fatal("normal repository sorting changed")
	}
	for _, expected := range []string{"Last scan", "Findings", "Rescan"} {
		if !strings.Contains(plain, expected) {
			t.Errorf("missing existing list feature %q", expected)
		}
	}
}

func TestRepoPrioritiesRejectsIncompleteEvidence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	deps := db.Skill{Name: "deps", OutputKind: "dependencies"}
	people := db.Skill{Name: "people", OutputKind: "maintainers"}
	for _, skill := range []*db.Skill{&deps, &people} {
		if err := s.DB.Create(skill).Error; err != nil {
			t.Fatal(err)
		}
	}
	lib := priorityTestRepo(t, s, "library")
	for i, scan := range []db.Scan{
		{CostCapped: true}, {MaxTurnsHit: true}, {Ref: "other"}, {SubPath: "subdir"},
	} {
		repo := priorityTestRepo(t, s, fmt.Sprintf("partial-%d", i))
		scan.RepositoryID, scan.SkillID, scan.Status = repo.ID, &deps.ID, db.ScanDone
		scan.Report = `{"analyses":{"inventory":{"status":"ok","result":[{"name":"owner/lib","ecosystem":"actions","manifest_path":"ci.yml"}]}}}`
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		priorityTestSBOM(t, s, scan, lib.ID, "")
	}
	row := requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if !strings.Contains(row, "0 consumers") {
		t.Fatal("partial or scoped inventories contributed consumers")
	}
	assessment := db.Scan{RepositoryID: lib.ID, SkillID: &people.ID, Status: db.ScanDone, Report: `{"maintainers":[{"login":"person","role":"lead","status":"inactive"}]}`}
	if err := s.DB.Create(&assessment).Error; err != nil {
		t.Fatal(err)
	}
	row = requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if !strings.Contains(row, "Inactive maintainers") {
		t.Fatal("missing complete assessment")
	}
	assessment.ID, assessment.CostCapped = 0, true
	if err := s.DB.Create(&assessment).Error; err != nil {
		t.Fatal(err)
	}
	row = requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
	if strings.Contains(row, "Inactive maintainers") {
		t.Fatal("partial assessment treated as complete")
	}
}

func TestRepoPrioritiesReleaseSignals(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	lib := priorityTestRepo(t, s, "library")
	app := priorityTestRepo(t, s, "app")
	skill := db.Skill{Name: "deps", OutputKind: "dependencies"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan := priorityTestInventory(t, s, app, skill, `[{"name":"owner/lib","ecosystem":"github-actions","manifest_path":"ci.yml"}]`, time.Now())
	priorityTestSBOM(t, s, scan, lib.ID, "")
	for _, tc := range []struct {
		name, metadata, label string
		want                  bool
	}{
		{"old", `[{"name":"owner/lib","ecosystem":"actions","versions_count":2,"latest_release_published_at":"2020-01-01T00:00:00Z"}]`, "Old release", true},
		{"unknown count", `[{"name":"owner/lib","ecosystem":"actions"}]`, "No releases", false},
		{"zero count", `[{"name":"owner/lib","ecosystem":"actions","versions_count":0}]`, "No releases", true},
		{"wrong ecosystem", `[{"name":"owner/lib","ecosystem":"golang","versions_count":0}]`, "No releases", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.DB.Model(&lib).Update("ecosystems_packages_data", tc.metadata).Error; err != nil {
				t.Fatal(err)
			}
			row := requireRepoListRow(t, priorityTestPage(t, s, ""), lib.ID)
			if strings.Contains(row, tc.label) != tc.want {
				t.Fatal(row)
			}
		})
	}
}

func TestRepoPrioritiesFindingsAndLastScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	for i := 0; i < perPage+1; i++ {
		priorityTestRepo(t, s, fmt.Sprintf("empty-%02d", i))
	}
	repo := priorityTestRepo(t, s, "z-audited")
	audit := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "security-deep-dive", Status: db.ScanDone}
	scanner := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "semgrep", Status: db.ScanDone}
	for _, scan := range []*db.Scan{&audit, &scanner} {
		if err := s.DB.Create(scan).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, finding := range []db.Finding{
		{ScanID: audit.ID, Status: db.FindingNew},
		{ScanID: audit.ID, Status: db.FindingAcknowledged},
		{ScanID: audit.ID, Status: db.FindingFixed},
		{ScanID: audit.ID, Status: db.FindingRejected},
		{ScanID: scanner.ID, Status: db.FindingNew},
	} {
		finding.RepositoryID = repo.ID
		finding.Title = "Example finding"
		if err := s.DB.Create(&finding).Error; err != nil {
			t.Fatal(err)
		}
	}
	date := time.Date(2026, time.October, 20, 12, 30, 0, 0, time.UTC)
	latest := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "metadata", Status: db.ScanDone, CreatedAt: date}
	if err := s.DB.Create(&latest).Error; err != nil {
		t.Fatal(err)
	}
	for _, sort := range []string{"findings", "scanned"} {
		body := priorityTestPage(t, s, "&sort="+sort)
		row := requireRepoListRow(t, body, repo.ID)
		if !strings.Contains(row, `class="badge-destructive">2</span>`) {
			t.Fatalf("%s count: %s", sort, row)
		}
		if !strings.Contains(row, fmt.Sprintf(`href="/scans/%d" title="2026-10-20 12:30:00 UTC">2026-10-20</a>`, latest.ID)) {
			t.Fatalf("%s latest scan: %s", sort, row)
		}
		if !strings.Contains(body, "sort="+sort+".asc&view=priorities") {
			t.Fatal("column sort lost priority view")
		}
		ascending := priorityTestPage(t, s, "&sort="+sort+".asc")
		if strings.Contains(ascending, fmt.Sprintf(`<tr id="repo-%d">`, repo.ID)) {
			t.Fatalf("%s ascending sort did not run before pagination", sort)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/?q=z-audited"))
	regular := requireRepoListRow(t, w.Body.String(), repo.ID)
	if !strings.Contains(regular, `class="badge-destructive">2</span>`) {
		t.Fatal("priority findings differ from regular list")
	}
	empty := priorityTestPage(t, s, "&q=empty-00")
	row := requireRepoListRow(t, empty, 1)
	if !strings.Contains(row, `class="badge-secondary">0</span>`) || strings.Count(row, "never") != 2 {
		t.Fatal("missing scans/findings did not render as zero and never")
	}
}

func testPriorityViewDatabase(t *testing.T, s *Server) {
	t.Helper()
	app := priorityTestRepo(t, s, "priority-app")
	lib := priorityTestRepo(t, s, "priority-library")
	if err := s.DB.Model(&lib).Updates(map[string]any{"languages": "Go", "ecosystems_packages_data": `[{"name":"owner/lib","ecosystem":"actions","versions_count":0}]`}).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "priority-deps", OutputKind: "dependencies"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	valid := priorityTestInventory(t, s, app, skill, `[{"name":"owner/lib","ecosystem":"actions","manifest_path":"ci.yml"}]`, time.Now())
	priorityTestSBOM(t, s, valid, lib.ID, "direct")
	broken := priorityTestInventory(t, s, app, skill, `null`, time.Now())
	if err := s.DB.Model(&broken).Update("report", `{"error":"incomplete"}`).Error; err != nil {
		t.Fatal(err)
	}
	audit := db.Scan{RepositoryID: lib.ID, SkillName: "security-deep-dive", Status: db.ScanDone}
	if err := s.DB.Create(&audit).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Create(&db.Finding{RepositoryID: lib.ID, ScanID: audit.ID, Title: "Priority finding", Status: db.FindingNew}).Error; err != nil {
		t.Fatal(err)
	}
	row := requireRepoListRow(t, priorityTestPage(t, s, "&sort=findings&language=go&q=priority-library"), lib.ID)
	for _, want := range []string{"1 consumers", "1 proven direct", "No releases", `class="badge-destructive">1</span>`, fmt.Sprintf(`href="/scans/%d"`, audit.ID)} {
		if !strings.Contains(row, want) {
			t.Errorf("missing %q: %s", want, row)
		}
	}
	refresh := priorityTestPage(t, s, "&queue=refresh&q=priority-app")
	row = requireRepoListRow(t, refresh, app.ID)
	if !strings.Contains(row, fmt.Sprintf(`href="/scans/%d"`, valid.ID)) {
		t.Fatal("failed scan did not fall back to usable inventory")
	}
}
