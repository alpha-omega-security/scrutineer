package web

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

// seedRunningScan creates a repo + running scan with an API token so API
// calls made with that token are authorised.
func seedRunningScan(t *testing.T, s *Server) (db.Repository, db.Scan) {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	now := time.Now()
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         worker.JobSkill,
		Status:       db.ScanRunning,
		Model:        "fake",
		APIToken:     "tok-" + strconv.FormatUint(uint64(repo.ID), 10),
		StartedAt:    &now,
	}
	s.DB.Create(&scan)
	return repo, scan
}

func TestAPIRejectsMissingBearer(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	r := httptest.NewRequest("GET", "/api/repositories/1", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("status %d, want 401. body=%s", w.Code, w.Body)
	}
}

func TestAPIRejectsCrossRepoAccess(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, scan := seedRunningScan(t, s)

	// Second repo; the token from scan (on repo #1) must not read it.
	other := db.Repository{URL: "https://example.com/y", Name: "y"}
	s.DB.Create(&other)

	r := httptest.NewRequest("GET", "/api/repositories/"+strconv.FormatUint(uint64(other.ID), 10), nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("status %d, want 403. body=%s", w.Code, w.Body)
	}
}

func TestAPIListsTypedReads(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	// Seed one row in each typed table.
	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "foo", Ecosystem: "rubygems", PURL: "pkg:gem/foo"})
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "bar", Ecosystem: "rubygems"})
	s.DB.Create(&db.Advisory{RepositoryID: repo.ID, UUID: "u1", Severity: "HIGH", CVSSScore: 7.5})
	s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: "dep", Ecosystem: "rubygems", ManifestPath: "Gemfile"})
	m := db.Maintainer{Login: "alice"}
	s.DB.Create(&m)
	if err := s.DB.Model(&repo).Association("Maintainers").Append(&m); err != nil {
		t.Fatal(err)
	}

	cases := map[string]int{
		"/api/repositories/%d/packages":     1,
		"/api/repositories/%d/dependents":   1,
		"/api/repositories/%d/advisories":   1,
		"/api/repositories/%d/dependencies": 1,
		"/api/repositories/%d/maintainers":  1,
	}
	for path, want := range cases {
		r := httptest.NewRequest("GET", replaceID(path, repo.ID), nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+scan.APIToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("%s status %d: %s", path, w.Code, w.Body)
			continue
		}
		var got []map[string]any
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Errorf("%s decode: %v", path, err)
			continue
		}
		if len(got) != want {
			t.Errorf("%s len=%d want=%d", path, len(got), want)
		}
	}
}

func TestAPIFindingReadsAndFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	// Simulate a prior deep-dive scan with a couple of findings attached.
	prior := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&prior)
	s.DB.Create(&db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "a", Severity: "High", Location: "a.go:1", Trace: "trace a"})
	s.DB.Create(&db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, FindingID: "F2", Title: "b", Severity: "Low", Location: "b.go:1", Trace: "trace b"})

	// Unfiltered list
	r := httptest.NewRequest("GET", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("findings list status %d: %s", w.Code, w.Body)
	}
	var findings []map[string]any
	_ = json.NewDecoder(w.Body).Decode(&findings)
	if len(findings) != 2 {
		t.Fatalf("findings len=%d want=2", len(findings))
	}

	// Severity filter
	r = httptest.NewRequest("GET",
		"/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?severity=High", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	_ = json.NewDecoder(w.Body).Decode(&findings)
	if len(findings) != 1 || findings[0]["severity"] != "High" {
		t.Errorf("severity filter: %+v", findings)
	}

	// Get one finding; should include trace prose.
	fid := findings[0]["id"]
	r = httptest.NewRequest("GET", "/api/findings/"+toString(fid), nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("get finding status %d: %s", w.Code, w.Body)
	}
	var detail map[string]any
	_ = json.NewDecoder(w.Body).Decode(&detail)
	if detail["trace"] != "trace a" {
		t.Errorf("finding detail missing trace: %+v", detail)
	}
}

func TestAPIListDependencyFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	app, scan := seedRunningScan(t, s)

	// App declares roo via Gemfile (ecosystem "gem", git-pkgs naming).
	s.DB.Create(&db.Dependency{RepositoryID: app.ID, Name: "roo", Ecosystem: "gem", Requirement: "~> 2.10", ManifestPath: "Gemfile", ManifestKind: "manifest", DependencyType: "runtime"})
	s.DB.Create(&db.Dependency{RepositoryID: app.ID, Name: "roo", Ecosystem: "gem", Requirement: "2.10.1", ManifestPath: "Gemfile.lock", ManifestKind: "lockfile", DependencyType: "runtime"})
	s.DB.Create(&db.Dependency{RepositoryID: app.ID, Name: "leftpad", Ecosystem: "npm", ManifestPath: "package.json"})

	// Library repo publishes roo to rubygems (ecosyste.ms naming) and has findings.
	lib := db.Repository{URL: "https://example.com/roo", Name: "roo"}
	s.DB.Create(&lib)
	s.DB.Create(&db.Package{RepositoryID: lib.ID, Name: "roo", Ecosystem: "rubygems"})
	libScan := db.Scan{RepositoryID: lib.ID, Kind: worker.JobSkill, Status: db.ScanDone}
	s.DB.Create(&libScan)
	s.DB.Create(&db.Finding{ScanID: libScan.ID, RepositoryID: lib.ID, Title: "xlsx bomb", Severity: sevHigh, CWE: "CWE-770", Location: "lib/roo/excelx.rb:42", Status: db.FindingNew, Trace: "t", Boundary: "b"})
	s.DB.Create(&db.Finding{ScanID: libScan.ID, RepositoryID: lib.ID, Title: "ods bomb", Severity: "Medium", CWE: "CWE-770", Status: db.FindingNew})
	s.DB.Create(&db.Finding{ScanID: libScan.ID, RepositoryID: lib.ID, Title: "old", Severity: sevHigh, Status: db.FindingFixed})

	// Self-published package on the app repo must not match its own findings.
	s.DB.Create(&db.Package{RepositoryID: app.ID, Name: "leftpad", Ecosystem: "npm"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: app.ID, Title: "self", Severity: sevHigh, Status: db.FindingNew})

	r := httptest.NewRequest("GET", "/api/repositories/"+strconv.FormatUint(uint64(app.ID), 10)+"/dependency-findings", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var rows []db.DependencyFinding
	if err := json.NewDecoder(w.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows=%d want=2 (live roo findings only): %+v", len(rows), rows)
	}
	if rows[0].Severity != sevHigh || rows[0].Package != "roo" {
		t.Errorf("first row should be the High roo finding, got %+v", rows[0])
	}
	if rows[0].Requirement != "2.10.1" {
		t.Errorf("lockfile requirement should win, got %q", rows[0].Requirement)
	}
	if rows[0].LibRepoURL != "https://example.com/roo" {
		t.Errorf("library_repository_url=%q", rows[0].LibRepoURL)
	}

	// Severity filter
	r = httptest.NewRequest("GET", "/api/repositories/"+strconv.FormatUint(uint64(app.ID), 10)+"/dependency-findings?severity=High", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	rows = nil
	_ = json.NewDecoder(w.Body).Decode(&rows)
	if len(rows) != 1 || rows[0].Title != "xlsx bomb" {
		t.Errorf("severity filter: %+v", rows)
	}
}

func TestAPIRunFindingSkill_scopesFindingID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	prior := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&prior)
	finding := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&finding)
	verify := db.Skill{Name: "verify", Description: "v", Body: "b", OutputFile: "report.json", OutputKind: "verify", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&verify)

	path := "/api/findings/" + strconv.FormatUint(uint64(finding.ID), 10) + "/skills/verify/run"
	r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var row db.Scan
	s.DB.Where("skill_id = ?", verify.ID).First(&row)
	if row.FindingID == nil || *row.FindingID != finding.ID {
		t.Errorf("enqueued scan has wrong finding_id: got=%v want=%d", row.FindingID, finding.ID)
	}
	if row.APIToken == "" {
		t.Error("enqueued scan missing api token")
	}
}

func TestAPIScansFilterBySkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "metadata"})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "packages"})

	r := httptest.NewRequest("GET",
		"/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/scans?skill=metadata", nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var rows []map[string]any
	_ = json.NewDecoder(w.Body).Decode(&rows)
	if len(rows) != 1 || rows[0]["skill_name"] != "metadata" {
		t.Errorf("filter by skill: %+v", rows)
	}
}

func replaceID(path string, id uint) string {
	return strings.ReplaceAll(path, "%d", strconv.FormatUint(uint64(id), 10))
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	}
	return ""
}
