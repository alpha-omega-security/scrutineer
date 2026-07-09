package web

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         worker.JobSkill,
		Status:       db.ScanRunning,
		Model:        "fake",
		APIToken:     "tok-" + strconv.FormatUint(uint64(repo.ID), 10),
		StartedAt:    new(time.Now()),
	}
	s.DB.Create(&scan)
	return repo, scan
}

func runSkillAPIJSON(t *testing.T, s *Server, repo db.Repository, scan db.Scan, skillName, body string) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/skills/" + skillName + "/run"
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestAPIListCNAs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, scan := seedRunningScan(t, s)

	s.DB.Create(&db.CNA{ShortName: "apache", Organization: "Apache Software Foundation",
		Scope: "All Apache Software Foundation projects", Email: "security@apache.org"})
	s.DB.Create(&db.CNA{ShortName: "curl", Organization: "curl", Scope: "curl and libcurl"})

	get := func(q string) []map[string]any {
		r := httptest.NewRequest("GET", "/api/cnas"+q, nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+scan.APIToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		var rows []map[string]any
		_ = json.NewDecoder(w.Body).Decode(&rows)
		return rows
	}

	all := get("")
	if len(all) != 2 {
		t.Fatalf("len = %d, want 2", len(all))
	}
	if all[0]["short_name"] != "apache" || all[0]["email"] != "security@apache.org" {
		t.Errorf("first row = %+v", all[0])
	}

	filtered := get("?q=libcurl")
	if len(filtered) != 1 || filtered[0]["short_name"] != "curl" {
		t.Errorf("scope filter: %+v", filtered)
	}
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

func TestAPIGetRepository_includesPostureFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	s.DB.Model(&repo).Updates(map[string]any{
		"posture":         "partial",
		"posture_summary": "SECURITY.md present, PVR disabled",
	})

	r := httptest.NewRequest("GET", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10), nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200. body=%s", w.Code, w.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["posture"] != "partial" {
		t.Errorf("posture = %v, want partial", body["posture"])
	}
	if body["posture_summary"] != "SECURITY.md present, PVR disabled" {
		t.Errorf("posture_summary = %v", body["posture_summary"])
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

func TestAPIPatchRepositoryFork(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	r := httptest.NewRequest("PATCH", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10),
		strings.NewReader(`{"fork":"fork-central/x"}`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.Fork != "fork-central/x" {
		t.Errorf("Fork = %q, want fork-central/x", got.Fork)
	}

	r = httptest.NewRequest("GET", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10), nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["fork"] != "fork-central/x" {
		t.Errorf("GET fork = %v", body["fork"])
	}
}

func TestAPIPatchRepositoryRejectsOtherRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, scan := seedRunningScan(t, s)
	other := db.Repository{URL: "https://example.com/y", Name: "y"}
	s.DB.Create(&other)

	r := httptest.NewRequest("PATCH", "/api/repositories/"+strconv.FormatUint(uint64(other.ID), 10),
		strings.NewReader(`{"fork":"fork-central/y"}`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("status %d, want 403", w.Code)
	}
}

func TestAPIPatchRepositoryRejectsEmptyBody(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	r := httptest.NewRequest("PATCH", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10),
		strings.NewReader(`{}`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 422 {
		t.Fatalf("status %d, want 422", w.Code)
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

func TestAPIRunSkill_profileOverridePersists(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	path := "/api/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/skills/metadata/run"
	r := httptest.NewRequest("POST", path, strings.NewReader(`{"profile":"php"}`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var row db.Scan
	s.DB.Where("skill_id = ?", skill.ID).First(&row)
	if row.Profile != "php" {
		t.Errorf("scan.Profile = %q, want %q", row.Profile, "php")
	}
}

func TestAPIRunSkill_diffRescanOptionsPersist(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)
	baseline := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: "metadata", Commit: "abc"}
	s.DB.Create(&baseline)

	body := fmt.Sprintf(`{"rescan_mode":"diff","baseline_scan_id":%d}`, baseline.ID)
	path := "/api/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/skills/metadata/run"
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var row db.Scan
	s.DB.Where("skill_id = ? AND status = ?", skill.ID, db.ScanQueued).First(&row)
	if row.RescanMode != db.ScanRescanModeDiff {
		t.Errorf("scan.RescanMode = %q, want diff", row.RescanMode)
	}
	if row.DiffBaseScanID == nil || *row.DiffBaseScanID != baseline.ID {
		t.Errorf("scan.DiffBaseScanID = %v, want %d", row.DiffBaseScanID, baseline.ID)
	}
}

func TestAPIRunSkill_rejectsInvalidRescanMode(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	w := runSkillAPIJSON(t, s, repo, scan, "metadata", `{"rescan_mode":"delta"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400. body=%s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&count)
	if count != 0 {
		t.Errorf("invalid rescan mode still created %d scans, want 0", count)
	}
}

func TestAPIRunSkill_rejectsMalformedJSON(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	w := runSkillAPIJSON(t, s, repo, scan, "metadata", `{"profile":`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400. body=%s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&count)
	if count != 0 {
		t.Errorf("malformed request still created %d scans, want 0", count)
	}
}

func TestAPIRunSkill_emptyBodyStillEnqueues(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	path := "/api/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/skills/metadata/run"
	r := httptest.NewRequest("POST", path, nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201. body=%s", w.Code, w.Body)
	}
	var row db.Scan
	if err := s.DB.Where("skill_id = ?", skill.ID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Ref != "" || row.Profile != "" {
		t.Errorf("empty-body scan options = ref:%q profile:%q, want zero values", row.Ref, row.Profile)
	}
}

func TestAPIRunSkill_unknownProfileRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	path := "/api/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/skills/metadata/run"
	r := httptest.NewRequest("POST", path, strings.NewReader(`{"profile":"bogus"}`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status %d, want 400. body=%s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&count)
	if count != 0 {
		t.Errorf("rejected enqueue still created %d scans", count)
	}
}

func TestAPIRunSkill_profileMismatchRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "php-only", Description: "m", Body: "b", OutputFile: "report.json",
		Version: 1, Active: true, Source: "ui", RequiresProfile: "php"}
	s.DB.Create(&skill)

	path := "/api/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/skills/php-only/run"
	r := httptest.NewRequest("POST", path, strings.NewReader(`{"profile":"default"}`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status %d, want 400. body=%s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&count)
	if count != 0 {
		t.Errorf("rejected enqueue still created %d scans", count)
	}
}

func TestAPIRunSkill_badRefRejectedAt400(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	path := "/api/repositories/" + strconv.FormatUint(uint64(repo.ID), 10) + "/skills/metadata/run"
	r := httptest.NewRequest("POST", path, strings.NewReader(`{"ref":"--upload-pack=/bin/sh"}`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status %d, want 400. body=%s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "invalid git ref") {
		t.Errorf("response body should name the failure, got %s", w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", skill.ID).Count(&count)
	if count != 0 {
		t.Errorf("rejected enqueue still created %d scans, want 0", count)
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

func TestAPIRunFindingSkill_rejectsMalformedJSON(t *testing.T) {
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
	r := httptest.NewRequest("POST", path, strings.NewReader(`{"model":`))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400. body=%s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.Scan{}).Where("skill_id = ?", verify.ID).Count(&count)
	if count != 0 {
		t.Errorf("malformed request still created %d scans, want 0", count)
	}
}

func TestAPIRunFindingSkill_emptyBodyStillEnqueues(t *testing.T) {
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
	r := httptest.NewRequest("POST", path, nil)
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201. body=%s", w.Code, w.Body)
	}
	var row db.Scan
	if err := s.DB.Where("skill_id = ?", verify.ID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.FindingID == nil || *row.FindingID != finding.ID {
		t.Errorf("enqueued scan has wrong finding_id: got=%v want=%d", row.FindingID, finding.ID)
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

func TestAPIAuth_capsRequestBody(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	body := `{"fork":"` + strings.Repeat("x", apiMaxBody) + `"}`
	r := httptest.NewRequest("PATCH", "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10), strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusNoContent {
		t.Fatalf("oversized body accepted: status %d", w.Code)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400 (decode fails on capped body)", w.Code)
	}
}

// seedScanWithSkill creates a repo + skill (with the given schema) + running
// scan whose APIToken authenticates and whose SkillID points at the skill, so
// validate-report calls resolve a schema to check against.
func seedScanWithSkill(t *testing.T, s *Server, schema string) db.Scan {
	t.Helper()
	repo := db.Repository{URL: "https://example.com/vr", Name: "vr"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "threat-model", Description: "t", Body: "b", OutputFile: "report.json",
		SchemaJSON: schema, Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)
	now := time.Now()
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         worker.JobSkill,
		Status:       db.ScanRunning,
		SkillID:      &skill.ID,
		SkillName:    skill.Name,
		APIToken:     "tok-vr",
		StartedAt:    &now,
	}
	s.DB.Create(&scan)
	return scan
}

const validateTestSchema = `{
  "type": "object",
  "required": ["tier"],
  "properties": {"tier": {"type": "string"}}
}`

func postValidate(t *testing.T, s *Server, scanID uint, token, body string) (int, map[string]any) {
	t.Helper()
	path := "/api/scans/" + strconv.FormatUint(uint64(scanID), 10) + "/validate-report"
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Host = testHost
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var out map[string]any
	_ = json.NewDecoder(w.Body).Decode(&out)
	return w.Code, out
}

func TestAPIValidateReport_valid(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scan := seedScanWithSkill(t, s, validateTestSchema)

	code, out := postValidate(t, s, scan.ID, scan.APIToken, `{"tier":"ready"}`)
	if code != 200 {
		t.Fatalf("status %d, want 200", code)
	}
	if out["valid"] != true {
		t.Errorf("response = %+v, want valid:true", out)
	}
}

func TestAPIValidateReport_invalidMatchesValidator(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scan := seedScanWithSkill(t, s, validateTestSchema)

	const report = `{"tier":42}`
	code, out := postValidate(t, s, scan.ID, scan.APIToken, report)
	if code != 200 {
		t.Fatalf("status %d, want 200", code)
	}
	if out["valid"] != false {
		t.Fatalf("response = %+v, want valid:false", out)
	}
	want := worker.ValidateReportSchema(validateTestSchema, report)
	if want == "" {
		t.Fatal("expected the validator to reject the report")
	}
	if got, _ := out["errors"].(string); got != want {
		t.Errorf("errors = %q, want %q (must match the harness validator)", got, want)
	}
}

func TestAPIValidateReport_crossScanForbidden(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scan := seedScanWithSkill(t, s, validateTestSchema)

	// A different running scan with its own token must not validate against
	// scan's ID using its own credentials.
	now := time.Now()
	other := db.Scan{RepositoryID: scan.RepositoryID, Kind: worker.JobSkill, Status: db.ScanRunning,
		SkillID: scan.SkillID, APIToken: "tok-other", StartedAt: &now}
	s.DB.Create(&other)

	code, out := postValidate(t, s, scan.ID, other.APIToken, `{"tier":"ready"}`)
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403. body=%+v", code, out)
	}
}

func TestAPIValidateReport_noSchema(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scan := seedScanWithSkill(t, s, "")

	code, out := postValidate(t, s, scan.ID, scan.APIToken, `{"anything":true}`)
	if code != 200 {
		t.Fatalf("status %d, want 200", code)
	}
	if out["valid"] != true || out["note"] != "skill has no schema" {
		t.Errorf("response = %+v, want valid:true with no-schema note", out)
	}
}

func TestAPIValidateReport_noSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, scan := seedRunningScan(t, s) // SkillID is nil

	code, out := postValidate(t, s, scan.ID, scan.APIToken, `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400. body=%+v", code, out)
	}
}

func TestAPIValidateReport_oversizedBodyRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	scan := seedScanWithSkill(t, s, validateTestSchema)

	// apiAuth caps every request body at apiMaxBody; a larger report is
	// rejected rather than silently truncated.
	body := `{"tier":"` + strings.Repeat("x", apiMaxBody) + `"}`
	code, _ := postValidate(t, s, scan.ID, scan.APIToken, body)
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", code)
	}
}
