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
