package web

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestParseLimit(t *testing.T) {
	tests := []struct {
		query   string
		want    int
		wantErr bool
	}{
		{"", 200, false},
		{"?limit=25", 25, false},
		{"?limit=1001", 1000, false},
		{"?limit=0", 0, false},
		{"?limit=", 0, true},
		{"?limit", 0, true},
		{"?limit=-1", 0, true},
		{"?limit=nope", 0, true},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/api/repositories/1/dependencies"+tc.query, nil)
		got, err := parseLimit(r, 200, 1000)
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: error = %v, wantErr %v", tc.query, err, tc.wantErr)
		}
		if got != tc.want {
			t.Errorf("%q: limit = %d, want %d", tc.query, got, tc.want)
		}
	}
}

func TestAPIListDependents_limit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	rows := make([]db.Dependent, 0, 201)
	for i := range 201 {
		rows = append(rows, db.Dependent{
			RepositoryID:   repo.ID,
			Name:           fmt.Sprintf("dependent-%03d", i),
			DependentRepos: i,
		})
	}
	if err := s.DB.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}

	get := func(query string) []dependentResponse {
		t.Helper()
		path := fmt.Sprintf("/api/repositories/%d/dependents%s", repo.ID, query)
		w := apiReq(t, s, "GET", path, scan.APIToken, "")
		if w.Code != 200 {
			t.Fatalf("%s: status = %d, want 200; body=%s", query, w.Code, w.Body)
		}
		var got []dependentResponse
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	got := get("")
	if len(got) != 200 {
		t.Fatalf("default dependents = %d, want 200", len(got))
	}
	if got[0].Name != "dependent-200" || got[199].Name != "dependent-001" {
		t.Errorf("default dependents range = %q..%q, want dependent-200..dependent-001", got[0].Name, got[199].Name)
	}

	got = get("?limit=2")
	if len(got) != 2 {
		t.Fatalf("dependents = %d, want 2", len(got))
	}
	if got[0].Name != "dependent-200" || got[1].Name != "dependent-199" {
		t.Errorf("dependents = %+v, want dependent-200 then dependent-199", got)
	}

	path := fmt.Sprintf("/api/repositories/%d/dependents?limit=", repo.ID)
	w := apiReq(t, s, "GET", path, scan.APIToken, "")
	if w.Code != 400 {
		t.Errorf("empty limit status = %d, want 400; body=%s", w.Code, w.Body)
	}
}

func TestAPIListDependencies_limit(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	rows := make([]db.Dependency, 0, 201)
	for i := range 201 {
		rows = append(rows, db.Dependency{
			RepositoryID: repo.ID,
			Name:         fmt.Sprintf("dependency-%03d", i),
			Ecosystem:    "npm",
		})
	}
	if err := s.DB.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}

	get := func(query string) []dependencyResponse {
		t.Helper()
		path := fmt.Sprintf("/api/repositories/%d/dependencies%s", repo.ID, query)
		w := apiReq(t, s, "GET", path, scan.APIToken, "")
		if w.Code != 200 {
			t.Fatalf("%s: status = %d, want 200; body=%s", query, w.Code, w.Body)
		}
		var got []dependencyResponse
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}

	got := get("")
	if len(got) != 200 {
		t.Fatalf("default dependencies = %d, want 200", len(got))
	}
	if got[0].Name != "dependency-000" || got[199].Name != "dependency-199" {
		t.Errorf("default dependencies range = %q..%q, want dependency-000..dependency-199", got[0].Name, got[199].Name)
	}

	got = get("?limit=2")
	if len(got) != 2 {
		t.Fatalf("dependencies = %d, want 2", len(got))
	}
	if got[0].Name != "dependency-000" || got[1].Name != "dependency-001" {
		t.Errorf("dependencies = %+v, want dependency-000 then dependency-001", got)
	}

	path := fmt.Sprintf("/api/repositories/%d/dependencies?limit=", repo.ID)
	w := apiReq(t, s, "GET", path, scan.APIToken, "")
	if w.Code != 400 {
		t.Errorf("empty limit status = %d, want 400; body=%s", w.Code, w.Body)
	}
}

func TestAPIListFindings_filtersBySkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)

	mkScan := func(skillName string) db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone, SkillName: skillName}
		s.DB.Create(&sc)
		return sc
	}
	semgrep := mkScan("semgrep")
	deepDive := mkScan("security-deep-dive")

	s.DB.Create(&db.Finding{ScanID: semgrep.ID, RepositoryID: repo.ID, Title: "sg1",
		Severity: "Medium", CWE: "CWE-79", Location: "a.rb:1"})
	s.DB.Create(&db.Finding{ScanID: semgrep.ID, RepositoryID: repo.ID, Title: "sg2",
		Severity: "High", CWE: "CWE-89", Location: "b.rb:1"})
	s.DB.Create(&db.Finding{ScanID: deepDive.ID, RepositoryID: repo.ID, Title: "dd1",
		Severity: "High", CWE: "CWE-22", Location: "c.rb:1"})

	get := func(q string) []map[string]any {
		r := httptest.NewRequest("GET", fmt.Sprintf("/api/repositories/%d/findings%s", repo.ID, q), nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+auth.APIToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", q, w.Code, w.Body)
		}
		var rows []map[string]any
		_ = json.NewDecoder(w.Body).Decode(&rows)
		return rows
	}

	if got := get(""); len(got) != 3 {
		t.Errorf("no filter: %d findings, want 3", len(got))
	}
	sg := get("?skill=semgrep")
	if len(sg) != 2 {
		t.Fatalf("?skill=semgrep: %d findings, want 2", len(sg))
	}
	for _, f := range sg {
		if f["title"] != "sg1" && f["title"] != "sg2" {
			t.Errorf("?skill=semgrep returned %v", f["title"])
		}
	}
	if got := get("?skill=security-deep-dive"); len(got) != 1 || got[0]["title"] != "dd1" {
		t.Errorf("?skill=security-deep-dive: got %v", got)
	}
	if got := get("?skill=nonexistent"); len(got) != 0 {
		t.Errorf("?skill=nonexistent: %d findings, want 0", len(got))
	}
	if got := get("?skill=semgrep&severity=High"); len(got) != 1 || got[0]["title"] != "sg2" {
		t.Errorf("?skill=semgrep&severity=High: got %v", got)
	}
}

func TestAPIListFindings_filtersByScanGroup(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)

	mk := func(group string) db.Scan {
		sc := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone,
			SkillName: "security-deep-dive", ScanGroup: group}
		s.DB.Create(&sc)
		return sc
	}
	g1 := mk("group-1")
	g2 := mk("group-2")

	s.DB.Create(&db.Finding{ScanID: g1.ID, RepositoryID: repo.ID, Title: "a",
		Severity: "High", Location: "a.go:1", DupCheck: "distinct from siblings"})
	s.DB.Create(&db.Finding{ScanID: g2.ID, RepositoryID: repo.ID, Title: "b",
		Severity: "High", Location: "b.go:1"})

	get := func(q string) []map[string]any {
		r := httptest.NewRequest("GET", fmt.Sprintf("/api/repositories/%d/findings%s", repo.ID, q), nil)
		r.Host = testHost
		r.Header.Set("Authorization", "Bearer "+auth.APIToken)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: status %d: %s", q, w.Code, w.Body)
		}
		var rows []map[string]any
		_ = json.NewDecoder(w.Body).Decode(&rows)
		return rows
	}

	if got := get(""); len(got) != 2 {
		t.Errorf("no filter: %d findings, want 2", len(got))
	}
	one := get("?scan_group=group-1")
	if len(one) != 1 || one[0]["title"] != "a" {
		t.Fatalf("?scan_group=group-1: got %v, want [a]", one)
	}
	if one[0]["dup_check"] != "distinct from siblings" {
		t.Errorf("dup_check = %v, want the emitted sentence", one[0]["dup_check"])
	}
	if got := get("?scan_group=nope"); len(got) != 0 {
		t.Errorf("?scan_group=nope: %d findings, want 0", len(got))
	}
}
