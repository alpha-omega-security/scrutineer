package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestExpectedFindingsAPI(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	req := httptest.NewRequest(http.MethodPost, "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/expected",
		strings.NewReader(`{"file":"./src/app.go","cwe":"cwe-79","cve":"CVE-2026-0001","note":"known sink"}`))
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST status %d: %s", w.Code, w.Body)
	}
	var created expectedFindingResponse
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.File != "src/app.go" || created.CWE != "CWE-79" {
		t.Fatalf("created = %+v", created)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/expected", nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status %d: %s", w.Code, w.Body)
	}
	var rows []expectedFindingResponse
	if err := json.NewDecoder(w.Body).Decode(&rows); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != created.ID {
		t.Fatalf("rows = %+v", rows)
	}

	req = httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/repositories/%d/expected/%d", repo.ID, created.ID), nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE status %d: %s", w.Code, w.Body)
	}
	var count int64
	s.DB.Model(&db.ExpectedFinding{}).Where("repository_id = ?", repo.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected findings count = %d, want 0", count)
	}
}

func TestExpectedFindingMatchingIgnoresLineNumbers(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/bench", Name: "bench"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "vuln-scan", Status: db.ScanDone}
	s.DB.Create(&scan)
	expected := db.ExpectedFinding{RepositoryID: repo.ID, File: "src/app.go", CWE: "CWE-79"}
	s.DB.Create(&expected)
	matched := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "xss", Severity: "High", CWE: "CWE-79", Location: "src/app.go:77:4"}
	unexpected := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "sqli", Severity: "Medium", CWE: "CWE-89", Location: "src/app.go:88"}
	s.DB.Create(&matched)
	s.DB.Create(&unexpected)

	got := expectedMatchesForScan(s.DB, repo.ID, scan.ID)
	if got.MatchedTotal != 1 || got.FindingTotal != 2 {
		t.Fatalf("matches = %+v", got)
	}
	if !got.FindingStatus[matched.ID] || got.FindingStatus[unexpected.ID] {
		t.Fatalf("finding status = %+v", got.FindingStatus)
	}
	if len(got.Expected) != 1 || !got.Expected[0].Matched || got.Expected[0].FindingID != matched.ID {
		t.Fatalf("expected status = %+v", got.Expected)
	}
}

func TestRepoShowExpectedFindingBadges(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/bench-ui", Name: "bench-ui"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: deepDiveSkillName, Status: db.ScanDone, Model: "test-model"}
	s.DB.Create(&scan)
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/app.go", CWE: "CWE-79"})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "expected xss", Severity: "High", CWE: "CWE-79", Location: "src/app.go:7", Status: db.FindingNew})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "surprise sqli", Severity: "High", CWE: "CWE-89", Location: "src/db.go:9", Status: db.FindingNew})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"Benchmark", "1/1", "matched", "expected xss", "unexpected"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
}

func TestBenchmarkPageRollupUsesLatestCompletedScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/bench-rollup", Name: "bench-rollup"}
	s.DB.Create(&repo)
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/a.go", CWE: "CWE-79"})
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/b.go", CWE: "CWE-89"})
	oldScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "vuln-scan", Status: db.ScanDone, Model: "old"}
	s.DB.Create(&oldScan)
	newScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "vuln-scan", Status: db.ScanDone, Model: "claude-test", SkillsRepoSHA: "abc123456789", SkillSchemaVersion: 1}
	s.DB.Create(&newScan)
	metadataScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "metadata", Status: db.ScanDone, Model: "claude-test"}
	s.DB.Create(&metadataScan)
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: oldScan.ID, Title: "old", Severity: "High", CWE: "CWE-89", Location: "src/b.go:1"})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: newScan.ID, Title: "xss", Severity: "High", CWE: "CWE-79", Location: "src/a.go:1"})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: newScan.ID, Title: "extra", Severity: "Medium", CWE: "CWE-22", Location: "src/c.go:1"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/benchmark?skill=vuln-scan"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"bench-rollup", "50%", "1 / 2", "claude-test", "v1", "abc123456789"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/benchmark"))
	if w.Code != http.StatusOK {
		t.Fatalf("default status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), fmt.Sprintf("/scans/%d", metadataScan.ID)) {
		t.Fatalf("default benchmark selected metadata scan:\n%s", w.Body)
	}
}
