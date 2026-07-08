package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestExpectedFindingsAPI(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	row := db.ExpectedFinding{RepositoryID: repo.ID, File: "src/app.go", CWE: "CWE-79", CVE: "CVE-2026-0001", Note: "known sink"}
	s.DB.Create(&row)

	req := httptest.NewRequest(http.MethodPost, "/api/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/expected",
		strings.NewReader(`{"file":"./src/app.go","cwe":"cwe-79","cve":"CVE-2026-0001","note":"known sink"}`))
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusCreated || w.Code == http.StatusOK || w.Code == http.StatusNoContent {
		t.Fatalf("scan-token POST unexpectedly succeeded: status %d", w.Code)
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
	if len(rows) != 1 || rows[0].ID != row.ID {
		t.Fatalf("rows = %+v", rows)
	}

	req = httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/repositories/%d/expected/%d", repo.ID, row.ID), nil)
	req.Host = testHost
	req.Header.Set("Authorization", "Bearer "+scan.APIToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusNoContent || w.Code == http.StatusOK {
		t.Fatalf("scan-token DELETE unexpectedly succeeded: status %d", w.Code)
	}
	var count int64
	s.DB.Model(&db.ExpectedFinding{}).Where("repository_id = ?", repo.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected findings count = %d, want unchanged row", count)
	}
}

func TestExpectedFindingForms(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/bench-form", Name: "bench-form"}
	s.DB.Create(&repo)

	form := url.Values{
		"file": {"./src/app.go"},
		"cwe":  {"cwe-79"},
		"cve":  {"CVE-2026-0001"},
		"note": {"known sink"},
	}
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/repositories/%d/expected", repo.ID), strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create status %d: %s", w.Code, w.Body)
	}
	var row db.ExpectedFinding
	if err := s.DB.Where("repository_id = ?", repo.ID).First(&row).Error; err != nil {
		t.Fatalf("expected finding was not created: %v", err)
	}
	if row.File != "src/app.go" || row.CWE != "CWE-79" {
		t.Fatalf("created row = %+v", row)
	}

	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/repositories/%d/expected/%d/delete", repo.ID, row.ID), nil)
	req.Host = testHost
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("delete status %d: %s", w.Code, w.Body)
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
	matched := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "xss", Severity: "High", CWE: "cwe-79", Location: "src/app.go:77:4"}
	unexpected := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "sqli", Severity: "Medium", CWE: "CWE-89", Location: "src/app.go:88"}
	s.DB.Create(&matched)
	s.DB.Create(&unexpected)

	got := expectedMatchesForScan(s.DB, repo.ID, scan.ID)
	if got.MatchedTotal != 1 || got.FindingTotal != 2 || got.TruePositiveFindings != 1 {
		t.Fatalf("matches = %+v", got)
	}
	if !got.FindingStatus[matched.ID] || got.FindingStatus[unexpected.ID] {
		t.Fatalf("finding status = %+v", got.FindingStatus)
	}
	if len(got.Expected) != 1 || !got.Expected[0].Matched || got.Expected[0].FindingID != matched.ID {
		t.Fatalf("expected status = %+v", got.Expected)
	}
}

func TestExpectedFindingPrecisionUsesTruePositiveFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/bench-precision", Name: "bench-precision"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "vuln-scan", Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/a.go", CWE: "CWE-79"})
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/b.go", CWE: "CWE-79"})
	finding := db.Finding{
		RepositoryID: repo.ID,
		ScanID:       scan.ID,
		Title:        "xss",
		Severity:     "High",
		CWE:          "CWE-79",
		Location:     "src/a.go:7",
		Locations:    "src/a.go:7\nsrc/b.go:9",
	}
	s.DB.Create(&finding)

	got := expectedMatchesForScan(s.DB, repo.ID, scan.ID)
	if got.MatchedTotal != 2 || got.FindingTotal != 1 || got.TruePositiveFindings != 1 {
		t.Fatalf("matches = %+v", got)
	}
	rows, totals := loadBenchmarkRows(s.DB, "vuln-scan", "", "")
	if len(rows) != 1 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Recall != 1 || rows[0].Precision != 1 || rows[0].F1 != 1 {
		t.Fatalf("row metrics = recall %.2f precision %.2f f1 %.2f", rows[0].Recall, rows[0].Precision, rows[0].F1)
	}
	if totals.Recall != 1 || totals.Precision != 1 || totals.F1 != 1 {
		t.Fatalf("totals = %+v", totals)
	}
}

func TestExpectedFindingMatchingIgnoresLowSeverityForBenchmarkTotals(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/bench-low", Name: "bench-low"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "vuln-scan", Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/app.go", CWE: "CWE-79"})
	low := db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "low xss", Severity: "Low", CWE: "CWE-79", Location: "src/app.go:77"}
	s.DB.Create(&low)

	got := expectedMatchesForScan(s.DB, repo.ID, scan.ID)
	if got.MatchedTotal != 0 || got.FindingTotal != 0 || got.TruePositiveFindings != 0 || got.FindingStatus[low.ID] {
		t.Fatalf("low severity finding affected benchmark totals/status: %+v", got)
	}
}

func TestBuildExpectedFindingRejectsNonRepoRelativePaths(t *testing.T) {
	bad := []string{"/etc/passwd", "../x.go", "src/../x.go", `src\..\x.go`}
	for _, file := range bad {
		if _, err := buildExpectedFinding(1, file, "CWE-79", "", ""); err == nil {
			t.Fatalf("buildExpectedFinding(%q) succeeded, want error", file)
		}
	}
	row, err := buildExpectedFinding(1, "./src/app.go", "cwe-79", "", "")
	if err != nil {
		t.Fatalf("valid expected finding rejected: %v", err)
	}
	if row.File != "src/app.go" || row.CWE != "CWE-79" {
		t.Fatalf("normalized row = %+v", row)
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
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/fixed.go", CWE: "CWE-22"})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "expected xss", Severity: "High", CWE: "CWE-79", Location: "src/app.go:7", Status: db.FindingNew})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "fixed path traversal", Severity: "High", CWE: "CWE-22", Location: "src/fixed.go:9", Status: db.FindingFixed})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "surprise sqli", Severity: "High", CWE: "CWE-89", Location: "src/db.go:9", Status: db.FindingNew})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"Benchmark", "2/2", "matched", "expected xss", "unexpected"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	fixedIdx := strings.Index(body, "fixed path traversal")
	if fixedIdx < 0 {
		t.Fatalf("body missing closed latest finding:\n%s", body)
	}
	fixedRow := body[fixedIdx:]
	if end := strings.Index(fixedRow, "</tr>"); end >= 0 {
		fixedRow = fixedRow[:end]
	}
	if !strings.Contains(fixedRow, "expected") || strings.Contains(fixedRow, "unexpected") {
		t.Fatalf("closed latest finding badge row = %s", fixedRow)
	}
}

func TestRepoShowBenchmarkTabUsesLatestVulnScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/bench-vuln", Name: "bench-vuln"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: vulnScanSkillName, Status: db.ScanDone, Model: "test-model"}
	s.DB.Create(&scan)
	s.DB.Create(&db.ExpectedFinding{RepositoryID: repo.ID, File: "src/app.go", CWE: "CWE-79"})
	s.DB.Create(&db.Finding{RepositoryID: repo.ID, ScanID: scan.ID, Title: "scanner xss", Severity: "High", CWE: "CWE-79", Location: "src/app.go:7", Status: db.FindingNew})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"Benchmark", "1/1", "scanner xss", "expected"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "missed") {
		t.Fatalf("vuln-scan-only expected row was marked missed:\n%s", body)
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
