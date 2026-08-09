package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
)

// A column missing from findingSummaryColumns serves a zero value instead.
func TestAPIListFindings_summaryColumnsCoverEveryField(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)

	checkedAt := time.Now().UTC().Truncate(time.Second)
	seeded := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "F1", Commit: "abcdef1", Sinks: "S1",
		Title: "OS command injection", Severity: "High", Status: db.FindingEnriched,
		CWE: "CWE-78", Location: "main.go:12", VID: "vid-1", Affected: ">=1.0,<1.4",
		Reachability: "reachable", QualityTier: "tier-1",
		CVEID: "CVE-2026-1", GHSAID: "GHSA-xxxx", CVSSVector: "CVSS:3.1/AV:N",
		CVSSScore: 9.8, FixVersion: "1.4.0", FixCommit: "abcd123",
		Resolution: db.ResolutionFix, Assignee: "alice", MissedCount: 3,
		DupCheck: "distinct from F2", Novelty: db.FindingNoveltyUnfixed,
		NoveltyCheckedCommit: "abcdef1", NoveltyCheckedAt: &checkedAt,
		// Prose the summary must not carry, and whose columns are excluded.
		Trace: "long trace", Snippet: "long snippet", SuggestedFix: "long diff",
	}
	if err := s.DB.Create(&seeded).Error; err != nil {
		t.Fatal(err)
	}

	w := apiReq(t, s, "GET", fmt.Sprintf("/api/repositories/%d/findings", repo.ID), scan.APIToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}

	// An unprojected row is the reference.
	var full db.Finding
	if err := s.DB.First(&full, seeded.ID).Error; err != nil {
		t.Fatal(err)
	}
	want := findingSummary(full)
	for key, wantVal := range want {
		wantJSON, _ := json.Marshal(wantVal)
		gotJSON, _ := json.Marshal(got[0][key])
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("%s = %s, want %s (missing from findingSummaryColumns?)", key, gotJSON, wantJSON)
		}
	}
}

// The summary omits the cached ecosyste.ms blobs but must still serve the rest.
func TestAPIGetRepository_omitsBlobsKeepsSummary(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	blob := strings.Repeat("x", 1<<16)
	if err := s.DB.Model(&repo).Updates(map[string]any{
		"full_name": "acme/thing", "default_branch": "main",
		"html_url": "https://github.com/acme/thing", "stars": 42, "forks": 7,
		"archived": true, "languages": "Go", "license": "MIT", "fork": "acme/staging",
		"posture": "ready", "posture_summary": "SECURITY.md present",
		"health":                   db.RepositoryHealthActive,
		"metadata":                 blob,
		"ecosystems_repo_data":     blob,
		"ecosystems_packages_data": blob,
	}).Error; err != nil {
		t.Fatal(err)
	}

	w := apiReq(t, s, "GET", fmt.Sprintf("/api/repositories/%d", repo.ID), scan.APIToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]any{
		"full_name": "acme/thing", "default_branch": "main",
		"html_url": "https://github.com/acme/thing", "stars": float64(42),
		"forks": float64(7), "archived": true, "languages": "Go", "license": "MIT",
		"fork": "acme/staging", "posture": "ready",
		"posture_summary": "SECURITY.md present", "health": "active",
	} {
		if got[key] != want {
			t.Errorf("%s = %v, want %v", key, got[key], want)
		}
	}
}

// scanSummary still reads diff_stats, coverage, and error past the projection.
func TestAPIListScans_omitsBlobsKeepsSummary(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)
	prior := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName, Commit: "abcdef1", Model: "fake",
		RescanMode: "diff", DiffBaseCommit: "0000001",
		DiffStats: `{"files":3}`, Coverage: `{"mode":"diff"}`, Error: "none",
		Log:    strings.Repeat("x", 1<<16),
		Report: `{"findings":[]}`,
	}
	if err := s.DB.Create(&prior).Error; err != nil {
		t.Fatal(err)
	}

	w := apiReq(t, s, "GET", fmt.Sprintf("/api/repositories/%d/scans?skill=%s", repo.ID, deepDiveSkillName),
		auth.APIToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d scans, want 1", len(got))
	}
	var full db.Scan
	if err := s.DB.First(&full, prior.ID).Error; err != nil {
		t.Fatal(err)
	}
	for key, wantVal := range scanSummary(full) {
		wantJSON, _ := json.Marshal(wantVal)
		gotJSON, _ := json.Marshal(got[0][key])
		if string(gotJSON) != string(wantJSON) {
			t.Errorf("%s = %s, want %s (omitted column scanSummary reads?)", key, gotJSON, wantJSON)
		}
	}
}

// apiGetScan does serve the report and log; the listing's projection must not
// have leaked into it.
func TestAPIGetScan_stillServesReportAndLog(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, auth := seedRunningScan(t, s)
	prior := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: deepDiveSkillName,
		Report:    `{"findings":[]}`, Log: "line one\nline two",
	}
	if err := s.DB.Create(&prior).Error; err != nil {
		t.Fatal(err)
	}

	w := apiReq(t, s, "GET", fmt.Sprintf("/api/scans/%d", prior.ID), auth.APIToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["report"] != `{"findings":[]}` || got["log"] != "line one\nline two" {
		t.Errorf("report = %v, log = %v", got["report"], got["log"])
	}
}

// apiAuth drops the blob columns but must keep the fields handlers read off the
// request context.
func TestAPIAuth_omitsBlobsKeepsIdentity(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, scan := seedRunningScan(t, s)
	if err := s.DB.Model(&scan).Updates(map[string]any{
		"log":        strings.Repeat("x", 1<<16),
		"prompt":     "prompt text",
		"report":     `{"findings":[]}`,
		"commit":     "abcdef1",
		"sub_path":   "packages/core",
		"skill_name": deepDiveSkillName,
	}).Error; err != nil {
		t.Fatal(err)
	}

	var seen *db.Scan
	probe := s.apiAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = scanFromRequest(r)
	}))
	r := localReq("GET", "/api/repositories/1")
	r.Header.Set("Authorization", "Bearer "+scan.APIToken)
	probe.ServeHTTP(httptest.NewRecorder(), r)

	if seen == nil {
		t.Fatal("no scan on context")
	}
	if seen.ID != scan.ID || seen.RepositoryID != repo.ID {
		t.Errorf("identity = scan %d repo %d, want scan %d repo %d",
			seen.ID, seen.RepositoryID, scan.ID, repo.ID)
	}
	// Fields the streamed-finding and validate-report paths stamp from context.
	if seen.Commit != "abcdef1" || seen.SubPath != "packages/core" || seen.SkillName != deepDiveSkillName {
		t.Errorf("identity fields dropped: commit=%q sub_path=%q skill_name=%q",
			seen.Commit, seen.SubPath, seen.SkillName)
	}
	if seen.Log != "" || seen.Prompt != "" || seen.Report != "" {
		t.Errorf("blob columns loaded: log=%d prompt=%d report=%d bytes",
			len(seen.Log), len(seen.Prompt), len(seen.Report))
	}
}
