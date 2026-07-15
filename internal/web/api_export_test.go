package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"

	"scrutineer/internal/db"
)

const sevHigh = "High"

func seedFindings(t *testing.T, s *Server) db.Repository {
	t.Helper()
	repoA := db.Repository{URL: "https://example.com/a", Name: "a"}
	repoB := db.Repository{URL: "https://example.com/b", Name: "b"}
	s.DB.Create(&repoA)
	s.DB.Create(&repoB)

	scanA := db.Scan{RepositoryID: repoA.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	scanB := db.Scan{RepositoryID: repoB.ID, Kind: "skill", Status: db.ScanDone, SkillName: "metadata-fetch"}
	s.DB.Create(&scanA)
	s.DB.Create(&scanB)

	s.DB.Create(&db.Finding{ScanID: scanA.ID, RepositoryID: repoA.ID, Title: "F1", Severity: sevHigh, Status: db.FindingTriaged})
	s.DB.Create(&db.Finding{ScanID: scanA.ID, RepositoryID: repoA.ID, Title: "F2", Severity: "Low", Status: db.FindingNew})
	s.DB.Create(&db.Finding{ScanID: scanB.ID, RepositoryID: repoB.ID, Title: "G1", Severity: sevHigh, Status: db.FindingNew})
	return repoA
}

func readJSONL(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("invalid JSONL line %q: %v", string(line), err)
		}
		out = append(out, m)
	}
	return out
}

func TestExportRepoFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoA := seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repoA.ID), 10)+"/findings?format=jsonl", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d, want 200. body=%s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-ndjson; charset=utf-8" {
		t.Errorf("content-type %q, want application/x-ndjson", ct)
	}
	rows := readJSONL(t, w.Body.String())
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	for _, row := range rows {
		if row["repository_id"] != float64(repoA.ID) {
			t.Errorf("row has repository_id %v, want %d", row["repository_id"], repoA.ID)
		}
		for _, k := range []string{"missed_count", "last_missed_scan_id"} {
			if _, ok := row[k]; !ok {
				t.Errorf("export row missing %q", k)
			}
		}
	}
}

func TestStreamJSONLRowsErrorReturns500(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	streamJSONL[db.Finding](w, s.DB.Raw("SELECT * FROM missing_export_table"), findingExport)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500. body=%s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type %q, want JSON API error", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body[errorKey] == "" {
		t.Fatalf("error response missing %q: %+v", errorKey, body)
	}
}

func TestExportRepoFindings_severityFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoA := seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repoA.ID), 10)+"/findings?severity=High", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0]["severity"] != sevHigh {
		t.Errorf("severity %v, want High", rows[0]["severity"])
	}
}

func TestExportRepoFindings_unknownRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := httptest.NewRequest("GET", "/api/v1/repositories/9999/findings", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 404 {
		t.Fatalf("status %d, want 404", w.Code)
	}
}

func TestExportFindings_acrossRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/findings?format=jsonl", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
}

func TestExportFindings_filters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)

	cases := []struct {
		name string
		qs   string
		want int
	}{
		{"severity High", "severity=High", 2},
		{"status new", "status=new", 2},
		{"severity Low", "severity=Low", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/api/v1/findings?"+tc.qs, nil)
			r.Host = testHost
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			rows := readJSONL(t, w.Body.String())
			if len(rows) != tc.want {
				t.Fatalf("%s: got %d rows, want %d. body=%s", tc.name, len(rows), tc.want, w.Body)
			}
		})
	}
}

func TestExportFindings_emptyDB(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := httptest.NewRequest("GET", "/api/v1/findings", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body should be empty, got %q", w.Body.String())
	}
}

func TestExportRepositories(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{
		URL:                    "https://github.com/example/repo",
		Name:                   "repo",
		FullName:               "example/repo",
		Owner:                  "example",
		Languages:              "Go, JavaScript",
		Stars:                  42,
		Metadata:               "large metadata blob",
		EcosystemsRepoData:     "large repo ecosystem blob",
		EcosystemsPackagesData: "large package ecosystem blob",
		ThreatModel:            "large threat model blob",
	}
	s.DB.Create(&repo)
	deep := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "abc123"}
	s.DB.Create(&deep)
	s.DB.Create(&db.Finding{ScanID: deep.ID, RepositoryID: repo.ID, Title: "SSRF", Severity: sevHigh, Status: db.FindingNew})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning, SkillName: "repo-overview", Commit: "def456"})

	r := httptest.NewRequest("GET", "/api/v1/repositories", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200. body=%s", w.Code, w.Body)
	}

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]
	for _, k := range []string{"id", "url", "name", "full_name", "owner", "languages", "stars", "findings_count", "last_scan"} {
		if _, ok := row[k]; !ok {
			t.Errorf("repository export missing %q", k)
		}
	}
	if row["findings_count"] != float64(1) {
		t.Errorf("findings_count = %v, want 1", row["findings_count"])
	}
	last, ok := row["last_scan"].(map[string]any)
	if !ok {
		t.Fatalf("last_scan = %#v, want object", row["last_scan"])
	}
	if last["status"] != string(db.ScanRunning) || last["skill_name"] != "repo-overview" || last["commit"] != "def456" {
		t.Errorf("last_scan = %#v", last)
	}
	for _, k := range []string{"metadata", "ecosystems_repo_data", "ecosystems_packages_data", "threat_model"} {
		if _, ok := row[k]; ok {
			t.Errorf("repository export should not include large column %q", k)
		}
	}
	if got := w.Body.String(); strings.Contains(got, "large metadata blob") || strings.Contains(got, "large repo ecosystem blob") {
		t.Errorf("repository export leaked large blob data: %s", got)
	}
}

func TestExportRepositories_noScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{
		URL:      "https://github.com/example/unscanned",
		Name:     "unscanned",
		FullName: "example/unscanned",
		Owner:    "example",
	}
	s.DB.Create(&repo)

	r := httptest.NewRequest("GET", "/api/v1/repositories", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d, want 200. body=%s", w.Code, w.Body)
	}

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0]["last_scan"] != nil {
		t.Fatalf("last_scan = %#v, want nil", rows[0]["last_scan"])
	}
	if rows[0]["findings_count"] != float64(0) {
		t.Errorf("findings_count = %v, want 0", rows[0]["findings_count"])
	}
}

func TestExportScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
}

func TestExportScans_skillFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/scans?skill=metadata-fetch", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0]["skill_name"] != "metadata-fetch" {
		t.Errorf("skill_name %v, want metadata-fetch", rows[0]["skill_name"])
	}
}

func TestExportRejectsBadHost(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := httptest.NewRequest("GET", "/api/v1/findings", nil)
	r.Host = "evil.example:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 403 {
		t.Fatalf("status %d, want 403", w.Code)
	}
}

func TestExportNoBearerNeeded(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/findings", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d, want 200", w.Code)
	}
}

func TestExportScans_statusFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoA := seedFindings(t, s)
	s.DB.Create(&db.Scan{RepositoryID: repoA.ID, Kind: "skill", Status: db.ScanQueued, SkillName: "queued-one"})

	r := httptest.NewRequest("GET", "/api/v1/scans?status=done", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (only done scans)", len(rows))
	}
	for _, row := range rows {
		if row["status"] != "done" {
			t.Errorf("status %v, want done", row["status"])
		}
	}
}

func TestExportRejectsUnknownFormat(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	for _, path := range []string{"/api/v1/repositories", "/api/v1/findings", "/api/v1/scans", "/api/v1/repositories/1/findings"} {
		r := httptest.NewRequest("GET", path+"?format=csv", nil)
		r.Host = testHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Errorf("%s: status %d, want 400", path, w.Code)
		}
	}
}

func TestExportRepoFindingsBundle(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoA := seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repoA.ID), 10)+"/findings?format=bundle", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d, want 200. body=%s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type %q, want application/json", ct)
	}

	var bundle struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
		Tool       string `json:"tool"`
		Findings   []struct {
			Title    string `json:"title"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	if bundle.Repository != repoA.URL {
		t.Errorf("repository %q, want %q", bundle.Repository, repoA.URL)
	}
	if bundle.Tool != "scrutineer" {
		t.Errorf("tool %q, want scrutineer", bundle.Tool)
	}
	if len(bundle.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(bundle.Findings))
	}
}

func initGitRepoWithOrigin(t *testing.T, origin string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet")
	if origin != "" {
		run("remote", "add", "origin", origin)
	}
	return dir
}

func TestExportRepoFindingsBundle_localCheckoutUsesHTTPSOrigin(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	dir := initGitRepoWithOrigin(t, "https://github.com/ruby/racc.git")
	repo := db.Repository{URL: LocalScheme + dir, Name: "racc"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "abc123"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		Title: "local finding", Severity: sevHigh})

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+
		strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var bundle sharingBundle
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Repository != "https://github.com/ruby/racc" {
		t.Errorf("repository = %q, want portable HTTPS origin", bundle.Repository)
	}

	// Importing the bundle must create a remote row. The worker's normal
	// remote-source path will clone it when verify (or any skill) first runs.
	importReq := httptest.NewRequest("POST", "/api/v1/import?revalidate=false",
		strings.NewReader(w.Body.String()))
	importReq.Host = testHost
	importW := httptest.NewRecorder()
	s.Handler().ServeHTTP(importW, importReq)
	if importW.Code != http.StatusCreated {
		t.Fatalf("import status %d: %s", importW.Code, importW.Body)
	}
	var imported db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/ruby/racc").First(&imported).Error; err != nil {
		t.Fatalf("portable repository not created: %v", err)
	}
	if imported.IsLocal() {
		t.Error("imported repository is local; verification would not clone it")
	}
}

func TestBundleRepositoryURL_localCheckoutWithoutPortableOriginFallsBack(t *testing.T) {
	dir := initGitRepoWithOrigin(t, "")
	repo := db.Repository{URL: LocalScheme + dir, Name: "local"}
	if got := bundleRepositoryURL(context.Background(), &repo); got != repo.URL {
		t.Errorf("bundleRepositoryURL = %q, want local fallback %q", got, repo.URL)
	}
}

func TestExportRepoFindingsBundle_credentialedOriginDoesNotLeak(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	const secret = "ghp_SECRET"
	dir := initGitRepoWithOrigin(t, "https://x-access-token:"+secret+"@github.com/o/r.git")
	repo := db.Repository{URL: LocalScheme + dir, Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: "security-deep-dive", Commit: "abc123"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		Title: "credential guard", Severity: sevHigh})

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+
		strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "x-access-token") {
		t.Fatalf("credentialed origin leaked into bundle: %s", w.Body)
	}
	var bundle sharingBundle
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Repository != repo.URL {
		t.Errorf("repository = %q, want safe fallback %q", bundle.Repository, repo.URL)
	}
}

func TestPortableGitOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		want   string
		ok     bool
	}{
		{name: "https", origin: "https://github.com/Ruby/Racc.git", want: "https://github.com/ruby/racc", ok: true},
		{name: "scp ssh", origin: "git@github.com:Ruby/Racc.git", want: "https://github.com/ruby/racc", ok: true},
		{name: "ssh URL", origin: "ssh://git@codeberg.org/Owner/Repo.git", want: "https://codeberg.org/owner/repo", ok: true},
		{name: "ssh URL port 22", origin: "ssh://git@gitlab.com:22/Owner/Repo.git", want: "https://gitlab.com/owner/repo", ok: true},
		{name: "credentialed https", origin: "https://token:secret@github.com/o/r.git"},
		{name: "unknown ssh forge", origin: "git@git.example.com:o/r.git"},
		{name: "nonstandard ssh port", origin: "ssh://git@github.com:2222/o/r.git"},
		{name: "git protocol", origin: "git://github.com/o/r.git"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := portableGitOrigin(tc.origin)
			if got != tc.want || ok != tc.ok {
				t.Errorf("portableGitOrigin(%q) = (%q, %v), want (%q, %v)",
					tc.origin, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestExportBundleRoundTrip(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// Seed a repo with a rich finding.
	repo := db.Repository{URL: "https://github.com/test/roundtrip", Name: "roundtrip"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive", Commit: "aaa111"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: "aaa111",
		Title: "SQL Injection in login", Severity: sevHigh, Confidence: "high",
		CWE: "CWE-89", Location: "auth/login.go:42",
		Trace: "Unsanitised user input reaches the query builder.",
	})

	// Export as bundle.
	exportReq := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle", nil)
	exportReq.Host = testHost
	exportW := httptest.NewRecorder()
	s.Handler().ServeHTTP(exportW, exportReq)
	if exportW.Code != 200 {
		t.Fatalf("export status %d: %s", exportW.Code, exportW.Body)
	}

	// Import the bundle into a fresh DB context (same server is fine;
	// the import path creates a new repo row because the URL will
	// match the existing one and deduplicate via FirstOrCreate).
	importReq := httptest.NewRequest("POST", "/api/v1/import", strings.NewReader(exportW.Body.String()))
	importReq.Host = testHost
	importW := httptest.NewRecorder()
	s.Handler().ServeHTTP(importW, importReq)
	if importW.Code != 201 {
		t.Fatalf("import status %d: %s", importW.Code, importW.Body)
	}

	var resp struct {
		Format  string `json:"format"`
		Results []struct {
			Created    int    `json:"created"`
			Repository string `json:"repository"`
		} `json:"results"`
	}
	if err := json.Unmarshal(importW.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal import response: %v", err)
	}
	if resp.Format != "minimal" {
		t.Errorf("import format %q, want minimal", resp.Format)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(resp.Results))
	}
	// The original finding already existed with the same fingerprint,
	// so re-import observes it rather than creating a duplicate.
	// A truly fresh import (different repo) would show created=1.
}

func TestExportBundleWithSeverityFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repoA := seedFindings(t, s)

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repoA.ID), 10)+"/findings?format=bundle&severity=High", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	var bundle struct {
		Findings []struct{ Severity string } `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(bundle.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 (High only)", len(bundle.Findings))
	}
	if bundle.Findings[0].Severity != sevHigh {
		t.Errorf("severity %q, want High", bundle.Findings[0].Severity)
	}
}

func TestExportBundleRejectsGlobalEndpoint(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)

	// format=bundle is only valid on the per-repo endpoint.
	r := httptest.NewRequest("GET", "/api/v1/findings?format=bundle", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 400 {
		t.Fatalf("status %d, want 400 (bundle not valid on global endpoint)", w.Code)
	}
}

func TestExportBundleEncryptedRoundTrip(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// Generate two recipients; both should be able to decrypt.
	id1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s.EncRecipients = []age.Recipient{id1.Recipient(), id2.Recipient()}
	s.EncIdentities = []age.Identity{id1, id2}

	repo := db.Repository{URL: "https://github.com/test/encrypted", Name: "encrypted"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive", Commit: "bbb222"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: "bbb222",
		Title: "XSS in template", Severity: sevHigh, CWE: "CWE-79",
		Location: "web/tmpl.go:10", Trace: "User input reflected without escaping.",
	})

	// Export encrypted.
	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle&encrypt=1", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.Bytes()
	if !bytes.HasPrefix(body, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		t.Fatal("response is not armored age")
	}
	// Body must not contain any plaintext finding data.
	if bytes.Contains(body, []byte("XSS in template")) {
		t.Error("plaintext finding title leaked into encrypted output")
	}

	// Decrypt with each identity independently.
	for i, id := range []age.Identity{id1, id2} {
		ar := armor.NewReader(bytes.NewReader(body))
		dr, err := age.Decrypt(ar, id)
		if err != nil {
			t.Fatalf("identity %d: decrypt: %v", i, err)
		}
		plain, err := io.ReadAll(dr)
		if err != nil {
			t.Fatalf("identity %d: read: %v", i, err)
		}
		var bundle struct {
			Findings []struct{ Title string } `json:"findings"`
		}
		if err := json.Unmarshal(plain, &bundle); err != nil {
			t.Fatalf("identity %d: unmarshal: %v", i, err)
		}
		if len(bundle.Findings) != 1 || bundle.Findings[0].Title != "XSS in template" {
			t.Errorf("identity %d: unexpected findings: %+v", i, bundle.Findings)
		}
	}

	// Import the decrypted bundle (decrypt server-side this time).
	importReq := httptest.NewRequest("POST", "/api/v1/import", bytes.NewReader(body))
	importReq.Host = testHost
	importW := httptest.NewRecorder()
	s.Handler().ServeHTTP(importW, importReq)
	if importW.Code != 201 {
		t.Fatalf("import status %d: %s", importW.Code, importW.Body)
	}
}

func TestExportBundleEncryptNoRecipients(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedFindings(t, s)

	// encrypt=1 with no recipients configured => 400.
	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle&encrypt=1", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 400 {
		t.Fatalf("status %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no recipients") {
		t.Errorf("unexpected error: %s", w.Body)
	}
}

func TestImportEncryptedNoIdentity(t *testing.T) {
	// Encrypt a bundle, then try to import with no identity => 422.
	id, _ := age.GenerateX25519Identity()
	plain := []byte(`{"repository":"https://example.com/x","tool":"test","findings":[{"title":"t","severity":"High"}]}`)
	ct, err := encryptBundle(plain, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}

	s, done := newTestServer(t)
	defer done()
	// s.EncIdentities is nil — no identity configured.

	r := httptest.NewRequest("POST", "/api/v1/import", bytes.NewReader(ct))
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 422 {
		t.Fatalf("status %d, want 422", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no identity configured") {
		t.Errorf("unexpected error: %s", w.Body)
	}
}

func TestImportCorruptedCiphertext(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	plain := []byte(`{"repository":"https://example.com/x","tool":"test","findings":[{"title":"t","severity":"High"}]}`)
	ct, err := encryptBundle(plain, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in the ciphertext body (after the header).
	corrupted := make([]byte, len(ct))
	copy(corrupted, ct)
	// Corrupt somewhere in the middle of the base64 payload.
	mid := len(corrupted) / 2
	corrupted[mid] ^= 0xff

	s, done := newTestServer(t)
	defer done()
	s.EncIdentities = []age.Identity{id}

	r := httptest.NewRequest("POST", "/api/v1/import", bytes.NewReader(corrupted))
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code == 201 {
		t.Fatal("corrupted ciphertext should not import successfully")
	}
}

func TestImportPlaintextStillWorksWithIdentityConfigured(t *testing.T) {
	id, _ := age.GenerateX25519Identity()

	s, done := newTestServer(t)
	defer done()
	s.EncIdentities = []age.Identity{id} // identity configured but body is plain

	plain := `{"repository":"https://github.com/test/plain","tool":"test","findings":[{"title":"plain finding","severity":"Low"}]}`
	r := httptest.NewRequest("POST", "/api/v1/import", strings.NewReader(plain))
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 201 {
		t.Fatalf("status %d, want 201: %s", w.Code, w.Body)
	}
}

func TestExportEncryptRejectsWithoutBundle(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedFindings(t, s)

	// encrypt=1 without format=bundle must 400, never silently fall through
	// to the plaintext NDJSON path. A request that asked for encryption and
	// got cleartext is the worst failure mode for this feature.
	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?encrypt=1", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != 400 {
		t.Fatalf("status %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "format=bundle") {
		t.Errorf("error should mention the format=bundle requirement, got: %s", w.Body)
	}
}

func TestExportEncryptRejectedOnGlobalEndpoints(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	seedFindings(t, s)

	// encrypt only applies to per-repo bundle exports. The cross-repo
	// findings and scans endpoints must 400, never silently stream plaintext
	// NDJSON when encryption was requested.
	for _, path := range []string{"/api/v1/findings?encrypt=1", "/api/v1/scans?encrypt=1"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = testHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Errorf("%s: status %d, want 400", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "encrypt") {
			t.Errorf("%s: error should mention encrypt, got: %s", path, w.Body)
		}
	}
}

func TestExportFindings_carriesDBFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, Commit: "abc123", SubPath: "core"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: "abc123", SubPath: "core",
		Fingerprint: "fp-1", LastSeenScanID: scan.ID, LastSeenCommit: "abc123", SeenCount: 3,
		FindingID: "F1", Title: "boom", Severity: sevHigh, Status: db.FindingTriaged,
		VID:   "VID-aaaa-bbbb-cccc-dddd-eeee-ffff",
		Trace: "t", Boundary: "b", Validation: "v", PriorArt: "p", Reach: "r", Rating: "x",
		DisclosureDraft: "d",
	})

	r := httptest.NewRequest("GET", "/api/v1/findings", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	want := []string{
		"id", "scan_id", "repository_id", "commit", "sub_path",
		"fingerprint", "last_seen_scan_id", "last_seen_commit", "seen_count", "vid",
		"finding_id", "sinks", "title", "severity", "status", "cwe", "location", "affected",
		"reachability", "quality_tier",
		"cve_id", "cvss_vector", "cvss_score", "fix_version", "fix_commit",
		"resolution", "disclosure_draft", "suggested_recipients", "assignee",
		"trace", "boundary", "validation", "prior_art", "reach", "rating",
		"created_at", "updated_at",
	}
	for _, k := range want {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("missing key %q in finding export", k)
		}
	}
}

func TestExportScans_carriesDBFieldsAndHidesAPIToken(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: "deep", SkillVersion: 2, SubPath: "core", Commit: "abc",
		CostUSD: 0.42, Turns: 5, InputTokens: 100, OutputTokens: 50,
		CacheReadTokens: 10, CacheWriteTokens: 5,
		Prompt: "p", Report: "r", Log: "l",
		APIToken: "secret-token-do-not-export",
	})

	r := httptest.NewRequest("GET", "/api/v1/scans", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	rows := readJSONL(t, w.Body.String())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	want := []string{
		"id", "repository_id", "kind", "status", "model",
		"skill_id", "skill_version", "skill_name", "finding_id",
		"sub_path", "commit", "started_at", "finished_at",
		"cost_usd", "turns",
		"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens",
		"prompt", "report", "log", "error", "findings_count",
		"created_at", "updated_at",
	}
	for _, k := range want {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("missing key %q in scan export", k)
		}
	}
	if _, leaked := rows[0]["api_token"]; leaked {
		t.Error("api_token must never appear in unauthenticated export")
	}
	if got := w.Body.String(); strings.Contains(got, "secret-token-do-not-export") {
		t.Errorf("APIToken value leaked into response body: %s", got)
	}
}

// richFinding seeds one finding with every field the enriched bundle carries,
// against a fresh repo, and returns the repo. Shared by the bundle-content and
// round-trip tests.
// rich-finding CVSS vectors and their canonical base scores, reused by the
// include=all round-trip test to assert the score is recomputed from the vector.
const (
	richCVSSv3Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	richCVSSv4Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
)

// rich-finding note/communication timestamps, kept as fixtures so the round-trip
// can assert they survive export→import unchanged.
var (
	richNote1At = time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	richNote2At = time.Date(2026, 6, 2, 10, 30, 0, 0, time.UTC)
	richCommAt  = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
)

// seedRichFinding creates one finding populated across every column and child
// record the bundle can carry: the default share-safe substance, the
// include=all enrichment/disclosure fields, and Notes/Communications/References.
// Tests use it to assert the default bundle stays lean while include=all is a
// faithful archival superset.
func seedRichFinding(t *testing.T, s *Server, url string) db.Repository {
	t.Helper()
	repo := db.Repository{URL: url, Name: "rich"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName, Commit: "scan-commit"}
	s.DB.Create(&scan)
	f := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, Commit: "find-commit", SubPath: "services/api",
		Title: "Path traversal", Severity: sevHigh, Confidence: "high",
		CWE: "CWE-22", Location: "h/download.go:88",
		Locations: "h/download.go:88\nh/legacy.go:12",
		Sinks:     "path.join,os.Open",
		VID:       "VID-aaaa-bbbb", Reachability: "reachable", QualityTier: "high",
		Trace:    "User input reaches path.join.",
		Boundary: "public handler", Validation: "confirmed locally",
		PriorArt: "CVE-2021-1", Reach: "public entry", Rating: "high impact",
		SuggestedFix: "--- a/x\n+++ b/x\n", SuggestedFixCommit: "fixbase9",
		// include=all archival fields.
		Snippet:                 "func download(p string) { open(path.Join(base, p)) }",
		Affected:                ">=1.0.0 <1.4.2",
		FixVersion:              "1.4.2",
		CVEID:                   "CVE-2021-9999",
		GHSAID:                  "GHSA-aaaa-bbbb-cccc",
		CVSSVector:              richCVSSv3Vector,
		CVSSScore:               9.8,
		CVSSv4Vector:            richCVSSv4Vector,
		Mitigation:              "Set safe_mode=true",
		MitigationSemgrep:       "rules: []",
		BreakingChange:          "non_breaking",
		BreakingChangeRationale: "no public API change",
		DupCheck:                "distinct from F2: different sink",
		DisclosureDraft:         "## Advisory\nPath traversal in download()",
		SuggestedRecipients:     "@alice (CODEOWNERS: crypto/*)",
		ExploitedInWild:         "no",
		ExploitedInWildEvidence: "no reports as of 2026-07",
		FixCommit:               "upstreamfix123",
	}
	if err := s.DB.Create(&f).Error; err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	if err := s.DB.Create(&[]db.FindingNote{
		{FindingID: f.ID, Body: "Reproduced locally on v1.4.1", By: "alice", CreatedAt: richNote1At},
		{FindingID: f.ID, Body: "Maintainer acknowledged", CreatedAt: richNote2At},
	}).Error; err != nil {
		t.Fatalf("seed notes: %v", err)
	}
	if err := s.DB.Create(&db.FindingCommunication{
		FindingID: f.ID, Channel: "email", Direction: "outbound",
		Actor: "maintainer@example.com", Body: "Reported privately",
		OfferedHelp: "pr", At: richCommAt,
	}).Error; err != nil {
		t.Fatalf("seed communication: %v", err)
	}
	if err := s.DB.Create(&[]db.FindingReference{
		{FindingID: f.ID, URL: "https://github.com/test/src/issues/1", Tags: "issue", Summary: "upstream issue"},
		{FindingID: f.ID, URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-9999", Tags: "cve"},
	}).Error; err != nil {
		t.Fatalf("seed references: %v", err)
	}
	return repo
}

func TestExportBundle_carriesEnrichedFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedRichFinding(t, s, "https://github.com/test/enriched")

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var bundle struct {
		GeneratedAt string           `json:"generated_at"`
		Findings    []sharingFinding `json:"findings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// generated_at lives inside the JSON and is a valid RFC3339 timestamp.
	if _, err := time.Parse(time.RFC3339, bundle.GeneratedAt); err != nil {
		t.Errorf("generated_at %q not RFC3339: %v", bundle.GeneratedAt, err)
	}
	if len(bundle.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(bundle.Findings))
	}
	f := bundle.Findings[0]
	checks := []struct{ name, got, want string }{
		{"description", f.Description, "User input reaches path.join."},
		{"commit", f.Commit, "find-commit"},
		{"sub_path", f.SubPath, "services/api"},
		{"locations", f.Locations, "h/download.go:88\nh/legacy.go:12"},
		{"vid", f.VID, "VID-aaaa-bbbb"},
		{"reachability", f.Reachability, "reachable"},
		{"quality_tier", f.QualityTier, "high"},
		{"boundary", f.Boundary, "public handler"},
		{"validation", f.Validation, "confirmed locally"},
		{"prior_art", f.PriorArt, "CVE-2021-1"},
		{"reach", f.Reach, "public entry"},
		{"rating", f.Rating, "high impact"},
		{"patch", f.Patch, "--- a/x\n+++ b/x\n"},
		{"fix_commit", f.FixCommit, "fixbase9"},
		// sinks now rides the default bundle; snippet does not (it would embed
		// verbatim, possibly private, source into a shareable artifact).
		{"sinks", f.Sinks, "path.join,os.Open"},
		{"snippet omitted from default bundle", f.Snippet, ""},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestExportBundleRoundTrip_carriesAllFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	src := seedRichFinding(t, s, "https://github.com/test/src")

	// Export.
	er := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(src.ID), 10)+"/findings?format=bundle", nil)
	er.Host = testHost
	ew := httptest.NewRecorder()
	s.Handler().ServeHTTP(ew, er)
	if ew.Code != 200 {
		t.Fatalf("export status %d: %s", ew.Code, ew.Body)
	}

	// Import into a *different* repo (?repo=) so the finding lands fresh
	// rather than deduping against the source row.
	ir := httptest.NewRequest("POST", "/api/v1/import?repo=https://github.com/test/dest", strings.NewReader(ew.Body.String()))
	ir.Host = testHost
	iw := httptest.NewRecorder()
	s.Handler().ServeHTTP(iw, ir)
	if iw.Code != 201 {
		t.Fatalf("import status %d: %s", iw.Code, iw.Body)
	}

	var dest db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/test/dest").First(&dest).Error; err != nil {
		t.Fatalf("dest repo not created: %v", err)
	}
	var got db.Finding
	if err := s.DB.Where("repository_id = ?", dest.ID).First(&got).Error; err != nil {
		t.Fatalf("imported finding not found: %v", err)
	}

	if got.Commit != "find-commit" {
		t.Errorf("Commit = %q, want find-commit (per-finding, not scan/bundle)", got.Commit)
	}
	if got.SubPath != "services/api" {
		t.Errorf("SubPath = %q", got.SubPath)
	}
	if got.Locations != "h/download.go:88\nh/legacy.go:12" {
		t.Errorf("Locations = %q", got.Locations)
	}
	if got.VID != "VID-aaaa-bbbb" {
		t.Errorf("VID = %q", got.VID)
	}
	if got.Reachability != "reachable" || got.QualityTier != "high" {
		t.Errorf("Reachability/QualityTier = %q/%q", got.Reachability, got.QualityTier)
	}
	if got.Boundary != "public handler" || got.Validation != "confirmed locally" ||
		got.PriorArt != "CVE-2021-1" || got.Reach != "public entry" || got.Rating != "high impact" {
		t.Errorf("audit prose mismatch: %+v", got)
	}
	// Patch stays gated out of SuggestedFix and is folded into Trace, with the
	// fix commit noted alongside.
	if got.SuggestedFix != "" {
		t.Errorf("SuggestedFix should stay empty (gated), got %q", got.SuggestedFix)
	}
	if !strings.Contains(got.Trace, "User input reaches path.join.") {
		t.Errorf("Trace missing original description: %q", got.Trace)
	}
	if !strings.Contains(got.Trace, "## Suggested fix") || !strings.Contains(got.Trace, "--- a/x") {
		t.Errorf("Trace missing folded patch: %q", got.Trace)
	}
	if !strings.Contains(got.Trace, "Applies to commit `fixbase9`") {
		t.Errorf("Trace missing fix-commit note: %q", got.Trace)
	}
	// sinks now round-trips through the default bundle; snippet, the archival
	// scalars, and the child records do not (they require include=all).
	if got.Sinks != "path.join,os.Open" {
		t.Errorf("Sinks = %q, want path.join,os.Open", got.Sinks)
	}
	if got.Snippet != "" || got.Affected != "" || got.CVEID != "" || got.DisclosureDraft != "" {
		t.Errorf("default bundle leaked archival fields: snippet=%q affected=%q cve=%q draft=%q",
			got.Snippet, got.Affected, got.CVEID, got.DisclosureDraft)
	}
	var noteCount int64
	s.DB.Model(&db.FindingNote{}).Where("finding_id = ?", got.ID).Count(&noteCount)
	if noteCount != 0 {
		t.Errorf("default bundle created %d notes, want 0", noteCount)
	}
}

func TestImportLegacyBundle_minimalFieldsStillWork(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// A bundle produced before the enriched fields existed: only the original
	// seven finding fields, and no generated_at. It must still import cleanly,
	// leaving the new columns empty and falling back to the bundle commit.
	legacy := `{"repository":"https://github.com/test/legacy","commit":"old1","tool":"scrutineer",` +
		`"findings":[{"title":"old finding","description":"d","severity":"High","confidence":"high",` +
		`"cwe":"CWE-79","location":"a.go:1","patch":"--- a\n+++ b\n"}]}`
	r := httptest.NewRequest("POST", "/api/v1/import", strings.NewReader(legacy))
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repo db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/test/legacy").First(&repo).Error; err != nil {
		t.Fatalf("repo not created: %v", err)
	}
	var got db.Finding
	if err := s.DB.Where("repository_id = ?", repo.ID).First(&got).Error; err != nil {
		t.Fatalf("finding not created: %v", err)
	}
	if got.Commit != "old1" {
		t.Errorf("Commit = %q, want old1 (bundle-level fallback)", got.Commit)
	}
	if got.SubPath != "" || got.VID != "" || got.Reachability != "" || got.Boundary != "" {
		t.Errorf("legacy import should leave new columns empty: %+v", got)
	}
}

// TestExportBundle_scopeFindingsCuratesScanners covers the opt-in bundle scope:
// without scope the bundle still carries scanner output (non-breaking), and
// scope=findings narrows it to the curated Findings bucket (nonScannerScanFilter)
// so per-repo semgrep/zizmor noise is not shared.
func TestExportBundle_scopeFindingsCuratesScanners(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/scoped", Name: "scoped"}
	s.DB.Create(&repo)
	dd := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&dd)
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: dd.ID, RepositoryID: repo.ID, Title: "audit finding", Severity: sevHigh})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "semgrep noise", Severity: "Low"})

	bundleTitles := func(qs string) []string {
		r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle"+qs, nil)
		r.Host = testHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("GET bundle%s: status %d: %s", qs, w.Code, w.Body)
		}
		var b struct {
			Findings []struct {
				Title string `json:"title"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		titles := make([]string, 0, len(b.Findings))
		for _, f := range b.Findings {
			titles = append(titles, f.Title)
		}
		return titles
	}

	// Default: scanner output is still included (existing callers unaffected).
	if got := bundleTitles(""); len(got) != 2 {
		t.Errorf("default bundle = %v, want both audit + scanner findings", got)
	}
	// scope=findings: curate to the Findings bucket, dropping the semgrep noise.
	if got := bundleTitles("&scope=findings"); len(got) != 1 || got[0] != "audit finding" {
		t.Errorf("scope=findings bundle = %v, want [audit finding] only (semgrep dropped)", got)
	}
}

// assertExportRejects runs each GET path and asserts a 400 whose body mentions
// keyword. Shared by the scope and include rejection tests, which validate the
// same "bundle-only query param used elsewhere" guard.
func assertExportRejects(t *testing.T, s *Server, keyword string, cases []struct{ name, path string }) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.path, nil)
			r.Host = testHost
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("status %d, want 400; body=%s", w.Code, w.Body)
			}
			if !strings.Contains(w.Body.String(), keyword) {
				t.Errorf("error should mention %s, got: %s", keyword, w.Body)
			}
		})
	}
}

// TestExportBundle_scopeRejected pins the validation: an unknown scope value, a
// scope without format=bundle, and scope on the cross-repo endpoints all 400
// rather than silently returning a wider set than the caller asked for.
func TestExportBundle_scopeRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedFindings(t, s)
	id := strconv.FormatUint(uint64(repo.ID), 10)

	assertExportRejects(t, s, "scope", []struct{ name, path string }{
		{"unknown scope value", "/api/v1/repositories/" + id + "/findings?format=bundle&scope=bogus"},
		{"scope without bundle", "/api/v1/repositories/" + id + "/findings?scope=findings"},
		{"scope on repositories", "/api/v1/repositories?scope=findings"},
		{"scope on global findings", "/api/v1/findings?scope=findings"},
		{"scope on global scans", "/api/v1/scans?scope=findings"},
	})
}

// TestExportBundle_scopeFindingsCuratesEncrypted confirms scope curation holds
// on the encrypted path too: scope filters the finding query before the
// plaintext/encrypt branch, so the scanner finding never reaches the ciphertext.
func TestExportBundle_scopeFindingsCuratesEncrypted(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s.EncRecipients = []age.Recipient{id.Recipient()}
	s.EncIdentities = []age.Identity{id}

	repo := db.Repository{URL: "https://example.com/enc-scoped", Name: "enc-scoped"}
	s.DB.Create(&repo)
	dd := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&dd)
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: dd.ID, RepositoryID: repo.ID, Title: "audit finding", Severity: sevHigh})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "semgrep noise", Severity: "Low"})

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/findings?format=bundle&encrypt=1&scope=findings", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	ar := armor.NewReader(bytes.NewReader(w.Body.Bytes()))
	dr, err := age.Decrypt(ar, id)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	plain, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var bundle struct {
		Findings []struct {
			Title string `json:"title"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(plain, &bundle); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(bundle.Findings) != 1 || bundle.Findings[0].Title != "audit finding" {
		t.Errorf("encrypted scope=findings bundle = %+v, want [audit finding] only (semgrep dropped)", bundle.Findings)
	}
}

// TestExportBundle_includeAllCarriesArchival pins the default/archival split:
// the default bundle carries the share-safe substance (sinks now included) but
// withholds snippet, the enrichment/disclosure scalars, and the child records;
// include=all is the faithful superset that carries all of them.
func TestExportBundle_includeAllCarriesArchival(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedRichFinding(t, s, "https://github.com/test/archival")
	id := strconv.FormatUint(uint64(repo.ID), 10)

	get := func(qs string) sharingFinding {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/repositories/"+id+"/findings?format=bundle"+qs, nil)
		r.Host = testHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("GET bundle%q: status %d: %s", qs, w.Code, w.Body)
		}
		var b struct {
			Findings []sharingFinding `json:"findings"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(b.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(b.Findings))
		}
		return b.Findings[0]
	}

	// Default bundle: sinks travels, everything archival is withheld.
	def := get("")
	if def.Sinks != "path.join,os.Open" {
		t.Errorf("default sinks = %q, want path.join,os.Open", def.Sinks)
	}
	if def.Snippet != "" || def.Affected != "" || def.CVEID != "" || def.CVSSVector != "" ||
		def.DisclosureDraft != "" || def.SuggestedRecipients != "" || def.ExploitedInWild != "" || def.UpstreamFixCommit != "" {
		t.Errorf("default bundle carried archival scalars: %+v", def)
	}
	if len(def.Notes) != 0 || len(def.Communications) != 0 || len(def.References) != 0 {
		t.Errorf("default bundle carried child records: notes=%d comms=%d refs=%d",
			len(def.Notes), len(def.Communications), len(def.References))
	}

	// include=all: the archival superset.
	all := get("&include=all")
	for _, c := range []struct{ name, got, want string }{
		{"snippet", all.Snippet, "func download(p string) { open(path.Join(base, p)) }"},
		{"affected", all.Affected, ">=1.0.0 <1.4.2"},
		{"fix_version", all.FixVersion, "1.4.2"},
		{"cve_id", all.CVEID, "CVE-2021-9999"},
		{"ghsa_id", all.GHSAID, "GHSA-aaaa-bbbb-cccc"},
		{"cvss_vector", all.CVSSVector, richCVSSv3Vector},
		{"cvss_v4_vector", all.CVSSv4Vector, richCVSSv4Vector},
		{"mitigation", all.Mitigation, "Set safe_mode=true"},
		{"mitigation_semgrep", all.MitigationSemgrep, "rules: []"},
		{"breaking_change", all.BreakingChange, "non_breaking"},
		{"breaking_change_rationale", all.BreakingChangeRationale, "no public API change"},
		{"dup_check", all.DupCheck, "distinct from F2: different sink"},
		{"disclosure_draft", all.DisclosureDraft, "## Advisory\nPath traversal in download()"},
		{"suggested_recipients", all.SuggestedRecipients, "@alice (CODEOWNERS: crypto/*)"},
		{"exploited_in_wild", all.ExploitedInWild, "no"},
		{"exploited_in_wild_evidence", all.ExploitedInWildEvidence, "no reports as of 2026-07"},
		// The real upstream fix commit rides the new key; the legacy fix_commit
		// still carries the SuggestedFix base.
		{"upstream_fix_commit", all.UpstreamFixCommit, "upstreamfix123"},
		{"fix_commit (suggested-fix base)", all.FixCommit, "fixbase9"},
	} {
		if c.got != c.want {
			t.Errorf("include=all %s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if len(all.Notes) != 2 || all.Notes[0].Body != "Reproduced locally on v1.4.1" ||
		all.Notes[0].By != "alice" || !all.Notes[0].CreatedAt.Equal(richNote1At) {
		t.Errorf("notes mismatch: %+v", all.Notes)
	}
	if len(all.Communications) != 1 || all.Communications[0].Channel != "email" ||
		all.Communications[0].OfferedHelp != "pr" || !all.Communications[0].At.Equal(richCommAt) {
		t.Errorf("communications mismatch: %+v", all.Communications)
	}
	if len(all.References) != 2 || all.References[0].URL != "https://github.com/test/src/issues/1" ||
		all.References[0].Tags != "issue" {
		t.Errorf("references mismatch: %+v", all.References)
	}
}

// TestExportBundleRoundTrip_includeAll exports the archival superset, imports it
// into a fresh repo, and asserts every carried column and child record lands —
// with the CVSS scores recomputed from the vectors rather than trusted.
func TestExportBundleRoundTrip_includeAll(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	src := seedRichFinding(t, s, "https://github.com/test/src2")

	er := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(src.ID), 10)+"/findings?format=bundle&include=all", nil)
	er.Host = testHost
	ew := httptest.NewRecorder()
	s.Handler().ServeHTTP(ew, er)
	if ew.Code != 200 {
		t.Fatalf("export status %d: %s", ew.Code, ew.Body)
	}

	// Import into a *different* repo so the finding lands fresh, not deduped.
	ir := httptest.NewRequest("POST", "/api/v1/import?repo=https://github.com/test/dest2&revalidate=false", strings.NewReader(ew.Body.String()))
	ir.Host = testHost
	iw := httptest.NewRecorder()
	s.Handler().ServeHTTP(iw, ir)
	if iw.Code != 201 {
		t.Fatalf("import status %d: %s", iw.Code, iw.Body)
	}

	var dest db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/test/dest2").First(&dest).Error; err != nil {
		t.Fatalf("dest repo not created: %v", err)
	}
	var got db.Finding
	if err := s.DB.Where("repository_id = ?", dest.ID).First(&got).Error; err != nil {
		t.Fatalf("imported finding not found: %v", err)
	}

	for _, c := range []struct{ name, got, want string }{
		{"sinks", got.Sinks, "path.join,os.Open"},
		{"snippet", got.Snippet, "func download(p string) { open(path.Join(base, p)) }"},
		{"affected", got.Affected, ">=1.0.0 <1.4.2"},
		{"fix_version", got.FixVersion, "1.4.2"},
		{"cve_id", got.CVEID, "CVE-2021-9999"},
		{"ghsa_id", got.GHSAID, "GHSA-aaaa-bbbb-cccc"},
		{"cvss_vector", got.CVSSVector, richCVSSv3Vector},
		{"cvss_v4_vector", got.CVSSv4Vector, richCVSSv4Vector},
		{"mitigation", got.Mitigation, "Set safe_mode=true"},
		{"mitigation_semgrep", got.MitigationSemgrep, "rules: []"},
		{"breaking_change", got.BreakingChange, "non_breaking"},
		{"breaking_change_rationale", got.BreakingChangeRationale, "no public API change"},
		{"dup_check", got.DupCheck, "distinct from F2: different sink"},
		{"disclosure_draft", got.DisclosureDraft, "## Advisory\nPath traversal in download()"},
		{"suggested_recipients", got.SuggestedRecipients, "@alice (CODEOWNERS: crypto/*)"},
		{"exploited_in_wild", got.ExploitedInWild, "no"},
		{"exploited_in_wild_evidence", got.ExploitedInWildEvidence, "no reports as of 2026-07"},
		// The real upstream fix commit lands in FixCommit (the new upstream key);
		// the SuggestedFix base stays folded into Trace.
		{"fix_commit (real upstream)", got.FixCommit, "upstreamfix123"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// CVSS scores are recomputed from the carried vectors, never trusted.
	wantV3, _ := db.CVSSV3ScoreFromVector(richCVSSv3Vector)
	wantV4, _ := db.CVSSV4ScoreFromVector(richCVSSv4Vector)
	if got.CVSSScore != wantV3 || wantV3 != 9.8 {
		t.Errorf("CVSSScore = %v, want %v (recomputed from vector)", got.CVSSScore, wantV3)
	}
	if got.CVSSv4Score != wantV4 || wantV4 == 0 {
		t.Errorf("CVSSv4Score = %v, want %v (recomputed from vector)", got.CVSSv4Score, wantV4)
	}

	// SuggestedFix stays gated and folded into Trace, as for the default bundle.
	if got.SuggestedFix != "" {
		t.Errorf("SuggestedFix should stay empty (gated), got %q", got.SuggestedFix)
	}
	if !strings.Contains(got.Trace, "## Suggested fix") || !strings.Contains(got.Trace, "Applies to commit `fixbase9`") {
		t.Errorf("Trace missing folded patch/fix-commit: %q", got.Trace)
	}

	// Child records round-trip with timestamps preserved.
	var notes []db.FindingNote
	s.DB.Where("finding_id = ?", got.ID).Order("created_at asc").Find(&notes)
	if len(notes) != 2 || notes[0].Body != "Reproduced locally on v1.4.1" || notes[0].By != "alice" ||
		!notes[0].CreatedAt.Equal(richNote1At) {
		t.Fatalf("notes mismatch: %+v", notes)
	}
	if notes[1].Body != "Maintainer acknowledged" || !notes[1].CreatedAt.Equal(richNote2At) {
		t.Errorf("note[1] mismatch: %+v", notes[1])
	}
	var comms []db.FindingCommunication
	s.DB.Where("finding_id = ?", got.ID).Find(&comms)
	if len(comms) != 1 || comms[0].Channel != "email" || comms[0].Actor != "maintainer@example.com" ||
		comms[0].OfferedHelp != "pr" || !comms[0].At.Equal(richCommAt) {
		t.Fatalf("communications mismatch: %+v", comms)
	}
	var refs []db.FindingReference
	s.DB.Where("finding_id = ?", got.ID).Order("id asc").Find(&refs)
	if len(refs) != 2 || refs[0].URL != "https://github.com/test/src/issues/1" ||
		refs[0].Tags != "issue" || refs[0].Summary != "upstream issue" {
		t.Fatalf("references mismatch: %+v", refs)
	}
}

// TestImportBundle_includeAllIdempotent re-imports the same include=all bundle
// onto a repo that already has the finding: the second import bumps seen_count
// and content-dedups the child records rather than duplicating them.
func TestImportBundle_includeAllIdempotent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	src := seedRichFinding(t, s, "https://github.com/test/src3")

	er := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(src.ID), 10)+"/findings?format=bundle&include=all", nil)
	er.Host = testHost
	ew := httptest.NewRecorder()
	s.Handler().ServeHTTP(ew, er)
	if ew.Code != 200 {
		t.Fatalf("export status %d: %s", ew.Code, ew.Body)
	}
	body := ew.Body.String()

	imp := func() {
		t.Helper()
		r := httptest.NewRequest("POST", "/api/v1/import?repo=https://github.com/test/dest3&revalidate=false", strings.NewReader(body))
		r.Host = testHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 201 {
			t.Fatalf("import status %d: %s", w.Code, w.Body)
		}
	}
	imp()
	imp() // re-import the same bundle onto the same repo

	var dest db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/test/dest3").First(&dest).Error; err != nil {
		t.Fatalf("dest repo not created: %v", err)
	}
	var got db.Finding
	if err := s.DB.Where("repository_id = ?", dest.ID).First(&got).Error; err != nil {
		t.Fatalf("imported finding not found: %v", err)
	}
	if got.SeenCount != 2 {
		t.Errorf("SeenCount = %d, want 2 after re-import", got.SeenCount)
	}
	var findingCount int64
	s.DB.Model(&db.Finding{}).Where("repository_id = ?", dest.ID).Count(&findingCount)
	if findingCount != 1 {
		t.Errorf("finding count = %d, want 1 (no duplicate row)", findingCount)
	}
	var notes, comms, refs int64
	s.DB.Model(&db.FindingNote{}).Where("finding_id = ?", got.ID).Count(&notes)
	s.DB.Model(&db.FindingCommunication{}).Where("finding_id = ?", got.ID).Count(&comms)
	s.DB.Model(&db.FindingReference{}).Where("finding_id = ?", got.ID).Count(&refs)
	if notes != 2 || comms != 1 || refs != 2 {
		t.Errorf("after re-import: notes=%d comms=%d refs=%d, want 2/1/2 (content-deduped)", notes, comms, refs)
	}
}

// TestExportBundle_includeRejected pins the validation: an unknown include
// value, include without format=bundle, and include on the cross-repo endpoints
// all 400 rather than silently returning the lean default.
func TestExportBundle_includeRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedFindings(t, s)
	id := strconv.FormatUint(uint64(repo.ID), 10)

	assertExportRejects(t, s, "include", []struct{ name, path string }{
		{"unknown include value", "/api/v1/repositories/" + id + "/findings?format=bundle&include=bogus"},
		{"include without bundle", "/api/v1/repositories/" + id + "/findings?include=all"},
		{"include on repositories", "/api/v1/repositories?include=all"},
		{"include on global findings", "/api/v1/findings?include=all"},
		{"include on global scans", "/api/v1/scans?include=all"},
	})
}

// TestExportBundleEncryptedRoundTrip_includeAll is the shape the batch-archival
// workflow uses: an encrypted include=all bundle. It confirms the sensitive
// child records are inside the ciphertext (a note body must not appear in the
// clear) and survive a server-side decrypt on import.
func TestExportBundleEncryptedRoundTrip_includeAll(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	s.EncRecipients = []age.Recipient{id.Recipient()}
	s.EncIdentities = []age.Identity{id}

	src := seedRichFinding(t, s, "https://github.com/test/enc-archival")

	r := httptest.NewRequest("GET", "/api/v1/repositories/"+strconv.FormatUint(uint64(src.ID), 10)+"/findings?format=bundle&include=all&encrypt=1", nil)
	r.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.Bytes()
	if !bytes.HasPrefix(body, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		t.Fatal("response is not armored age")
	}
	// The internal note body must never appear in the clear.
	if bytes.Contains(body, []byte("Reproduced locally on v1.4.1")) {
		t.Error("plaintext note body leaked into encrypted output")
	}

	// Import (server decrypts in place) into a fresh repo.
	ir := httptest.NewRequest("POST", "/api/v1/import?repo=https://github.com/test/enc-dest&revalidate=false", bytes.NewReader(body))
	ir.Host = testHost
	iw := httptest.NewRecorder()
	s.Handler().ServeHTTP(iw, ir)
	if iw.Code != 201 {
		t.Fatalf("import status %d: %s", iw.Code, iw.Body)
	}

	var dest db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/test/enc-dest").First(&dest).Error; err != nil {
		t.Fatalf("dest repo not created: %v", err)
	}
	var got db.Finding
	if err := s.DB.Where("repository_id = ?", dest.ID).First(&got).Error; err != nil {
		t.Fatalf("imported finding not found: %v", err)
	}
	if got.DisclosureDraft == "" || got.CVSSVector != richCVSSv3Vector {
		t.Errorf("archival scalars did not survive encrypted round-trip: draft=%q cvss=%q", got.DisclosureDraft, got.CVSSVector)
	}
	var notes int64
	s.DB.Model(&db.FindingNote{}).Where("finding_id = ?", got.ID).Count(&notes)
	if notes != 2 {
		t.Errorf("notes after encrypted round-trip = %d, want 2", notes)
	}
}
