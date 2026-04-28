package web

import (
	"bufio"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

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

	for _, path := range []string{"/api/v1/findings", "/api/v1/scans", "/api/v1/repositories/1/findings"} {
		r := httptest.NewRequest("GET", path+"?format=csv", nil)
		r.Host = testHost
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Errorf("%s: status %d, want 400", path, w.Code)
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
		"fingerprint", "last_seen_scan_id", "last_seen_commit", "seen_count",
		"finding_id", "sinks", "title", "severity", "status", "cwe", "location", "affected",
		"cve_id", "cvss_vector", "cvss_score", "fix_version", "fix_commit",
		"resolution", "disclosure_draft", "assignee",
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
