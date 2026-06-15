package web

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

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
