package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// readArchive uncompresses a tar.gz response body and returns a map of
// filename -> content.
func readArchive(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip open: %v", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("tar read %q: %v", h.Name, err)
		}
		out[h.Name] = data
	}
	return out
}

func setUpBundleFinding(t *testing.T, s *Server, withPatch bool) *db.Finding {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/acme/widget", FullName: "acme/widget", Name: "widget"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, Commit: "abc123"}
	s.DB.Create(&scan)
	f := db.Finding{
		ScanID:       scan.ID,
		RepositoryID: repo.ID,
		Title:        "SQL injection in handler",
		Severity:     "High",
		CWE:          "CWE-89",
		Location:     "internal/api/users.go:42",
		Trace:        "user input flows into raw SQL string",
	}
	if withPatch {
		f.SuggestedFix = "--- a/internal/api/users.go\n+++ b/internal/api/users.go\n@@ -1 +1 @@\n-x\n+y\n"
	}
	s.DB.Create(&f)
	return &f
}

func TestFindingBundle_containsManifestAndExports(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, true)

	r := httptest.NewRequest(http.MethodGet,
		"/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Type"); got != "application/gzip" {
		t.Errorf("Content-Type = %q", got)
	}
	files := readArchive(t, w.Body.Bytes())

	want := []string{"manifest.json", "osv.json", "csaf.json", "report.md", "patch.diff"}
	for _, name := range want {
		if _, ok := files[name]; !ok {
			t.Errorf("archive missing %s; have %v", name, keys(files))
		}
	}

	var m bundleManifest
	if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if m.FindingID != f.ID {
		t.Errorf("manifest finding_id = %d, want %d", m.FindingID, f.ID)
	}
	if m.Title != f.Title {
		t.Errorf("manifest title = %q", m.Title)
	}
	if m.Repository != "acme/widget" {
		t.Errorf("manifest repository = %q", m.Repository)
	}
	if _, ok := m.Contents["osv.json"]; !ok {
		t.Errorf("manifest.contents missing osv.json: %+v", m.Contents)
	}
	if _, ok := m.Contents["patch.diff"]; !ok {
		t.Errorf("manifest.contents missing patch.diff: %+v", m.Contents)
	}

	// The per-file exports must equal what the corresponding /findings/{id}/{file}
	// endpoint serves. The OSV and report endpoints are the strongest check:
	// they hit the same builder, so the bytes should match exactly.
	osvReq := httptest.NewRequest(http.MethodGet,
		"/findings/"+strconv.Itoa(int(f.ID))+"/osv.json", nil)
	osvReq.Host = "127.0.0.1:8080"
	osvRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(osvRec, osvReq)
	if !bytes.Equal(files["osv.json"], osvRec.Body.Bytes()) {
		t.Errorf("bundle osv.json differs from /findings/%d/osv.json", f.ID)
	}
}

func TestFindingBundle_skipsPatchWhenAbsent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, false)

	r := httptest.NewRequest(http.MethodGet,
		"/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	files := readArchive(t, w.Body.Bytes())
	if _, ok := files["patch.diff"]; ok {
		t.Errorf("archive should omit patch.diff when SuggestedFix is empty")
	}

	var m bundleManifest
	_ = json.Unmarshal(files["manifest.json"], &m)
	if _, ok := m.Contents["patch.diff"]; ok {
		t.Errorf("manifest.contents should omit patch.diff")
	}
}

func TestFindingBundle_rejectsDuplicate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	f := setUpBundleFinding(t, s, false)
	s.DB.Model(f).Update("status", db.FindingDuplicate)

	r := httptest.NewRequest(http.MethodGet,
		"/findings/"+strconv.Itoa(int(f.ID))+"/bundle.tar.gz", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusGone {
		t.Errorf("status = %d, want 410 for duplicate finding", w.Code)
	}
}

func TestFindingBundle_notFoundReturns404(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	r := httptest.NewRequest(http.MethodGet, "/findings/99999/bundle.tar.gz", nil)
	r.Host = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Compile-time guarantee that the handler signature matches the rest of
// the export handlers; if either changes, the build (and the rest of
// the tests) catches it immediately.
var _ = func(s *Server, w http.ResponseWriter, r *http.Request) {
	s.findingBundleDownload(w, r)
	_ = strings.TrimSpace("")
}
