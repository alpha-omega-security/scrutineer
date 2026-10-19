package web

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/osscrs"
	"scrutineer/internal/poc"
)

const ossCRSPath = "/api/v1/import/oss-crs?repo=https://github.com/example/widget&commit=deadbeef&run=run-42"

const ossCRSCandidate = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"crs-a"}},"results":[
	{"ruleId":"heap-overflow","message":{"text":"heap overflow in parse"},
	 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/parse.c"},"region":{"startLine":12}}}],
	 "attachments":[{"artifactLocation":{"uri":"povs/abc"}},{"artifactLocation":{"uri":"patches/fix.diff"}},{"artifactLocation":{"uri":"povs/missing"}}]}]}]}`

func ossCRSArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fullOSSCRSArchive(t *testing.T) []byte {
	return ossCRSArchive(t, map[string]string{
		"bug-candidates/a.sarif": ossCRSCandidate,
		"povs/abc":               "\x00\xffcrash",
		"povs/zzz":               "other crash",
		"patches/fix.diff":       "--- a/src/parse.c\n+++ b/src/parse.c\n",
		"reports/r.tar.gz":       "report bytes",
		"seeds/1":                "s",
		"seeds/2":                "s",
	})
}

type ossCRSResponse struct {
	ScanID  uint `json:"scan_id"`
	Results []struct {
		Created    int    `json:"created"`
		Observed   int    `json:"observed"`
		FindingIDs []uint `json:"finding_ids"`
	} `json:"results"`
	Artifacts []ossCRSArtifact `json:"artifacts"`
	Skipped   []struct {
		Path   string `json:"path"`
		Files  int    `json:"files"`
		Reason string `json:"reason"`
	} `json:"skipped"`
	Unresolved []string `json:"unresolved_attachments"`
}

func postOSSCRS(t *testing.T, s *Server, path string, body []byte) (*httptest.ResponseRecorder, ossCRSResponse) {
	t.Helper()
	w := postImport(t, s, path, string(body))
	var resp ossCRSResponse
	if w.Code == http.StatusCreated {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return w, resp
}

func TestImportOSSCRSRetainsEvidence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w, resp := postOSSCRS(t, s, ossCRSPath, fullOSSCRSArchive(t))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if len(resp.Results) != 1 || resp.Results[0].Created != 1 {
		t.Fatalf("results = %+v", resp.Results)
	}
	findingID := resp.Results[0].FindingIDs[0]

	var finding db.Finding
	if err := s.DB.First(&finding, findingID).Error; err != nil {
		t.Fatal(err)
	}
	if finding.ImportedFrom != "crs-a" || finding.Commit != "deadbeef" || finding.Location != "src/parse.c:12" {
		t.Errorf("finding = from=%q commit=%q loc=%q", finding.ImportedFrom, finding.Commit, finding.Location)
	}
	if finding.SuggestedFix != "" {
		t.Errorf("SuggestedFix = %q, want empty until the patch gate passes", finding.SuggestedFix)
	}

	var scan db.Scan
	if err := s.DB.First(&scan, resp.ScanID).Error; err != nil {
		t.Fatal(err)
	}
	if scan.Kind != "import" || scan.SkillName != "oss-crs" || scan.Commit != "deadbeef" || !strings.Contains(scan.Log, "oss-crs run: run-42") {
		t.Errorf("scan = kind=%q skill=%q commit=%q log=%q", scan.Kind, scan.SkillName, scan.Commit, scan.Log)
	}

	got := map[string]uint{}
	for _, a := range resp.Artifacts {
		if !a.Stored {
			t.Errorf("%s: stored = false on first import", a.Path)
		}
		got[a.Path] = a.FindingID
	}
	want := map[string]uint{"povs/abc": findingID, "patches/fix.diff": findingID, "povs/zzz": 0, "reports/r.tar.gz": 0}
	if len(got) != len(want) {
		t.Errorf("artifacts = %v, want %v", got, want)
	}
	for p, id := range want {
		if fid, ok := got[p]; !ok || fid != id {
			t.Errorf("%s: finding = %d (present %v), want %d", p, fid, ok, id)
		}
	}
	if len(resp.Skipped) != 1 || resp.Skipped[0].Path != "seeds/" || resp.Skipped[0].Files != 2 {
		t.Errorf("skipped = %+v, want seeds/ with 2 files", resp.Skipped)
	}
	if len(resp.Unresolved) != 1 || resp.Unresolved[0] != "povs/missing" {
		t.Errorf("unresolved = %v, want [povs/missing]", resp.Unresolved)
	}
}

func TestImportOSSCRSCapturesAssociatedPoV(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, resp := postOSSCRS(t, s, ossCRSPath, fullOSSCRSArchive(t))
	findingID := resp.Results[0].FindingIDs[0]

	row, err := db.LoadFindingPoC(s.DB, findingID)
	if err != nil || row == nil {
		t.Fatalf("captured PoC = %v, %v", row, err)
	}
	files, err := poc.Decode(row.Files)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Path != "povs/abc" || string(files[0].Data) != "\x00\xffcrash" || row.ScanID != resp.ScanID {
		t.Errorf("captured PoC = %+v scan=%d", files, row.ScanID)
	}
}

func TestImportOSSCRSDownloadsOriginalBytes(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, resp := postOSSCRS(t, s, ossCRSPath, fullOSSCRSArchive(t))

	var report ossCRSArtifact
	for _, a := range resp.Artifacts {
		if a.Path == "reports/r.tar.gz" {
			report = a
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/import-artifacts/"+strconv.FormatUint(uint64(report.ID), 10), nil)
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "report bytes" {
		t.Fatalf("download = %d %q", w.Code, w.Body.String())
	}
	if cd := w.Header().Get("Content-Disposition"); cd != `attachment; filename="r.tar.gz"` {
		t.Errorf("Content-Disposition = %q", cd)
	}

	var repo db.Repository
	s.DB.First(&repo)
	r = httptest.NewRequest(http.MethodGet, "/api/v1/repositories/"+strconv.FormatUint(uint64(repo.ID), 10)+"/import-artifacts", nil)
	asOperator(r)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var listed []db.ImportArtifact
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || len(listed) != 4 {
		t.Fatalf("list = %d %s (%v)", w.Code, w.Body.String(), err)
	}
	if strings.Contains(w.Body.String(), "report bytes") {
		t.Error("listing carries artifact bytes")
	}

	if err := s.DB.Delete(&db.ImportArtifact{}, report.ID).Error; err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/v1/import-artifacts/"+strconv.FormatUint(uint64(report.ID), 10), nil)
	asOperator(r)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing artifact status = %d, want 404", w.Code)
	}
}

func TestImportOSSCRSRepeatImportIsIdempotent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	body := fullOSSCRSArchive(t)
	if w, _ := postOSSCRS(t, s, ossCRSPath, body); w.Code != http.StatusCreated {
		t.Fatalf("first import = %d %s", w.Code, w.Body.String())
	}
	w, resp := postOSSCRS(t, s, ossCRSPath, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("second import = %d %s", w.Code, w.Body.String())
	}
	if resp.Results[0].Created != 0 || resp.Results[0].Observed != 1 {
		t.Errorf("second import results = %+v, want 0 created and 1 observed", resp.Results)
	}
	for _, a := range resp.Artifacts {
		if a.Stored || a.ID == 0 {
			t.Errorf("%s: stored=%v id=%d, want the existing row", a.Path, a.Stored, a.ID)
		}
	}
	for model, want := range map[string]int64{"findings": 1, "import_artifacts": 4, "finding_pocs": 1} {
		var n int64
		s.DB.Table(model).Count(&n)
		if n != want {
			t.Errorf("%s rows = %d, want %d", model, n, want)
		}
	}
}

func TestImportOSSCRSQueuesRevalidation(t *testing.T) {
	for _, tc := range []struct {
		path string
		want int64
	}{
		{ossCRSPath, 1},
		{ossCRSPath + "&revalidate=false", 0},
	} {
		s, done := newTestServer(t)
		revalidate := db.Skill{Name: revalidateSkillName, OutputFile: "report.json", OutputKind: "revalidate", Version: 1, Active: true}
		if err := s.DB.Create(&revalidate).Error; err != nil {
			t.Fatal(err)
		}
		if w, _ := postOSSCRS(t, s, tc.path, fullOSSCRSArchive(t)); w.Code != http.StatusCreated {
			t.Fatalf("%s = %d %s", tc.path, w.Code, w.Body.String())
		}
		var queued int64
		s.DB.Model(&db.Scan{}).Where("skill_id = ? AND status = ?", revalidate.ID, db.ScanQueued).Count(&queued)
		if queued != tc.want {
			t.Errorf("%s: queued revalidate = %d, want %d", tc.path, queued, tc.want)
		}
		done()
	}
}

func TestImportOSSCRSRefusesOversizedArchive(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	files := map[string]string{}
	for i := range osscrs.MaxRetainedBytes/poc.MaxFileBytes + 1 {
		files["povs/"+strconv.Itoa(i)] = strings.Repeat("a", poc.MaxFileBytes)
	}
	if w, _ := postOSSCRS(t, s, ossCRSPath, ossCRSArchive(t, files)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (%s)", w.Code, w.Body.String())
	}
	var n int64
	s.DB.Model(&db.Scan{}).Count(&n)
	if n != 0 {
		t.Errorf("scans = %d after a refused archive, want 0", n)
	}
}

func TestImportOSSCRSWithoutCandidatesKeepsEvidence(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w, resp := postOSSCRS(t, s, ossCRSPath, ossCRSArchive(t, map[string]string{"povs/zzz": "crash"}))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d %s", w.Code, w.Body.String())
	}
	if len(resp.Results) != 0 || len(resp.Artifacts) != 1 || resp.Artifacts[0].FindingID != 0 {
		t.Errorf("response = %+v", resp)
	}
}

func TestImportOSSCRSRejectsBadRequests(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	archive := fullOSSCRSArchive(t)
	cases := []struct {
		name, path string
		body       []byte
		want       int
	}{
		{"no repo", "/api/v1/import/oss-crs?commit=deadbeef", archive, http.StatusBadRequest},
		{"no commit", "/api/v1/import/oss-crs?repo=https://github.com/example/widget", archive, http.StatusBadRequest},
		{"control run", "/api/v1/import/oss-crs?repo=https://github.com/example/widget&commit=deadbeef&run=a%07b", archive, http.StatusBadRequest},
		{"bad revalidate", ossCRSPath + "&revalidate=maybe", archive, http.StatusBadRequest},
		{"not gzip", ossCRSPath, []byte(ossCRSCandidate), http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		if w, _ := postOSSCRS(t, s, tc.path, tc.body); w.Code != tc.want {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
	var n int64
	s.DB.Model(&db.ImportArtifact{}).Count(&n)
	if n != 0 {
		t.Errorf("import_artifacts rows = %d after rejected requests, want 0", n)
	}
}

func TestDeleteFindingRemovesItsImportArtifacts(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, resp := postOSSCRS(t, s, ossCRSPath, fullOSSCRSArchive(t))
	var finding db.Finding
	if err := s.DB.First(&finding, resp.Results[0].FindingIDs[0]).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := s.deleteFinding(finding); err != nil {
		t.Fatal(err)
	}
	var paths []string
	s.DB.Model(&db.ImportArtifact{}).Order("path").Pluck("path", &paths)
	if strings.Join(paths, ",") != "povs/zzz,reports/r.tar.gz" {
		t.Errorf("remaining artifacts = %v, want only the unassociated ones", paths)
	}
}

func TestImportOSSCRSPoVReachesDisclosureBundle(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	_, resp := postOSSCRS(t, s, ossCRSPath, fullOSSCRSArchive(t))
	r := httptest.NewRequest(http.MethodGet, "/findings/"+strconv.FormatUint(uint64(resp.Results[0].FindingIDs[0]), 10)+"/bundle.tar.gz", nil)
	asOperator(r)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("bundle status = %d: %s", w.Code, w.Body.String())
	}
	files := readArchive(t, w.Body.Bytes())
	if string(files["poc/povs/abc"]) != "\x00\xffcrash" {
		t.Fatalf("bundle entries = %v, want poc/povs/abc with the imported bytes", keys(files))
	}
}
