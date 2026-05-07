package web

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestFindingPatchDownload_servesGatedColumn(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone}
	s.DB.Create(&scan)
	diff := "--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-a\n+b\n"
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t",
		Severity: "Low", Location: "x.go:1", SuggestedFix: diff, SuggestedFixCommit: "abc"}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d/patch.diff", f.ID)))
	if w.Code != 200 {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	if w.Body.String() != diff {
		t.Errorf("body = %q, want the stored diff", w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/x-diff") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestFindingPatchDownload_404WhenNoGatedFix(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: "Low"}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d/patch.diff", f.ID)))
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no gated patch") {
		t.Errorf("body = %q", w.Body.String())
	}
}
