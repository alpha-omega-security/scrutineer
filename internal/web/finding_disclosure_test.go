package web

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// TestFindingDisclosureHTML_inlineStyles checks the Gmail-ready disclosure view:
// the draft markdown is rendered and every tag Gmail keeps on paste carries an
// inline style= attribute, because Gmail strips <style> blocks.
func TestFindingDisclosureHTML_inlineStyles(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{Name: "acme/thing", FullName: "acme/thing"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "Command injection",
		Severity: "High", Status: db.FindingEnriched,
		DisclosureDraft: "## GHSA draft\n\nA **command injection** in `acme/thing` via `arg`.\n\n" +
			"See [advisory](https://example.com/ghsa).\n\n```go\nexec.Command(arg)\n```\n\n> embargo until fixed\n",
	}
	s.DB.Create(&f)

	path := "/findings/" + strconv.FormatUint(uint64(f.ID), 10) + "/disclosure.html"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}

	body := w.Body.String()
	// Gmail drops <style> blocks on paste, so the page must not rely on one.
	if strings.Contains(body, "<style") {
		t.Errorf("page leans on a <style> block Gmail will strip:\n%s", body)
	}
	// Each formatting-bearing tag must carry an inline style.
	wants := []string{
		"<strong style=",
		"<code style=", // inline code
		"<pre style=",  // code block, collapsed from <pre><code>
		"<blockquote style=",
		"<a style=",
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("body missing inline style %q\nbody:\n%s", want, body)
		}
	}
	// The code block's nested <code> is dropped so it doesn't get a box-in-a-box.
	if strings.Contains(body, "</code></pre>") {
		t.Errorf("code block still wraps a nested <code>:\n%s", body)
	}
	// The draft content itself survives the rewrite.
	if !strings.Contains(body, "command injection") {
		t.Errorf("draft body missing from page:\n%s", body)
	}
}

func TestFindingDisclosureHTML_emptyDraftNotFound(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{Name: "acme/thing", FullName: "acme/thing"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "No draft", DisclosureDraft: "   "}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/"+strconv.FormatUint(uint64(f.ID), 10)+"/disclosure.html"))
	if w.Code != 404 {
		t.Errorf("status = %d, want 404 for empty draft", w.Code)
	}
}

func TestFindingDisclosureHTML_missingFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/999999/disclosure.html"))
	if w.Code != 404 {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
