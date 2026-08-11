package web

import (
	"net/http"
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
	// This finding has no suggested recipients, so no To: line is prepended.
	if strings.Contains(body, "To:</strong>") {
		t.Errorf("unexpected To: line for finding without suggested recipients:\n%s", body)
	}
}

// TestFindingDisclosureHTML_suggestedRecipients checks that suggested recipients
// ride above the draft as a To: line (the PVR-less fallback where the draft goes
// out as an email) and that the free-text value is HTML-escaped, not injected raw.
func TestFindingDisclosureHTML_suggestedRecipients(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{Name: "acme/thing", FullName: "acme/thing"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "Command injection",
		DisclosureDraft:     "## GHSA draft\n\nbody.\n",
		SuggestedRecipients: "@alice <alice@x.com> (CODEOWNERS: crypto/*)",
	}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/"+strconv.FormatUint(uint64(f.ID), 10)+"/disclosure.html"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	body := w.Body.String()
	if !strings.Contains(body, "To:</strong>") {
		t.Errorf("body missing To: line:\n%s", body)
	}
	if !strings.Contains(body, "@alice &lt;alice@x.com&gt; (CODEOWNERS: crypto/*)") {
		t.Errorf("recipients not escaped into To: line:\n%s", body)
	}
	if strings.Contains(body, "<alice@x.com>") {
		t.Errorf("raw recipient markup leaked into page:\n%s", body)
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

func TestFindingDisclosureMarkdown_exportsLatestSavedDraft(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{Name: "thing", FullName: "acme/thing"}
	s.DB.Create(&repo)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: discloseSkillName, Status: db.ScanDone,
		Report: `{"ghsa":{"summary":"Stale generated title","description":"old generated draft"}}`,
	}
	s.DB.Create(&scan)
	const latest = "## Summary\n\nLatest analyst edit with `inline code`.\n\n- item\n  - nested\n\n```go\nfmt.Println(\"kept\")\n```"
	f := db.Finding{
		ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "Current finding title",
		DisclosureDraft: latest,
	}
	s.DB.Create(&f)

	path := "/findings/" + strconv.FormatUint(uint64(f.ID), 10) + "/disclosure.md"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Content-Type"); got != "text/markdown; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := w.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment") || !strings.Contains(got, "disclosure") || !strings.Contains(got, ".md") {
		t.Errorf("Content-Disposition = %q", got)
	}
	want := "# Current finding title\n\n" + latest + "\n"
	if got := w.Body.String(); got != want {
		t.Errorf("markdown export did not preserve the latest saved draft\nwant:\n%s\ngot:\n%s", want, got)
	}
	for _, stale := range []string{"Stale generated title", "old generated draft", "Scan metadata", "patched", "preserved"} {
		if strings.Contains(w.Body.String(), stale) {
			t.Errorf("export contains stale or internal generation data %q:\n%s", stale, w.Body)
		}
	}

	const revised = "## Summary\n\nSaved again after generation.\n"
	if err := db.WriteFindingField(s.DB, f.ID, "disclosure_draft", revised, db.SourceAnalyst, ""); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", path))
	if !strings.Contains(w.Body.String(), revised) || strings.Contains(w.Body.String(), latest) {
		t.Errorf("export did not read the latest persisted edit:\n%s", w.Body)
	}
}

func TestFindingDisclosureMarkdown_emptyDraftNotFound(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{Name: "thing"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "No saved draft", DisclosureDraft: "  "}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/"+strconv.FormatUint(uint64(f.ID), 10)+"/disclosure.md"))
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "no disclosure draft") {
		t.Errorf("status/body = %d %q, want explicit 404", w.Code, w.Body.String())
	}
}
