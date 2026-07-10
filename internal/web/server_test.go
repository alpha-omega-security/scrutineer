package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/worker"
)

func newTestServer(t testing.TB) (*Server, func()) {
	t.Helper()
	gdb, err := db.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	q, err := queue.New(sqldb, log, 0)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(gdb, q, log, NewBroker(), &worker.Worker{DB: gdb})
	if err != nil {
		t.Fatal(err)
	}
	s.Backend = worker.HarnessName(worker.ClaudeHarness{})
	s.resolvePURL = func(context.Context, string) string { return "" }
	s.resolveSync = true
	s.prefetchEcosystems = func(uint) {}
	return s, func() { _ = sqldb.Close() }
}

func localReq(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "127.0.0.1:8080"
	return r
}

func requireRepoListRow(t *testing.T, body string, repoID uint) string {
	t.Helper()
	start := strings.Index(body, fmt.Sprintf(`<tr id="repo-%d">`, repoID))
	if start < 0 {
		t.Fatalf("missing repo row %d in body=%s", repoID, body)
	}
	end := strings.Index(body[start:], "</tr>")
	if end < 0 {
		t.Fatalf("unterminated repo row %d in body=%s", repoID, body[start:])
	}
	return body[start : start+end]
}

func TestSeverityOrder(t *testing.T) {
	want := "CASE severity WHEN 'Low' THEN 3 WHEN 'Medium' THEN 2 WHEN 'High' THEN 1 WHEN 'Critical' THEN 0 ELSE 4 END"
	if severityOrder != want {
		t.Errorf("severityOrder = %q, want %q", severityOrder, want)
	}
}

func TestLoadRepoMap(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	r1 := db.Repository{URL: "https://example.com/a", Name: "a"}
	r2 := db.Repository{URL: "https://example.com/b", Name: "b"}
	s.DB.Create(&r1)
	s.DB.Create(&r2)

	findings := []db.Finding{{RepositoryID: r1.ID}, {RepositoryID: r2.ID}, {RepositoryID: r1.ID}}
	m := loadRepoMap(s.DB, findings, findingRepoID)
	if len(m) != 2 || m[r1.ID].Name != "a" || m[r2.ID].Name != "b" {
		t.Errorf("findings map = %+v", m)
	}

	advisories := []db.Advisory{{RepositoryID: r2.ID}}
	m = loadRepoMap(s.DB, advisories, advisoryRepoID)
	if len(m) != 1 || m[r2.ID].Name != "b" {
		t.Errorf("advisories map = %+v", m)
	}
}

func TestLoadByID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)

	r := localReq("GET", "/")
	r.SetPathValue("id", fmt.Sprint(repo.ID))
	w := httptest.NewRecorder()
	got, ok := loadByID[db.Repository](s, w, r)
	if !ok || got.ID != repo.ID || got.Name != "x" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}

	r.SetPathValue("id", "999999")
	w = httptest.NewRecorder()
	if _, ok := loadByID[db.Repository](s, w, r); ok || w.Code != http.StatusNotFound {
		t.Errorf("missing id: ok=%v code=%d, want false/404", ok, w.Code)
	}

	// A non-numeric id must 404 before reaching the DB rather than being
	// spliced into the GORM inline condition as raw SQL (the SQLi this
	// fix closes).
	r.SetPathValue("id", "1; DROP TABLE repositories")
	w = httptest.NewRecorder()
	if _, ok := loadByID[db.Repository](s, w, r); ok || w.Code != http.StatusNotFound {
		t.Errorf("injection id: ok=%v code=%d, want false/404", ok, w.Code)
	}
}

// TestFindingShow_nonNumericID covers the same SQLi guard on a handler
// that loads via Preload("...").First, exercising the second code path
// (handlers that parse the id inline rather than through loadByID).
func TestFindingShow_nonNumericID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings/abc"))
	if w.Code != http.StatusNotFound {
		t.Errorf("non-numeric finding id: code=%d, want 404", w.Code)
	}
}

func TestRepoList_batchedFindingsCountAcrossRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	mk := func(name string, findings int) {
		repo := db.Repository{URL: "https://example.com/" + name, Name: name}
		s.DB.Create(&repo)
		if findings > 0 {
			scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
			s.DB.Create(&scan)
			for i := 0; i < findings; i++ {
				s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
					Title: fmt.Sprintf("F%d", i), Severity: "High"})
			}
		}
	}
	mk("alpha", 3)
	mk("bravo", 0)
	mk("charlie", 7)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	// Every repo's count must be rendered correctly in the rendered
	// table, even though they all come out of a single grouped query.
	for _, want := range []struct{ repo, count string }{
		{"alpha", `badge-destructive">3</span>`},
		{"bravo", `badge-secondary">0</span>`},
		{"charlie", `badge-destructive">7</span>`},
	} {
		if !strings.Contains(body, want.count) {
			t.Errorf("missing %s count %q in body", want.repo, want.count)
		}
	}
}

func TestRepoList_findingsCountIgnoresClosedFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/statuses", Name: "statuses"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)

	statuses := []db.FindingLifecycle{
		db.FindingNew,
		db.FindingEnriched,
		db.FindingTriaged,
		db.FindingReady,
		db.FindingReported,
		db.FindingAcknowledged,
		db.FindingFixed,
		db.FindingPublished,
		db.FindingRejected,
		db.FindingDuplicate,
	}
	for i, status := range statuses {
		s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
			Title: fmt.Sprintf("finding-%d", i), Severity: "High", Status: status})
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	row := requireRepoListRow(t, w.Body.String(), repo.ID)
	if !strings.Contains(row, `<span class="badge-destructive">6</span>`) {
		t.Errorf("expected only six open findings in repo row, row=%s", row)
	}
	if strings.Contains(row, `<span class="badge-destructive">10</span>`) {
		t.Errorf("closed findings should not be counted, row=%s", row)
	}
}

func TestMaintainersIndex_rendersFindingsCountAndDNCBadge(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar.git", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "A", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "B", Severity: "Medium"})

	alice := db.Maintainer{Login: "alice", Name: "Alice", Status: db.MaintainerActive, DoNotContact: true}
	s.DB.Create(&alice)
	bob := db.Maintainer{Login: "bob", Name: "Bob", Status: db.MaintainerActive}
	s.DB.Create(&bob)
	if err := s.DB.Model(&repo).Association("Maintainers").Append([]db.Maintainer{alice, bob}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/maintainers"))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()

	// Both maintainers share the one repo and its two findings, so both
	// rows should render the "2" findings badge.
	if strings.Count(body, `<span class="badge-destructive">2</span>`) < 2 {
		t.Errorf("expected two maintainer rows with findings=2 badge")
	}
	// Alice carries the DNC badge; Bob should not.
	if !strings.Contains(body, `data-tooltip="Do not contact">DNC`) {
		t.Errorf("missing DNC badge for alice")
	}
}

// Imports show in the Findings tab, so they must also count toward the
// maintainer index badge. Regression for the aliasedFindingsScanFilter drift:
// the count query once filtered skill_name only and silently dropped imports.
func TestMaintainersIndex_countsImportedFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar.git", Name: "bar"}
	s.DB.Create(&repo)

	// One deep-dive audit finding and one operator-import finding. An import
	// scan carries the producing tool's name as skill_name with kind=import —
	// the same shape import.go writes — so a skill_name-only filter misses it.
	dd := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&dd)
	imp := db.Scan{RepositoryID: repo.ID, Kind: "import", Status: db.ScanDone, SkillName: "trivy"}
	s.DB.Create(&imp)
	// A scanner finding stays out of the count — per-repo lint noise.
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: dd.ID, RepositoryID: repo.ID, Title: "audit", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: imp.ID, RepositoryID: repo.ID, Title: "imported", Severity: "Medium"})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "scanner", Severity: "Low"})

	alice := db.Maintainer{Login: "alice", Name: "Alice", Status: db.MaintainerActive}
	s.DB.Create(&alice)
	if err := s.DB.Model(&repo).Association("Maintainers").Append([]db.Maintainer{alice}); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/maintainers"))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	// deep-dive + import = 2; the semgrep scanner finding is excluded. Before
	// the fix this rendered 1 (import dropped); a scanner leak would render 3.
	if !strings.Contains(body, `<span class="badge-destructive">2</span>`) {
		t.Errorf("expected maintainer findings badge of 2 (deep-dive + import, scanner excluded); body=%s", body)
	}
}

func flashFrom(t *testing.T, w *httptest.ResponseRecorder) Flash {
	t.Helper()
	r := &http.Request{Header: http.Header{"Cookie": w.Header().Values("Set-Cookie")}}
	c, err := r.Cookie("flash")
	if err != nil {
		t.Fatalf("no flash cookie set: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(c.Value)
	var f Flash
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("decode flash: %v", err)
	}
	return f
}

func TestRenderScanStatus_OOBRowAndToast(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar.git", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "audit", Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High"})

	out := s.renderScanStatus(scan.ID)

	if !strings.Contains(out, fmt.Sprintf(`id="scan-%d"`, scan.ID)) {
		t.Errorf("missing row id: %s", out)
	}
	if !strings.Contains(out, `hx-swap-oob="true"`) {
		t.Error("row not marked for OOB swap")
	}
	if !strings.Contains(out, `hx-swap-oob="afterbegin:#toaster"`) {
		t.Error("toast not targeted at #toaster")
	}
	if !strings.Contains(out, "audit done") {
		t.Errorf("toast title missing skill+status: %s", out)
	}
	if !strings.Contains(out, "bar") {
		t.Error("toast missing repo name")
	}
}

func TestRepoNew_fallbackPages(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	for _, tc := range []struct{ path, want string }{
		{"/repositories/new", "Add repository"},
		{"/repositories/new?bulk=1", "Bulk import"},
		{"/sboms/new", "Upload SBOM"},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		req.Host = testHost
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d", tc.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("%s: body missing %q", tc.path, tc.want)
		}
	}
}

func TestRepoCreate_htmxInvalidURL_rendersInlineAlert(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"url": {"not-a-url"}}
	r := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	r.Host = testHost
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("HX-Request", "true")

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 (htmx error path renders inline, no redirect)", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("unexpected Location %q (htmx error path must not redirect)", loc)
	}
	if hx := w.Header().Get("HX-Redirect"); hx != "" {
		t.Errorf("unexpected HX-Redirect %q (htmx error path must not redirect)", hx)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type %q, want text/html", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, `id="add-repo-alert"`) {
		t.Errorf("body missing inline alert target:\n%s", body)
	}
	if !strings.Contains(body, "Invalid repository URL") {
		t.Errorf("body missing error title:\n%s", body)
	}

	var n int64
	s.DB.Model(&db.Repository{}).Count(&n)
	if n != 0 {
		t.Errorf("repository count = %d, want 0 (invalid input must not persist)", n)
	}
}

func TestFlash_roundtrip(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	rec := httptest.NewRecorder()
	setFlash(rec, Flash{Category: "success", Title: "Imported", Description: "3 added"})

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = testHost
	req.Header.Set("Cookie", rec.Header().Get("Set-Cookie"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Imported") || !strings.Contains(body, "3 added") {
		t.Error("flash not rendered into page body")
	}
	var cleared bool
	for _, sc := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, "flash=") && strings.Contains(sc, "Max-Age=0") {
			cleared = true
		}
	}
	if !cleared {
		t.Error("flash cookie not cleared after render")
	}
}

func TestNavKey(t *testing.T) {
	cases := map[string]string{
		"/":               "repos",
		"/repositories/7": "repos",
		"/findings":       "findings",
		"/findings/42":    "findings",
		"/benchmark":      "benchmark",
		"/scans/1":        "scans",
		"/sboms":          "sboms",
		"/usage":          "usage",
	}
	for path, want := range cases {
		if got := navKey(path); got != want {
			t.Errorf("navKey(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestSidebar_rendersAriaCurrent(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	req := httptest.NewRequest("GET", "/findings", nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `href="/findings" aria-current="page"`) {
		t.Error("findings link missing aria-current")
	}
	if strings.Contains(body, `href="/" aria-current="page"`) {
		t.Error("repos link should not be current on /findings")
	}
}

func TestRedirect_branchesOnHXRequest(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	plain := httptest.NewRequest("POST", "/x", nil)
	w := httptest.NewRecorder()
	s.redirect(w, plain, "/target")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/target" {
		t.Errorf("plain: code=%d Location=%q", w.Code, w.Header().Get("Location"))
	}

	hx := httptest.NewRequest("POST", "/x", nil)
	hx.Header.Set("HX-Request", "true")
	w = httptest.NewRecorder()
	s.redirect(w, hx, "/target")
	if w.Code != http.StatusNoContent || w.Header().Get("HX-Redirect") != "/target" {
		t.Errorf("hx: code=%d HX-Redirect=%q", w.Code, w.Header().Get("HX-Redirect"))
	}
	if w.Header().Get("Location") != "" {
		t.Errorf("hx: unexpected Location %q", w.Header().Get("Location"))
	}
}

func TestMaintainerDoNotContactToggle(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	m := db.Maintainer{Login: "alice", Name: "Alice", Status: db.MaintainerActive}
	s.DB.Create(&m)

	post := func(value string) {
		form := url.Values{"value": {value}}
		r := httptest.NewRequest("POST", fmt.Sprintf("/maintainers/%d/do-not-contact", m.ID), strings.NewReader(form.Encode()))
		r.Host = testHost
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("value=%s status %d: %s", value, w.Code, w.Body)
		}
	}
	post("true")
	var got db.Maintainer
	s.DB.First(&got, m.ID)
	if !got.DoNotContact {
		t.Error("expected DoNotContact=true after toggle")
	}
	post("false")
	s.DB.First(&got, m.ID)
	if got.DoNotContact {
		t.Error("expected DoNotContact=false after clear")
	}
}

func TestRepoDisclosureChannel_setAndClear(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/foo/bar.git", Name: "bar"}
	s.DB.Create(&repo)

	post := func(v string) {
		form := url.Values{"disclosure_channel": {v}}
		r := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/disclosure-channel", repo.ID), strings.NewReader(form.Encode()))
		r.Host = testHost
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
	}
	post("security@example.org")
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.DisclosureChannel != "security@example.org" {
		t.Errorf("got %q", got.DisclosureChannel)
	}
	post("")
	s.DB.First(&got, repo.ID)
	if got.DisclosureChannel != "" {
		t.Errorf("empty submission should clear; got %q", got.DisclosureChannel)
	}
}

func TestRepoList_findingsCountIsRepoWideNotLastScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar.git", Name: "bar"}
	s.DB.Create(&repo)

	// Older scan produces two findings.
	deep := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&deep)
	s.DB.Create(&db.Finding{ScanID: deep.ID, RepositoryID: repo.ID, Title: "SSRF", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: deep.ID, RepositoryID: repo.ID, Title: "XSS", Severity: "Medium"})

	// Newer scan is repo-overview — no findings, and it is now the
	// LastScan on the repo.
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "repo-overview"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	// The row for this repo should show "2" in a findings badge — the
	// repo-wide total — not "0" that a naive LastScan.FindingsCount
	// read would have produced.
	if !strings.Contains(body, `<span class="badge-destructive">2</span>`) {
		t.Errorf("expected findings badge showing 2, body=%s", body)
	}
	if strings.Contains(body, `<span class="badge-secondary">0</span>`) {
		t.Errorf("repo with two findings should not render a 0 badge")
	}
}

func TestRepoList_sortByFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	mk := func(slug string, n int) db.Repository {
		repo := db.Repository{URL: "https://x/" + slug, Name: slug}
		s.DB.Create(&repo)
		if n == 0 {
			return repo
		}
		scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
		s.DB.Create(&scan)
		for i := 0; i < n; i++ {
			s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
				Title: fmt.Sprintf("F%d", i), Severity: "High", Status: db.FindingNew})
		}
		return repo
	}
	mkClosed := func(slug string, n int) db.Repository {
		repo := db.Repository{URL: "https://x/" + slug, Name: slug}
		s.DB.Create(&repo)
		scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
		s.DB.Create(&scan)
		for i := 0; i < n; i++ {
			s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
				Title: fmt.Sprintf("closed-%d", i), Severity: "High", Status: db.FindingFixed})
		}
		return repo
	}
	mk("two-findings", 2)
	mk("zero-findings", 0)
	mk("five-findings", 5)
	one := mk("one-finding", 1)
	closed := mkClosed("closed-findings", 10)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/?sort=findings"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	order := []string{"x/five-findings", "x/two-findings", "x/one-finding", "x/zero-findings"}
	last := -1
	for _, slug := range order {
		i := strings.Index(body, slug)
		if i < 0 {
			t.Fatalf("missing %q in body", slug)
		}
		if i < last {
			t.Errorf("%q out of order (want descending by finding count)", slug)
		}
		last = i
	}
	closedIndex := strings.Index(body, "x/closed-findings")
	oneIndex := strings.Index(body, "x/one-finding")
	if closedIndex < 0 {
		t.Fatalf("missing closed-findings in body")
	}
	if closedIndex < oneIndex {
		t.Errorf("repo with only closed findings sorted above open findings")
	}
	closedRow := requireRepoListRow(t, body, closed.ID)
	if !strings.Contains(closedRow, `<span class="badge-secondary">0</span>`) {
		t.Errorf("expected closed-only repo to show zero findings, row=%s", closedRow)
	}
	oneRow := requireRepoListRow(t, body, one.ID)
	if !strings.Contains(oneRow, `<span class="badge-destructive">1</span>`) {
		t.Errorf("expected one open finding, row=%s", oneRow)
	}
}

func TestDistinctLanguages_splitsJoinedColumn(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Repository{URL: "https://x/1", Name: "a", Languages: "Kotlin, Java, Prolog"})
	s.DB.Create(&db.Repository{URL: "https://x/2", Name: "b", Languages: "Kotlin, Prolog, Java"})
	s.DB.Create(&db.Repository{URL: "https://x/3", Name: "c", Languages: "Go"})
	s.DB.Create(&db.Repository{URL: "https://x/4", Name: "d", Languages: "Go, Python"})
	s.DB.Create(&db.Repository{URL: "https://x/5", Name: "e", Languages: ""})

	got := distinctLanguages(s.DB)
	want := []string{"Go", "Java", "Kotlin", "Prolog", "Python"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRepoList_languageFilterMatchesWithinList(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Repository{URL: "https://x/only-java", Name: "a", Languages: "Java"})
	s.DB.Create(&db.Repository{URL: "https://x/first-java", Name: "b", Languages: "Java, Python"})
	s.DB.Create(&db.Repository{URL: "https://x/mid-java", Name: "c", Languages: "Kotlin, Java, Prolog"})
	s.DB.Create(&db.Repository{URL: "https://x/last-java", Name: "d", Languages: "Python, Java"})
	s.DB.Create(&db.Repository{URL: "https://x/jsrepo", Name: "e", Languages: "JavaScript"})
	s.DB.Create(&db.Repository{URL: "https://x/gorepo", Name: "f", Languages: "Go"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/?language=Java"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	for _, want := range []string{"x/only-java", "x/first-java", "x/mid-java", "x/last-java"} {
		if !strings.Contains(body, want) {
			t.Errorf("language=Java should include %q", want)
		}
	}
	// "Java" must not substring-match "JavaScript".
	if strings.Contains(body, "x/jsrepo") {
		t.Errorf("language=Java wrongly matched JavaScript repo")
	}
	if strings.Contains(body, "x/gorepo") {
		t.Errorf("language=Java wrongly matched Go repo")
	}
}

func TestRepoSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Repository{URL: "https://github.com/rails/rails", Name: "rails", FullName: "rails/rails", Description: "Ruby on Rails"})
	s.DB.Create(&db.Repository{URL: "https://github.com/rubygems/rubygems", Name: "rubygems", FullName: "rubygems/rubygems", Description: "gem package manager"})
	s.DB.Create(&db.Repository{URL: "https://github.com/rails-api/jbuilder", Name: "jbuilder", FullName: "rails-api/jbuilder", Description: "JSON builder"})

	cases := []struct {
		query string
		match []string
		drop  []string
	}{
		{query: "rails", match: []string{"rails/rails", "rails-api/jbuilder"}, drop: []string{"rubygems/rubygems"}},
		{query: "package", match: []string{"rubygems/rubygems"}, drop: []string{"rails/rails", "rails-api/jbuilder"}},
		{query: "jbuilder", match: []string{"rails-api/jbuilder"}, drop: []string{"rails/rails", "rubygems/rubygems"}},
		{query: "NOPE_NOPE_NOPE", match: nil, drop: []string{"rails/rails", "rubygems/rubygems", "rails-api/jbuilder"}},
	}

	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/?q="+url.QueryEscape(tc.query)))
		if w.Code != 200 {
			t.Fatalf("q=%q status %d: %s", tc.query, w.Code, w.Body)
		}
		body := w.Body.String()
		for _, want := range tc.match {
			if !strings.Contains(body, want) {
				t.Errorf("q=%q: body missing %q", tc.query, want)
			}
		}
		for _, drop := range tc.drop {
			if strings.Contains(body, drop) {
				t.Errorf("q=%q: body should not contain %q", tc.query, drop)
			}
		}
		if len(tc.match) == 0 && !strings.Contains(body, "No matches") {
			t.Errorf("q=%q: empty-match body missing 'No matches' state", tc.query)
		}
	}
}

func TestRepoSearchPreservesOtherFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Repository{URL: "https://github.com/rails/rails", Name: "rails", Languages: "Ruby"})
	s.DB.Create(&db.Repository{URL: "https://github.com/go-rails/something", Name: "go-rails", Languages: "Go"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/?q=rails&language=Ruby"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "rails/rails") || strings.Contains(body, "go-rails/something") {
		t.Errorf("q=rails language=Ruby did not combine correctly. body=%s", body)
	}
}

func TestFindingsSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "SSRF in image fetcher",
		Severity: "High", Location: "fetch.go:42", CWE: "CWE-918"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "OS command injection",
		Severity: "Critical", Location: "shell.go:10", CWE: "CWE-78", CVEID: "CVE-2026-1"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "Stored XSS",
		Severity: "Medium", Location: "view.go:5", CWE: "CWE-79"})

	cases := map[string][]string{
		"SSRF":           {"SSRF in image fetcher"},
		"command":        {"OS command injection"},
		"shell.go":       {"OS command injection"},
		"CWE-79":         {"Stored XSS"},
		"CVE-2026-1":     {"OS command injection"},
		"NOPE_NOPE_NOPE": nil,
	}
	for q, want := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/findings?q="+url.QueryEscape(q)))
		if w.Code != 200 {
			t.Errorf("q=%q status %d", q, w.Code)
			continue
		}
		body := w.Body.String()
		for _, title := range want {
			if !strings.Contains(body, title) {
				t.Errorf("q=%q missing %q", q, title)
			}
		}
		if len(want) == 0 && !strings.Contains(body, "No matches") {
			t.Errorf("q=%q empty state missing", q)
		}
	}
}

func TestFindings_categoryFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "OS command injection",
		Severity: "Critical", Location: "shell.go:10", CWE: "CWE-78"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "Use-after-free in parser",
		Severity: "High", Location: "parse.go:7", CWE: "CWE-416"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "Unlabelled finding",
		Severity: "Low", Location: "misc.go:1"})

	cases := []struct {
		category string
		want     []string
		missing  []string
	}{
		{"Injection", []string{"OS command injection"}, []string{"Use-after-free in parser", "Unlabelled finding"}},
		{"Memory Safety", []string{"Use-after-free in parser"}, []string{"OS command injection", "Unlabelled finding"}},
		{UncategorizedCWE, []string{"Unlabelled finding"}, []string{"OS command injection", "Use-after-free in parser"}},
		{"Not A Real Category", nil, []string{"OS command injection", "Use-after-free in parser", "Unlabelled finding"}},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/findings?category="+url.QueryEscape(tc.category)))
		if w.Code != 200 {
			t.Errorf("category=%q status %d", tc.category, w.Code)
			continue
		}
		body := w.Body.String()
		for _, title := range tc.want {
			if !strings.Contains(body, title) {
				t.Errorf("category=%q missing %q", tc.category, title)
			}
		}
		for _, title := range tc.missing {
			if strings.Contains(body, ">"+title+"</a>") {
				t.Errorf("category=%q should not include %q", tc.category, title)
			}
		}
	}
}

func TestFindings_statusFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "fresh finding",
		Severity: "High", Status: db.FindingNew})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "triaged finding",
		Severity: "High", Status: db.FindingTriaged})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "fixed finding",
		Severity: "High", Status: db.FindingFixed})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "published finding",
		Severity: "High", Status: db.FindingPublished})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rejected finding",
		Severity: "High", Status: db.FindingRejected})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "duplicate finding",
		Severity: "High", Status: db.FindingDuplicate})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings"))
	if w.Code != 200 {
		t.Fatalf("default status code %d", w.Code)
	}
	body := w.Body.String()
	for _, title := range []string{"fresh finding", "triaged finding"} {
		if !strings.Contains(body, ">"+title+"</a>") {
			t.Errorf("default listing missing %q", title)
		}
	}
	for _, title := range []string{"fixed finding", "published finding", "rejected finding", "duplicate finding"} {
		if strings.Contains(body, ">"+title+"</a>") {
			t.Errorf("default listing should hide closed finding %q", title)
		}
	}
	if !strings.Contains(body, ">Open</a>") || !strings.Contains(body, "status=all") {
		t.Error("status dropdown should expose Open and status=all options")
	}

	cases := []struct {
		status  string
		want    []string
		missing []string
	}{
		{"all", []string{"fresh finding", "triaged finding", "fixed finding", "published finding", "rejected finding", "duplicate finding"}, nil},
		{"new", []string{"fresh finding"}, []string{"triaged finding", "fixed finding", "published finding", "rejected finding", "duplicate finding"}},
		{"triaged", []string{"triaged finding"}, []string{"fresh finding", "fixed finding", "published finding", "rejected finding", "duplicate finding"}},
		{"fixed", []string{"fixed finding"}, []string{"fresh finding", "triaged finding", "published finding", "rejected finding", "duplicate finding"}},
		{"published", []string{"published finding"}, []string{"fresh finding", "triaged finding", "fixed finding", "rejected finding", "duplicate finding"}},
		{"rejected", []string{"rejected finding"}, []string{"fresh finding", "triaged finding", "fixed finding", "published finding", "duplicate finding"}},
		{"duplicate", []string{"duplicate finding"}, []string{"fresh finding", "triaged finding", "fixed finding", "published finding", "rejected finding"}},
	}
	for _, tc := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/findings?status="+url.QueryEscape(tc.status)))
		if w.Code != 200 {
			t.Errorf("status=%q status code %d", tc.status, w.Code)
			continue
		}
		body := w.Body.String()
		for _, title := range tc.want {
			if !strings.Contains(body, ">"+title+"</a>") {
				t.Errorf("status=%q missing %q", tc.status, title)
			}
		}
		for _, title := range tc.missing {
			if strings.Contains(body, ">"+title+"</a>") {
				t.Errorf("status=%q should not include %q", tc.status, title)
			}
		}
	}

	// The status filter is preserved across the other filter links.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings?status=new"))
	body = w.Body.String()
	if !strings.Contains(body, "severity=High&status=new&category=") {
		t.Error("severity dropdown links should carry status=new")
	}
}

func TestPackagesSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "lodash", Ecosystem: "npm", PURL: "pkg:npm/lodash"})
	s.DB.Create(&db.Package{RepositoryID: repo.ID, Name: "express", Ecosystem: "npm", PURL: "pkg:npm/express", Licenses: "MIT"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/packages?q=lodash"))
	body := w.Body.String()
	if !strings.Contains(body, "lodash") || strings.Contains(body, "express") {
		t.Errorf("name search: %s", body)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/packages?q=MIT"))
	body = w.Body.String()
	if !strings.Contains(body, "express") {
		t.Errorf("license search did not find express: %s", body)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/packages?q=NOPE_NOPE_NOPE"))
	if !strings.Contains(w.Body.String(), "No matches") {
		t.Error("empty-match packages: no empty state")
	}
}

func TestOrgsList_aggregatesByOwner(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	mk := func(owner, name string) db.Repository {
		r := db.Repository{URL: "https://example.com/" + owner + "/" + name, Name: name, Owner: owner}
		s.DB.Create(&r)
		return r
	}
	a1 := mk("acme", "one")
	mk("acme", "two")
	b1 := mk("globex", "service")

	scan := db.Scan{RepositoryID: a1.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: a1.ID, Title: "A", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: a1.ID, Title: "B", Severity: "Medium"})

	bscan := db.Scan{RepositoryID: b1.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&bscan)
	s.DB.Create(&db.Finding{ScanID: bscan.ID, RepositoryID: b1.ID, Title: "C", Severity: "Low"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	for _, want := range []string{"acme", "globex",
		`<span class="badge-destructive">2</span>`,
		`<span class="badge-destructive">1</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// The orgs index finding total is a sibling of the maintainer count and once
// drifted the same way: imports showed in the Findings tab but were filtered
// out of the cross-org total. Regression for aliasedFindingsScanFilter.
func TestOrgsList_countsImportedFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// Single owner, single repo (Repos column = 1, so a "2" badge can only be
	// the findings total). One deep-dive finding plus one import finding; a
	// zizmor scanner finding stays in the per-repo Scanners tab, not the total.
	repo := db.Repository{URL: "https://example.com/acme/svc", Name: "svc", Owner: "acme"}
	s.DB.Create(&repo)
	dd := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&dd)
	imp := db.Scan{RepositoryID: repo.ID, Kind: "import", Status: db.ScanDone, SkillName: "grype"}
	s.DB.Create(&imp)
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "zizmor"}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: dd.ID, RepositoryID: repo.ID, Title: "audit", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: imp.ID, RepositoryID: repo.ID, Title: "imported", Severity: "Medium"})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "scanner", Severity: "Low"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	// deep-dive + import = 2; the zizmor scanner finding is excluded. Before
	// the fix this rendered 1 (import dropped); a scanner leak would render 3.
	if !strings.Contains(body, `<span class="badge-destructive">2</span>`) {
		t.Errorf("expected org findings total badge of 2 (deep-dive + import, scanner excluded); body=%s", body)
	}
}

// TestIndexTotals_countVulnScanFindings pins vuln-scan's inclusion in the
// maintainers/orgs index aggregates: aliasedFindingsScanFilter was widened to
// s.skill_name IN (?, ?) so vuln-scan findings count toward the cross-repo
// totals alongside deep-dive, while scanner output stays excluded. It exercises
// the second bound placeholder (vulnScanSkillName) in BOTH aggregate queries —
// the path TestVulnScanBucketedAsFinding (repo bucket + /findings toggle) and
// the import-count tests (first placeholder + kind='import') do not reach.
func TestIndexTotals_countVulnScanFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// One owner + one maintainer on a single repo. Two vuln-scan findings count
	// toward both index totals; a semgrep scanner finding stays out. A "2" badge
	// is unambiguous (Repos column = 1) and separates the correct total from a
	// regression: 0 if vuln-scan were treated as a scanner, 3 if semgrep leaked.
	repo := db.Repository{URL: "https://example.com/acme/svc", Name: "svc", Owner: "acme"}
	s.DB.Create(&repo)
	vs := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: vulnScanSkillName}
	s.DB.Create(&vs)
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: vs.ID, RepositoryID: repo.ID, Title: "vuln-scan a", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: vs.ID, RepositoryID: repo.ID, Title: "vuln-scan b", Severity: "Medium"})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "scanner", Severity: "Low"})

	alice := db.Maintainer{Login: "alice", Name: "Alice", Status: db.MaintainerActive}
	s.DB.Create(&alice)
	if err := s.DB.Model(&repo).Association("Maintainers").Append([]db.Maintainer{alice}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/maintainers", "/orgs"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", path))
		if w.Code != 200 {
			t.Fatalf("GET %s: status %d", path, w.Code)
		}
		if body := w.Body.String(); !strings.Contains(body, `<span class="badge-destructive">2</span>`) {
			t.Errorf("GET %s: want vuln-scan findings total badge of 2 (semgrep excluded); body=%s", path, body)
		}
	}
}

func TestOrgsList_sortOptions(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	mk := func(owner, name string, findings int) {
		r := db.Repository{URL: "https://example.com/" + owner + "/" + name, Name: name, Owner: owner}
		s.DB.Create(&r)
		if findings > 0 {
			scan := db.Scan{RepositoryID: r.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
			s.DB.Create(&scan)
			for i := 0; i < findings; i++ {
				s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: r.ID,
					Title: fmt.Sprintf("F-%d", i), Severity: "High"})
			}
		}
	}
	// acme: 1 repo, 5 findings. globex: 3 repos, 1 finding. umbrella: 2 repos, 0 findings.
	// Zebra has a leading capital so a byte-wise sort would float it above acme.
	mk("acme", "one", 5)
	mk("globex", "a", 0)
	mk("globex", "b", 1)
	mk("globex", "c", 0)
	mk("umbrella", "x", 0)
	mk("umbrella", "y", 0)
	mk("Zebra", "z", 0)

	orderFromBody := func(body string, owners ...string) []string {
		type pos struct {
			owner string
			idx   int
		}
		positions := make([]pos, 0, len(owners))
		for _, o := range owners {
			if i := strings.Index(body, `>`+o+`<`); i >= 0 {
				positions = append(positions, pos{o, i})
			}
		}
		sort.Slice(positions, func(i, j int) bool { return positions[i].idx < positions[j].idx })
		out := make([]string, len(positions))
		for i, p := range positions {
			out[i] = p.owner
		}
		return out
	}

	owners := []string{"acme", "globex", "umbrella", "Zebra"}
	for _, tc := range []struct {
		sort string
		want []string
	}{
		{"name", []string{"acme", "globex", "umbrella", "Zebra"}},
		{"findings", []string{"acme", "globex"}}, // 5 > 1; zero-finding orgs are unordered among themselves
		{"repos", []string{"globex", "umbrella"}},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/orgs?sort="+tc.sort))
		if w.Code != 200 {
			t.Fatalf("sort=%s status %d", tc.sort, w.Code)
		}
		got := orderFromBody(w.Body.String(), owners...)
		got = got[:len(tc.want)]
		if !stringsEqual(got, tc.want) {
			t.Errorf("sort=%s: got %v, want %v", tc.sort, got, tc.want)
		}
	}
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOrgShow_rendersRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r1 := db.Repository{URL: "https://example.com/acme/one", Name: "one", Owner: "acme", Languages: "Go"}
	s.DB.Create(&r1)
	r2 := db.Repository{URL: "https://example.com/acme/two", Name: "two", Owner: "acme", Languages: "Ruby"}
	s.DB.Create(&r2)
	scan := db.Scan{RepositoryID: r1.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: r1.ID, Title: "SSRF in fetch", Severity: "High"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/acme"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"one", "two", "Go", "Ruby", "SSRF in fetch", `href="/orgs"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestOrgShow_findingsTabSortsBySeverity(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r := db.Repository{URL: "https://example.com/acme/web", Name: "web", Owner: "acme"}
	s.DB.Create(&r)
	scan := db.Scan{RepositoryID: r.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)
	// Create in the wrong order on purpose, so id-desc would place Low
	// above Medium and Medium above High.
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: r.ID, Title: "LOW-ROW", Severity: "Low"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: r.ID, Title: "MED-ROW", Severity: "Medium"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: r.ID, Title: "HIGH-ROW", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: r.ID, Title: "CRIT-ROW", Severity: "Critical"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/acme"))
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	order := []string{"CRIT-ROW", "HIGH-ROW", "MED-ROW", "LOW-ROW"}
	lastIdx := -1
	for _, title := range order {
		idx := strings.Index(body, title)
		if idx < 0 {
			t.Fatalf("missing %q in body", title)
		}
		if idx < lastIdx {
			t.Errorf("findings out of severity order: %v rendered in wrong position", order)
		}
		lastIdx = idx
	}
}

func TestOrgShow_excludesScannerFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/acme/svc", Name: "svc", Owner: "acme"}
	s.DB.Create(&repo)
	dd := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&dd)
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: dd.ID, RepositoryID: repo.ID, Title: "audit-only", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "semgrep-only", Severity: "High"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/acme"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "audit-only") {
		t.Error("org show should include deep-dive findings")
	}
	if strings.Contains(body, "semgrep-only") {
		t.Error("org show should hide scanner findings; visit the repo Scanners tab instead")
	}
	// Per-repo Findings column should count 1 (audit-only), not 2.
	if !strings.Contains(body, `<span class="badge-destructive">1</span>`) {
		t.Errorf("per-repo finding count should be 1 (deep-dive only); body=%s", body)
	}
}

func TestOrgShow_unknownIs404(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/nope"))
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestFindings_ownerFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	a := db.Repository{URL: "https://example.com/acme/one", Name: "one", Owner: "acme"}
	s.DB.Create(&a)
	g := db.Repository{URL: "https://example.com/globex/svc", Name: "svc", Owner: "globex"}
	s.DB.Create(&g)
	sa := db.Scan{RepositoryID: a.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&sa)
	sg := db.Scan{RepositoryID: g.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: sa.ID, RepositoryID: a.ID, Title: "acme-only finding", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: g.ID, Title: "globex-only finding", Severity: "High"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings?owner=acme"))
	body := w.Body.String()
	if !strings.Contains(body, "acme-only finding") || strings.Contains(body, "globex-only finding") {
		t.Errorf("owner filter failed: %s", body)
	}
}

func TestFindings_missedFilterAndBadge(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "still-present finding",
		Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "possibly-fixed finding",
		Severity: "High", MissedCount: 2, LastMissedScanID: scan.ID})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "closed-missed finding",
		Severity: "High", Status: db.FindingFixed, MissedCount: 1, LastMissedScanID: scan.ID})

	// Unfiltered: both visible, missed one shows the count, toolbar shows total.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings"))
	body := w.Body.String()
	if !strings.Contains(body, "still-present finding") || !strings.Contains(body, "possibly-fixed finding") {
		t.Fatalf("unfiltered list missing rows: %s", body)
	}
	if !strings.Contains(body, "not seen 2x") {
		t.Error("missed-count marker not rendered on row")
	}
	if !strings.Contains(body, "Not seen on rescan (1)") {
		t.Error("toolbar should show total open findings with missed_count > 0")
	}

	// ?missed=1: only the missed finding.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings?missed=1"))
	body = w.Body.String()
	if strings.Contains(body, "still-present finding") {
		t.Error("?missed=1 should hide findings with missed_count = 0")
	}
	if !strings.Contains(body, "possibly-fixed finding") {
		t.Error("?missed=1 should show findings with missed_count > 0")
	}
	if strings.Contains(body, "closed-missed finding") {
		t.Error("?missed=1 should still hide closed findings by default")
	}
	// Severity/sort links preserve the missed filter.
	if !strings.Contains(body, "severity=High&status=&category=&sort=newest&missed=1") {
		t.Error("severity dropdown links should carry missed=1")
	}

	// Explicit closed-status filters count and list closed missed findings.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings?status=fixed&missed=1"))
	body = w.Body.String()
	if !strings.Contains(body, "closed-missed finding") || strings.Contains(body, "possibly-fixed finding") {
		t.Errorf("fixed missed filter should show only fixed missed findings: %s", body)
	}
	if !strings.Contains(body, "Not seen on rescan (1)") {
		t.Error("missed badge should count fixed missed findings under status=fixed")
	}
}

func TestFindings_scannerToggle(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/sc", Name: "sc"}
	s.DB.Create(&repo)
	dd := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&dd)
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	s.DB.Create(&sg)
	zz := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "zizmor"}
	s.DB.Create(&zz)
	s.DB.Create(&db.Finding{ScanID: dd.ID, RepositoryID: repo.ID, Title: "audit-finding", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "semgrep-finding", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: zz.ID, RepositoryID: repo.ID, Title: "zizmor-finding", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: dd.ID, RepositoryID: repo.ID, Title: "fixed-audit-finding",
		Severity: "High", Status: db.FindingFixed})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "fixed-semgrep-finding",
		Severity: "High", Status: db.FindingFixed})

	// Default: scanner findings hidden, audit visible. Toggle advertises the
	// total scanner count so the operator knows what they're suppressing.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings"))
	body := w.Body.String()
	if !strings.Contains(body, "audit-finding") {
		t.Error("default listing should include deep-dive findings")
	}
	if strings.Contains(body, "semgrep-finding") || strings.Contains(body, "zizmor-finding") {
		t.Error("default listing should hide scanner findings")
	}
	if !strings.Contains(body, "Include scanners (2)") {
		t.Error("toolbar should show scanner total when scanners are suppressed")
	}

	// ?scanners=1: scanner findings reappear.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings?scanners=1"))
	body = w.Body.String()
	for _, want := range []string{"audit-finding", "semgrep-finding", "zizmor-finding"} {
		if !strings.Contains(body, want) {
			t.Errorf("?scanners=1 should include %q", want)
		}
	}

	// Explicit closed-status filters count matching scanner findings too.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings?status=fixed"))
	body = w.Body.String()
	if !strings.Contains(body, "fixed-audit-finding") || strings.Contains(body, "fixed-semgrep-finding") {
		t.Errorf("status=fixed should show fixed audit findings and hide scanner rows by default: %s", body)
	}
	if !strings.Contains(body, "Include scanners (1)") {
		t.Error("scanner badge should count fixed scanner findings under status=fixed")
	}
}

func TestDeepDiveSkillNameSafeForSplicing(t *testing.T) {
	// deepDiveSkillName, vulnScanSkillName and advisoryDeepDiveSkillName are
	// spliced into findingsBucketSkillSQL as raw single-quoted literals (it feeds
	// SQL such as the deepDiveFindingsCountSQL ORDER BY subquery, which cannot
	// take a bind parameter), so none may ever carry a SQL metacharacter. This
	// tripwire fails loudly if a refactor changes a constant or makes a value
	// dynamic.
	for _, name := range []string{deepDiveSkillName, vulnScanSkillName, advisoryDeepDiveSkillName} {
		if strings.ContainsAny(name, "'\";\\\x00") {
			t.Errorf("skill name %q must stay free of SQL metacharacters; it is spliced into findingsBucketSkillSQL", name)
		}
		// The literal it is spliced as must be a faithful single-quote wrap —
		// the same output db.SQLStringLiteral would produce — and must actually
		// appear in findingsBucketSkillSQL.
		quoted := db.SQLStringLiteral(name)
		if quoted != "'"+name+"'" {
			t.Errorf("SQLStringLiteral(%q) = %q, want simple quoting", name, quoted)
		}
		if !strings.Contains(findingsBucketSkillSQL, quoted) {
			t.Errorf("findingsBucketSkillSQL %q must splice %s as %q", findingsBucketSkillSQL, name, quoted)
		}
	}
}

func TestFindings_importsShownByDefault(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/imp", Name: "imp"}
	s.DB.Create(&repo)
	// An operator import: kind=import, with the producing tool in skill_name.
	imp := db.Scan{RepositoryID: repo.ID, Kind: "import", Status: db.ScanDone, SkillName: "CodeQL"}
	s.DB.Create(&imp)
	// A genuine tool scanner running as a skill must stay hidden by default.
	sg := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "semgrep"}
	s.DB.Create(&sg)
	s.DB.Create(&db.Finding{ScanID: imp.ID, RepositoryID: repo.ID, Title: "imported-finding", Severity: "High"})
	s.DB.Create(&db.Finding{ScanID: sg.ID, RepositoryID: repo.ID, Title: "semgrep-finding", Severity: "High"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/findings"))
	body := w.Body.String()
	if !strings.Contains(body, "imported-finding") {
		t.Error("imported findings should appear in the default findings list")
	}
	if strings.Contains(body, "semgrep-finding") {
		t.Error("tool-scanner findings should still be hidden by default")
	}
	// The scanners toggle counts only the genuine scanner, not the import.
	if !strings.Contains(body, "Include scanners (1)") {
		t.Errorf("scanner badge should count only the semgrep finding, not the import: %s", body)
	}
}

func TestFindingShow_rendersMissedCount(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	rescan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&rescan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "gone upstream", Severity: "High",
		LastSeenScanID: scan.ID, SeenCount: 1, MissedCount: 3, LastMissedScanID: rescan.ID}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if !strings.Contains(body, "Not seen") {
		t.Error("expected 'Not seen' label on finding page")
	}
	if !strings.Contains(body, "(missed 3x)") {
		t.Error("expected missed count rendered on finding page")
	}
	if !strings.Contains(body, fmt.Sprintf("scan #%d", rescan.ID)) {
		t.Error("expected link to last-missed scan")
	}
}

func TestFindingShow_disablesVerifyActionWhenVerifyInFlight(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "awaiting verify", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&f)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning,
		StatusPriority: db.StatusPriorityFor(db.ScanRunning), SkillName: verifySkillName, FindingID: new(f.ID)})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if strings.Contains(body, fmt.Sprintf(`hx-post="/findings/%d/verify"`, f.ID)) {
		t.Error("finding page should not render an active verify action while verify is in flight")
	}
	if !strings.Contains(body, `button type="button" class="btn" disabled`) || !strings.Contains(body, "Verify in progress") {
		t.Errorf("finding page should render disabled verify state, body=%s", body)
	}
}

func TestFindingShow_rendersValidateFixForm(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "needs a fix", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if !strings.Contains(body, fmt.Sprintf(`action="/repositories/%d/validate-fix"`, repo.ID)) {
		t.Errorf("expected a validate-fix form posting to the repo endpoint, body=%s", body)
	}
	if !strings.Contains(body, fmt.Sprintf(`name="finding_ids" value="%d"`, f.ID)) {
		t.Error("expected this finding's id wired into the validate-fix form")
	}
	if !strings.Contains(body, `name="ref"`) {
		t.Error("expected a ref input in the validate-fix form")
	}
}

func TestFindingShow_ghsaLinksToRepoAdvisory(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/savonrb/savon", Name: "savon",
		HTMLURL: "https://github.com/savonrb/savon"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "xxe", Severity: "High",
		GHSAID: "GHSA-mx5j-mp4f-g8jg"}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	want := "https://github.com/savonrb/savon/security/advisories/GHSA-mx5j-mp4f-g8jg"
	if !strings.Contains(body, want) {
		t.Errorf("expected repo-nested GHSA advisory link %q on finding page", want)
	}
}

func TestFindingShow_ghsaFallsBackToGlobalAdvisory(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	// Local/non-GitHub repos have no HTMLURL; the link falls back to the
	// global advisories page rather than emitting a broken relative URL.
	repo := db.Repository{URL: "file:///tmp/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "xxe", Severity: "High",
		GHSAID: "GHSA-mx5j-mp4f-g8jg"}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if !strings.Contains(body, "https://github.com/advisories/GHSA-mx5j-mp4f-g8jg") {
		t.Error("expected global GHSA advisory link when repo has no HTMLURL")
	}
}

func TestFindingShow_hidesExposureForZizmorFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: zizmorSkillName}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "workflow issue", Severity: "High"}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if strings.Contains(body, "Dependent exposure") || strings.Contains(body, "/exposure") {
		t.Error("zizmor findings should not render dependent exposure controls")
	}
}

func TestFindingShow_hidesExposureWhenNoDependents(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "app issue", Severity: "High"}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if strings.Contains(body, "Dependent exposure") || strings.Contains(body, "/exposure") {
		t.Error("findings without dependents should not render dependent exposure controls")
	}
	if strings.Contains(body, "CSAF VEX") {
		t.Error("findings without dependents should not advertise CSAF VEX in the disclosure bundle")
	}
}

func TestFindingShow_rendersExposureWhenDependentsExist(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/r", Name: "r"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "library issue", Severity: "High"}
	s.DB.Create(&f)
	dep := db.Dependent{RepositoryID: repo.ID, Name: "downstream", Ecosystem: "go", RepositoryURL: "https://example.com/downstream"}
	s.DB.Create(&dep)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	for _, want := range []string{"Dependent exposure", "/exposure", "CSAF VEX"} {
		if !strings.Contains(body, want) {
			t.Errorf("dependent-backed finding missing %q", want)
		}
	}
}

func TestFindingShow_rendersPublicIssueActionForReadyFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "low severity hardening", Severity: "Low", Status: db.FindingReady}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if !strings.Contains(body, fmt.Sprintf("/findings/%d/public-issue", f.ID)) {
		t.Error("ready finding page missing public issue action")
	}
	if !strings.Contains(body, "File public issue") {
		t.Error("ready finding page missing public issue label")
	}
}

func TestFindingShow_hidesPublicIssueActionForHighSeverityReadyFinding(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	for _, severity := range []string{"High", "Critical"} {
		f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: severity + " severity finding", Severity: severity, Status: db.FindingReady}
		s.DB.Create(&f)

		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, body)
		}
		if strings.Contains(body, fmt.Sprintf("/findings/%d/public-issue", f.ID)) {
			t.Errorf("%s ready finding page should not render public issue action", severity)
		}
		if strings.Contains(body, "File public issue") {
			t.Errorf("%s ready finding page should not render public issue label", severity)
		}
	}
}

func TestFindingShow_operatorWorkflowWhenNoDependents(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/app", Name: "app"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)

	cases := []struct {
		status db.FindingLifecycle
		want   []string
	}{
		{db.FindingTriaged, []string{"Triaged, ready for operator handoff", "patch or mitigation"}},
		{db.FindingReady, []string{"Remediation handoff ready", "share with the operator", "Mark shared"}},
		{db.FindingReported, []string{"Shared with operator", "remediation owner"}},
		{db.FindingAcknowledged, []string{"Operator acknowledged", "remediation owner is working on a fix"}},
		{db.FindingFixed, []string{"internal advisory"}},
		{db.FindingPublished, []string{"Closed out", "Internal advisory or remediation follow-up is complete"}},
	}
	for _, tc := range cases {
		f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: string(tc.status) + " finding",
			Severity: "High", Status: tc.status}
		s.DB.Create(&f)

		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Fatalf("%s status %d: %s", tc.status, w.Code, body)
		}
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s finding page missing no-dependent workflow text %q", tc.status, want)
			}
		}
		for _, gone := range []string{"send to the maintainer", "Mark as reported"} {
			if strings.Contains(body, gone) {
				t.Errorf("%s finding page should not render dependent-disclosure text %q", tc.status, gone)
			}
		}
	}
}

func TestFindingShow_dependentWorkflowWhenDependentsExist(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/lib", Name: "lib"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)
	s.DB.Create(&db.Dependent{RepositoryID: repo.ID, Name: "downstream", Ecosystem: "npm"})
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "ready finding",
		Severity: "High", Status: db.FindingReady}
	s.DB.Create(&f)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	for _, want := range []string{"Disclosure draft ready", "send to the maintainer", "Mark as reported"} {
		if !strings.Contains(body, want) {
			t.Errorf("dependent workflow missing %q", want)
		}
	}
	for _, gone := range []string{"Remediation handoff ready", "Mark shared"} {
		if strings.Contains(body, gone) {
			t.Errorf("dependent workflow should not render no-dependent text %q", gone)
		}
	}
}

func TestOrgReport_rendersFindingsAcrossRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r1 := db.Repository{URL: "https://example.com/acme/one", Name: "one", Owner: "acme", Description: "first repo"}
	s.DB.Create(&r1)
	r2 := db.Repository{URL: "https://example.com/acme/two", Name: "two", Owner: "acme"}
	s.DB.Create(&r2)
	_ = db.Repository{URL: "https://example.com/globex/svc", Name: "svc", Owner: "globex"}

	scan1 := db.Scan{RepositoryID: r1.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan1)
	s.DB.Create(&db.Finding{ScanID: scan1.ID, RepositoryID: r1.ID,
		Title: "SSRF in image fetch", Severity: "High", Location: "fetch.go:42",
		CWE: "CWE-918", Trace: "Attacker controls URL...", Status: db.FindingTriaged})
	s.DB.Create(&db.Finding{ScanID: scan1.ID, RepositoryID: r1.ID,
		Title: "Path traversal", Severity: "Medium", Location: "io.go:10"})

	scan2 := db.Scan{RepositoryID: r2.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan2)
	s.DB.Create(&db.Finding{ScanID: scan2.ID, RepositoryID: r2.ID,
		Title: "XSS in admin panel", Severity: "High", Location: "views/admin.go:77"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/acme/findings.md"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "acme-findings") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	body := w.Body.String()
	for _, want := range []string{
		"# scrutineer findings report: acme",
		"Repositories: 2",
		"Total findings: 3",
		"### Severity breakdown",
		"| High | 2 |",
		"| Medium | 1 |",
		"### Coverage",
		"| one | 2 |",
		"| two | 1 |",
		"## one",
		"## two",
		"SSRF in image fetch",
		"Path traversal",
		"XSS in admin panel",
		"Attacker controls URL",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// Should not contain globex's findings under the acme report.
	if strings.Contains(body, "globex") {
		t.Errorf("acme report contains globex content")
	}
}

func TestOrgSummary_rendersSynopsisShape(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r1 := db.Repository{URL: "https://github.com/acme/web.git", Name: "web", Owner: "acme", FullName: "acme/web"}
	s.DB.Create(&r1)
	r2 := db.Repository{URL: "https://github.com/acme/api.git", Name: "api", Owner: "acme", FullName: "acme/api"}
	s.DB.Create(&r2)
	empty := db.Repository{URL: "https://github.com/acme/quiet.git", Name: "quiet", Owner: "acme", FullName: "acme/quiet"}
	s.DB.Create(&empty)

	scan1 := db.Scan{RepositoryID: r1.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan1)
	s.DB.Create(&db.Finding{ScanID: scan1.ID, RepositoryID: r1.ID,
		Title: "Open redirect in /api/sso", Severity: "High",
		Location: "src/route.ts:46", Rating: "**High.** Auth-adjacent; token leakage.",
		Trace: "should not appear in summary"})

	scan2 := db.Scan{RepositoryID: r2.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan2)
	s.DB.Create(&db.Finding{ScanID: scan2.ID, RepositoryID: r2.ID,
		Title: "CSV injection", Severity: "Medium",
		Location: "api/reports.cs:20", Rating: "**Medium.** Requires admin-held role."})
	s.DB.Create(&db.Finding{ScanID: scan2.ID, RepositoryID: r2.ID,
		Title: "Cookie not httpOnly", Severity: "Low",
		Location: "auth/set-cookie.ts:27", Rating: "**Low.** Defense in depth."})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/acme/summary.md"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "acme-summary") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	body := w.Body.String()
	for _, want := range []string{
		"# Summary of findings",
		"Findings: 1 high, 1 medium, 1 low severity",
		"## acme/web",
		"## acme/api",
		"Findings: 1 high, 0 medium, 0 low severity", // web
		"Findings: 0 high, 1 medium, 1 low severity", // api
		"### Finding #1 - Rating: High",
		"Open redirect in /api/sso",
		"Location: `src/route.ts:46`",
		"**High.** Auth-adjacent; token leakage.",
		"### Finding #2 - Rating: Medium",
		"### Finding #3 - Rating: Low",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("summary missing %q", want)
		}
	}

	// Archive content must NOT leak into the synopsis, and we
	// deliberately don't include any per-repo link line.
	for _, unwanted := range []string{
		"should not appear in summary",
		"| Field | Value |",
		"#### Trace",
		"### Severity breakdown",
		"Full report and validation code",
		"/repositories/",
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("summary contains archive-only content %q", unwanted)
		}
	}

	// acme/quiet has no findings so it should be omitted entirely.
	if strings.Contains(body, "acme/quiet") {
		t.Errorf("repos without findings should not appear in summary")
	}

	// Cross-repo order: acme/web (worst: High) before acme/api (worst: Medium).
	if strings.Index(body, "## acme/web") > strings.Index(body, "## acme/api") {
		t.Errorf("expected acme/web (High) before acme/api (Medium)")
	}
	// Within-repo order: Medium must render before Low in acme/api.
	mediumIdx := strings.Index(body, "### Finding #2 - Rating: Medium")
	lowIdx := strings.Index(body, "### Finding #3 - Rating: Low")
	if mediumIdx < 0 || lowIdx < 0 || mediumIdx > lowIdx {
		t.Errorf("expected Medium before Low within acme/api (medium=%d low=%d)", mediumIdx, lowIdx)
	}
}

func TestOrgSummary_unknownIs404(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/nope/summary.md"))
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestOrgReport_unknownIs404(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/orgs/nope/findings.md"))
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestAdvisoriesIndex(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	railsRepo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	s.DB.Create(&railsRepo)
	djangoRepo := db.Repository{URL: "https://github.com/django/django", Name: "django"}
	s.DB.Create(&djangoRepo)

	now := time.Now()
	s.DB.Create(&db.Advisory{RepositoryID: railsRepo.ID, UUID: "u1",
		URL: "https://example.com/a1", Title: "SQL injection in activerecord",
		Severity: "CRITICAL", CVSSScore: 9.8, Packages: "rails,activerecord",
		Classification: "CWE-89", PublishedAt: &now})
	s.DB.Create(&db.Advisory{RepositoryID: djangoRepo.ID, UUID: "u2",
		URL: "https://example.com/a2", Title: "XSS in admin",
		Severity: "MODERATE", CVSSScore: 5.4, Packages: "django",
		Classification: "CWE-79", PublishedAt: &now})
	s.DB.Create(&db.Advisory{RepositoryID: djangoRepo.ID, UUID: "u3",
		URL: "", Title: "advisory without upstream link",
		Severity: "HIGH", CVSSScore: 7.2, Packages: "django"})

	// All advisories render.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		"SQL injection in activerecord",
		"XSS in admin",
		"advisory without upstream link",
		"rails", "django",
		"9.8", "5.4",
		`badge-destructive">Critical`,
		`badge-destructive">High`,
		`badge-primary">Medium`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, `href=""`) {
		t.Error("empty URL produced a broken anchor pointing to the current page")
	}
	if strings.Contains(body, ">MODERATE<") || strings.Contains(body, ">Moderate<") {
		t.Error("severity rendered without casing normalization")
	}

	// Severity filter: only CRITICAL rows.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories?severity=CRITICAL"))
	body = w.Body.String()
	if !strings.Contains(body, "SQL injection") || strings.Contains(body, "XSS in admin") {
		t.Errorf("severity filter: %s", body)
	}

	// Search: classification match.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories?q=CWE-79"))
	body = w.Body.String()
	if !strings.Contains(body, "XSS in admin") || strings.Contains(body, "SQL injection") {
		t.Errorf("search: %s", body)
	}

	// Empty-match state.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/advisories?q=NOPE_NOPE_NOPE"))
	if !strings.Contains(w.Body.String(), "No matches") {
		t.Error("empty-match advisories: no empty state")
	}
}

func TestMaintainersSortOptions(t *testing.T) {
	const (
		zeta    = "zeta"
		alpha   = "alpha"
		charlie = "charlie"
	)
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Maintainer{Login: zeta, Name: "Alice", Status: db.MaintainerActive})
	s.DB.Create(&db.Maintainer{Login: alpha, Name: "Zed", Status: db.MaintainerInactive})
	s.DB.Create(&db.Maintainer{Login: charlie, Name: "", Status: db.MaintainerUnknown})

	// logins returns the order the three seeded logins appear in a rendered body.
	logins := func(body string) []string {
		idx := map[string]int{}
		for _, want := range []string{alpha, charlie, zeta} {
			if i := strings.Index(body, ">"+want+"</td>"); i >= 0 {
				idx[want] = i
			}
		}
		out := []string{alpha, charlie, zeta}
		for i := 0; i < len(out); i++ {
			for j := i + 1; j < len(out); j++ {
				if idx[out[j]] < idx[out[i]] {
					out[i], out[j] = out[j], out[i]
				}
			}
		}
		return out
	}
	orderBy := func(path string) []string {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", path))
		if w.Code != 200 {
			t.Fatalf("%s status %d", path, w.Code)
		}
		return logins(w.Body.String())
	}

	// sort=name (default): Alice(zeta) then Zed(alpha) then empty-name(charlie).
	nameOrder := orderBy("/maintainers?sort=name")
	if nameOrder[0] != zeta || nameOrder[1] != alpha || nameOrder[2] != charlie {
		t.Errorf("sort=name order: %v", nameOrder)
	}

	// sort=login: alpha, charlie, zeta
	loginOrder := orderBy("/maintainers?sort=login")
	if loginOrder[0] != alpha || loginOrder[1] != charlie || loginOrder[2] != zeta {
		t.Errorf("sort=login order: %v", loginOrder)
	}

	// sort=newest: most recently created first (charlie was inserted last).
	newestOrder := orderBy("/maintainers?sort=newest")
	if newestOrder[0] != charlie {
		t.Errorf("sort=newest expected charlie first, got %v", newestOrder)
	}
}

func TestMaintainersSearchFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Maintainer{Login: "alice", Name: "Alice Example", Email: "alice@example.com", Company: "Acme"})
	s.DB.Create(&db.Maintainer{Login: "bob", Name: "Bob", Email: "bob@other.net", Notes: "has bus factor risk"})

	cases := map[string][]string{
		"alice":          {"alice"},
		"@example.com":   {"alice"},
		"Acme":           {"alice"},
		"bus factor":     {"bob"},
		"NOPE_NOPE_NOPE": nil,
	}
	for q, want := range cases {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/maintainers?q="+url.QueryEscape(q)))
		if w.Code != 200 {
			t.Errorf("q=%q status %d", q, w.Code)
			continue
		}
		body := w.Body.String()
		for _, login := range want {
			if !strings.Contains(body, login) {
				t.Errorf("q=%q missing %q", q, login)
			}
		}
		if len(want) == 0 && !strings.Contains(body, "No matches") {
			t.Errorf("q=%q empty state missing", q)
		}
	}
}

func TestIndexRenders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `name="url"`) {
		t.Error("missing form")
	}
}

func TestCreateRepoEnqueuesTriageSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	h := s.Handler()

	// Seed a triage skill; without it adding a repo is a no-op.
	triage := db.Skill{
		Name:        "triage",
		Description: "orchestrator",
		Body:        "body",
		Active:      true,
		Source:      "ui",
		Version:     1,
	}
	s.DB.Create(&triage)

	form := url.Values{"url": {"https://github.com/foo/bar.git"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create status %d: %s", w.Code, w.Body)
	}
	if w.Header().Get("Location") == "" {
		t.Error("expected Location redirect")
	}

	var repo db.Repository
	if err := s.DB.First(&repo).Error; err != nil {
		t.Fatal(err)
	}
	var scans []db.Scan
	s.DB.Where("repository_id = ?", repo.ID).Find(&scans)
	if len(scans) != 1 {
		t.Fatalf("expected one scan (triage), got %d", len(scans))
	}
	if scans[0].SkillID == nil || *scans[0].SkillID != triage.ID {
		t.Errorf("scan SkillID = %v, want %d", scans[0].SkillID, triage.ID)
	}
}

func TestFindingDiscloseEnqueuesDiscloseSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&finding)
	disclose := db.Skill{Name: "disclose", Description: "d", Body: "b", OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&disclose)

	req := httptest.NewRequest("POST", "/findings/1/disclose", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.HasPrefix(w.Header().Get("Location"), "/scans/") {
		t.Errorf("expected redirect to scan, got %q", w.Header().Get("Location"))
	}

	var row db.Scan
	s.DB.Where("skill_id = ?", disclose.ID).First(&row)
	if row.FindingID == nil || *row.FindingID != finding.ID {
		t.Errorf("scan FindingID = %v, want %d", row.FindingID, finding.ID)
	}
	if row.APIToken == "" {
		t.Error("scan missing api token")
	}
}

func TestFindingPublicIssueEnqueuesPublicIssueSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "Low", Status: db.FindingReady}
	s.DB.Create(&finding)
	publicIssue := db.Skill{Name: publicIssueSkillName, Description: "p", Body: "b", OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&publicIssue)

	req := httptest.NewRequest("POST", fmt.Sprintf("/findings/%d/public-issue", finding.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.HasPrefix(w.Header().Get("Location"), "/scans/") {
		t.Errorf("expected redirect to scan, got %q", w.Header().Get("Location"))
	}

	var row db.Scan
	s.DB.Where("skill_id = ?", publicIssue.ID).First(&row)
	if row.FindingID == nil || *row.FindingID != finding.ID {
		t.Errorf("scan FindingID = %v, want %d", row.FindingID, finding.ID)
	}
	if row.APIToken == "" {
		t.Error("scan missing api token")
	}
}

func TestFindingVerifySkipsOpenVerifyScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	parent := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&parent)
	finding := db.Finding{ScanID: parent.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&finding)
	verify := db.Skill{Name: verifySkillName, Description: "v", Body: "b", OutputFile: "report.json", OutputKind: "verify", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&verify)
	openScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanQueued,
		StatusPriority: db.StatusPriorityFor(db.ScanQueued), SkillName: verifySkillName, SkillID: new(verify.ID), FindingID: new(finding.ID)}
	s.DB.Create(&openScan)

	req := httptest.NewRequest("POST", fmt.Sprintf("/findings/%d/verify", finding.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got, want := w.Header().Get("Location"), fmt.Sprintf("/scans/%d", openScan.ID); got != want {
		t.Errorf("redirect = %q, want existing scan %q", got, want)
	}
	var count int64
	s.DB.Model(&db.Scan{}).
		Where("finding_id = ? AND skill_name = ?", finding.ID, verifySkillName).
		Count(&count)
	if count != 1 {
		t.Errorf("verify scans = %d, want 1", count)
	}
}

func TestFindingPatchRunEnqueuesPatchSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&finding)
	patch := db.Skill{Name: "patch", Description: "p", Body: "b", OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&patch)

	req := httptest.NewRequest("POST", "/findings/1/patch", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var row db.Scan
	s.DB.Where("skill_id = ?", patch.ID).First(&row)
	if row.FindingID == nil || *row.FindingID != finding.ID {
		t.Errorf("scan FindingID = %v, want %d", row.FindingID, finding.ID)
	}
}

func TestEnqueueSkillWith_modelPrecedence(t *testing.T) {
	withTestModels(t, []Model{
		{Name: "Test High", ID: "test-high"},
		{Name: "Test Mid", ID: "test-mid"},
		{Name: "Test Max", ID: "test-max"},
		{Name: "Test Exact", ID: "test-exact"},
	})

	s, done := newTestServer(t)
	defer done()

	if err := db.SetSetting(s.DB, db.SettingModelTierMid, "test-mid"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(s.DB, db.SettingModelTierHigh, "test-high"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(s.DB, db.SettingModelTierMax, "test-max"); err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	withModel := db.Skill{Name: "lite", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui", Model: "test-exact"}
	s.DB.Create(&withModel)
	withTier := db.Skill{Name: "tiered", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui", Model: ModelTierMid}
	s.DB.Create(&withTier)
	noModel := db.Skill{Name: "heavy", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&noModel)
	metadata := db.Skill{Name: "metadata", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui", Model: ModelTierMid}
	s.DB.Create(&metadata)
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui", Model: ModelTierMax}
	s.DB.Create(&deepDive)

	cases := []struct {
		name    string
		skillID uint
		opts    ScanOpts
		want    string
	}{
		{"explicit scan model wins", withTier.ID, ScanOpts{Model: "test-max"}, "test-max"},
		{"explicit scan tier wins", withModel.ID, ScanOpts{Model: ModelTierMax}, "test-max"},
		{"skill model fills empty scan model", withModel.ID, ScanOpts{}, "test-exact"},
		{"skill model fills invalid scan model", withModel.ID, ScanOpts{Model: "garbage"}, "test-exact"},
		{"skill tier resolves through settings", withTier.ID, ScanOpts{}, "test-mid"},
		{"generic skill defaults to high tier", noModel.ID, ScanOpts{}, "test-high"},
		{"metadata skill uses mid tier", metadata.ID, ScanOpts{}, "test-mid"},
		{"deep dive skill uses max tier", deepDive.ID, ScanOpts{}, "test-max"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanID, err := s.enqueueSkillWith(context.Background(), repo.ID, tc.skillID, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			var sc db.Scan
			s.DB.First(&sc, scanID)
			if sc.Model != tc.want {
				t.Errorf("scan.Model = %q, want %q", sc.Model, tc.want)
			}
		})
	}
}

func TestEnqueueSkillWith_effort(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.SetDefaultEffort("high")

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "lite", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	cases := []struct {
		name string
		opts ScanOpts
		want string
	}{
		{"explicit effort honored", ScanOpts{Effort: "max"}, "max"},
		{"runtime default fills empty effort", ScanOpts{}, "high"},
		{"runtime default fills invalid effort", ScanOpts{Effort: "garbage"}, "high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scanID, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			var sc db.Scan
			s.DB.First(&sc, scanID)
			if sc.Effort != tc.want {
				t.Errorf("scan.Effort = %q, want %q", sc.Effort, tc.want)
			}
		})
	}
}

func TestEnqueueSkillWith_stampsBenchmarkVersionFields(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.SkillsRepoSHA = "feedface0123456789abcdef0123456789abcdef"

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "lite", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 7, Metadata: `{"scrutineer.version":1}`, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	scanID, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, ScanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var sc db.Scan
	s.DB.First(&sc, scanID)
	if sc.SkillsRepoSHA != s.SkillsRepoSHA {
		t.Errorf("scan.SkillsRepoSHA = %q, want %q", sc.SkillsRepoSHA, s.SkillsRepoSHA)
	}
	if sc.SkillVersion != skill.Version {
		t.Errorf("scan.SkillVersion = %d, want %d", sc.SkillVersion, skill.Version)
	}
	if sc.SkillSchemaVersion != 1 {
		t.Errorf("scan.SkillSchemaVersion = %d, want 1", sc.SkillSchemaVersion)
	}
}

func TestEnqueueSkillWith_emptySkillsRepoSHAByDefault(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "lite", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	scanID, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, ScanOpts{})
	if err != nil {
		t.Fatal(err)
	}
	var sc db.Scan
	s.DB.First(&sc, scanID)
	if sc.SkillsRepoSHA != "" {
		t.Errorf("scan.SkillsRepoSHA = %q, want empty", sc.SkillsRepoSHA)
	}
}

func TestEnqueueSkillWith_localRepoRejectsRemoteOnlySkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	local := db.Repository{URL: "file:///srv/projects/myrepo", Name: "myrepo"}
	s.DB.Create(&local)
	remote := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&remote)
	remoteSkill := db.Skill{Name: "fork", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui", RequiresRemote: true}
	s.DB.Create(&remoteSkill)
	localSkill := db.Skill{Name: "deep", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&localSkill)

	_, err := s.enqueueSkillWith(context.Background(), local.ID, remoteSkill.ID, ScanOpts{})
	if err == nil {
		t.Error("expected enqueue of RequiresRemote skill on local repo to fail")
	} else if !errors.Is(err, ErrSkillRequiresRemote) {
		t.Errorf("expected ErrSkillRequiresRemote, got %v", err)
	}
	if _, err := s.enqueueSkillWith(context.Background(), local.ID, localSkill.ID, ScanOpts{}); err != nil {
		t.Errorf("local-friendly skill on local repo should succeed, got %v", err)
	}
	if _, err := s.enqueueSkillWith(context.Background(), remote.ID, remoteSkill.ID, ScanOpts{}); err != nil {
		t.Errorf("RequiresRemote skill on remote repo should succeed, got %v", err)
	}
}

func TestEnqueueSkillWith_profileMismatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	phpSkill := db.Skill{Name: "php-only", Body: "b", OutputFile: "r.json", OutputKind: "freeform",
		Version: 1, Active: true, Source: "ui", RequiresProfile: "php"}
	s.DB.Create(&phpSkill)

	if _, err := s.enqueueSkillWith(context.Background(), repo.ID, phpSkill.ID, ScanOpts{Profile: "default"}); err == nil {
		t.Error("expected enqueue with mismatched profile to fail")
	} else if !errors.Is(err, ErrSkillProfileMismatch) {
		t.Errorf("expected ErrSkillProfileMismatch, got %v", err)
	}

	if _, err := s.enqueueSkillWith(context.Background(), repo.ID, phpSkill.ID, ScanOpts{Profile: "php"}); err != nil {
		t.Errorf("matching profile should succeed, got %v", err)
	}

	if _, err := s.enqueueSkillWith(context.Background(), repo.ID, phpSkill.ID, ScanOpts{}); err != nil {
		t.Errorf("empty profile (auto-detect) should not be gated at enqueue, got %v", err)
	}
}

func TestEnqueueSkillWith_findingScopedJumpsQueue(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	prior := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&prior)
	skill := db.Skill{Name: "verify", Body: "b", OutputFile: "r.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)
	finding := db.Finding{ScanID: prior.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High"}
	s.DB.Create(&finding)

	if _, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, ScanOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, ScanOpts{FindingID: &finding.ID}); err != nil {
		t.Fatal(err)
	}

	sqldb, _ := s.DB.DB()
	rows, err := sqldb.Query("SELECT priority FROM goqite")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []int
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		got = append(got, p)
	}
	sort.Ints(got)
	want := []int{worker.PrioScan, worker.PrioFinding}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("queue priorities = %v, want %v", got, want)
	}
}

func TestRepoVerifyAll(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	verify := db.Skill{Name: "verify", Body: "b", OutputFile: "r.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&verify)

	// Three findings awaiting verification.
	for i := range 3 {
		s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
			FindingID: fmt.Sprintf("N%d", i), Title: "x", Severity: "High", Status: db.FindingNew})
	}
	// A triaged finding that must be ignored.
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "T1", Title: "x", Severity: "High", Status: db.FindingTriaged})
	// A new finding that already has a running verify scan: must be skipped.
	skipF := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "S1", Title: "x", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&skipF)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning,
		SkillName: "verify", SkillID: new(verify.ID), FindingID: new(skipF.ID)})

	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/verify-all", repo.ID), nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	// One queued verify scan per "new" finding without an in-flight verify.
	var queued []db.Scan
	s.DB.Where("skill_name = ? AND status = ?", "verify", db.ScanQueued).Find(&queued)
	if len(queued) != 3 {
		t.Fatalf("queued verify scans = %d, want 3", len(queued))
	}
	for _, sc := range queued {
		if sc.FindingID == nil {
			t.Errorf("queued verify scan %d missing finding id", sc.ID)
		}
	}
	if f := flashFrom(t, w); !strings.Contains(f.Title, "3 queued") || !strings.Contains(f.Title, "1 already running") {
		t.Errorf("flash = %q, want 3 queued / 1 already running", f.Title)
	}
}

func TestRepoVerifyAll_respectsCategoryFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	verify := db.Skill{Name: "verify", Body: "b", OutputFile: "r.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&verify)

	// One new finding in each of two categories.
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "INJ", Title: "x", Severity: "High", Status: db.FindingNew, CWE: "CWE-78"})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "MEM", Title: "x", Severity: "High", Status: db.FindingNew, CWE: "CWE-416"})

	// The badge counts only the filtered category.
	body := getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "Verify all new (2)") {
		t.Errorf("unfiltered badge should be 2; body=%s", body)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d?category=Injection", repo.ID)))
	if !strings.Contains(w.Body.String(), "Verify all new (1)") {
		t.Errorf("Injection-filtered badge should be 1; body=%s", w.Body)
	}

	// The action enqueues only the filtered category's finding.
	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/verify-all?category=Injection", repo.ID), nil)
	req.Host = testHost
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var queued []db.Scan
	s.DB.Where("skill_name = ? AND status = ?", "verify", db.ScanQueued).Find(&queued)
	if len(queued) != 1 {
		t.Fatalf("queued verify scans = %d, want 1 (category-scoped)", len(queued))
	}
}

func TestRepoVerifyAll_skillNotInstalled(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "N1", Title: "x", Severity: "High", Status: db.FindingNew})

	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/verify-all", repo.ID), nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var n int64
	s.DB.Model(&db.Scan{}).Where("skill_name = ?", "verify").Count(&n)
	if n != 0 {
		t.Errorf("verify scans created = %d, want 0 when skill missing", n)
	}
	if f := flashFrom(t, w); f.Category != "error" {
		t.Errorf("flash category = %q, want error", f.Category)
	}
}

func TestRepoScanAll(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json",
		OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&deepDive)

	// Three subprojects; one of them already has an in-flight deep-dive scan
	// and must be skipped so the button is idempotent.
	for _, p := range []string{"a", "b", "skipme"} {
		s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: p, Name: p})
	}
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning,
		SkillName: deepDiveSkillName, SkillID: new(deepDive.ID), SubPath: "skipme"})

	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/scan-all", repo.ID), nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	// One queued deep-dive scan per subproject without an in-flight scan.
	var queued []db.Scan
	s.DB.Where("skill_name = ? AND status = ?", deepDiveSkillName, db.ScanQueued).Find(&queued)
	if len(queued) != 2 {
		t.Fatalf("queued scans = %d, want 2", len(queued))
	}
	paths := map[string]bool{}
	for _, sc := range queued {
		paths[sc.SubPath] = true
	}
	if !paths["a"] || !paths["b"] || paths["skipme"] {
		t.Errorf("queued sub_paths = %v, want {a, b} only", paths)
	}
	if f := flashFrom(t, w); !strings.Contains(f.Title, "2 queued") || !strings.Contains(f.Title, "1 already running") {
		t.Errorf("flash = %q, want 2 queued / 1 already running", f.Title)
	}
	// The cohort shares one non-empty scan_group so each sibling can read the
	// others' findings via ?scan_group= while they run in parallel.
	if queued[0].ScanGroup == "" {
		t.Error("scan-all cohort should carry a scan_group")
	}
	if queued[0].ScanGroup != queued[1].ScanGroup {
		t.Errorf("scan-all scans should share one scan_group, got %q and %q",
			queued[0].ScanGroup, queued[1].ScanGroup)
	}
}

func TestRepoScan_setsScanGroup(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json",
		OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&deepDive)

	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/scan", repo.ID), nil)
	req.Host = testHost
	s.Handler().ServeHTTP(httptest.NewRecorder(), req)

	var sc db.Scan
	if err := s.DB.Where("repository_id = ?", repo.ID).First(&sc).Error; err != nil {
		t.Fatalf("no scan created: %v", err)
	}
	if sc.ScanGroup == "" {
		t.Error("a single New-scan run should still carry a scan_group")
	}
}

func TestRepoScan_diffRescanQueuesGroupedSkills(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	for _, name := range []string{threatModelSkillName, "semgrep", deepDiveSkillName} {
		s.DB.Create(&db.Skill{Name: name, Body: "b", OutputFile: "r.json",
			OutputKind: "freeform", Version: 1, Active: true, Source: "ui"})
	}

	body := strings.NewReader("rescan_mode=diff")
	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/scan", repo.ID), body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var scans []db.Scan
	if err := s.DB.Where("repository_id = ?", repo.ID).Order("skill_name").Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if len(scans) != 3 {
		t.Fatalf("queued scans = %d, want 3", len(scans))
	}
	group := scans[0].ScanGroup
	if group == "" {
		t.Fatal("diff rescan group is empty")
	}
	gotNames := map[string]bool{}
	for _, sc := range scans {
		gotNames[sc.SkillName] = true
		if sc.RescanMode != db.ScanRescanModeDiff {
			t.Errorf("%s RescanMode = %q, want diff", sc.SkillName, sc.RescanMode)
		}
		if sc.ScanGroup != group {
			t.Errorf("%s ScanGroup = %q, want shared %q", sc.SkillName, sc.ScanGroup, group)
		}
	}
	for _, name := range []string{threatModelSkillName, "semgrep", deepDiveSkillName} {
		if !gotNames[name] {
			t.Errorf("missing queued %s scan", name)
		}
	}
}

func TestRepoScanAll_skillNotInstalled(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "a", Name: "a"})

	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/scan-all", repo.ID), nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	var n int64
	s.DB.Model(&db.Scan{}).Count(&n)
	if n != 0 {
		t.Errorf("scans created = %d, want 0 when skill missing", n)
	}
	if f := flashFrom(t, w); f.Category != "error" {
		t.Errorf("flash category = %q, want error", f.Category)
	}
}

func TestFindingPatchDownload(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	gatedDiff := "diff --git a/foo.go b/foo.go\n@@ -1 +1 @@\n-old\n+new\n"
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High",
		Status: db.FindingTriaged, SuggestedFix: gatedDiff, SuggestedFixCommit: "abc123"}
	s.DB.Create(&finding)

	report := `{"patch":"diff --git a/foo.go b/foo.go\n@@ -1 +1 @@\n-old\n+new\n","rationale":"adds guard","files_changed":["foo.go"],"base_commit":"abc123","tests_added":false}`
	patchScan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName:  "patch",
		FindingID:  new(finding.ID),
		FinishedAt: new(time.Now()),
		Report:     report,
	}
	s.DB.Create(&patchScan)

	req := httptest.NewRequest("GET", "/findings/1/patch.diff", nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("download status %d: %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-diff") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "finding-1.patch") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if body := w.Body.String(); !strings.HasPrefix(body, "diff --git") {
		t.Errorf("body does not start with diff header: %q", body)
	}

	req = httptest.NewRequest("GET", "/findings/1", nil)
	req.Host = testHost
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "Proposed patch") {
		t.Error("finding show page missing 'Proposed patch' section")
	}
	if !strings.Contains(body, "adds guard") {
		t.Error("finding show page missing rationale")
	}
	if !strings.Contains(body, "/findings/1/patch.diff") {
		t.Error("finding show page missing download link")
	}
	if !strings.Contains(body, "git apply") {
		t.Error("finding show page missing apply instructions")
	}
}

func TestFindingPatchDownload_404WhenNoPatch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&finding)

	req := httptest.NewRequest("GET", "/findings/1/patch.diff", nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d: %s", w.Code, w.Body)
	}
}

func TestFindingDisclose404WhenSkillMissing(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&finding)

	req := httptest.NewRequest("POST", "/findings/1/disclose", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 when disclose skill not installed, got %d: %s", w.Code, w.Body)
	}
}

func TestFindingPublicIssue404WhenSkillMissing(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "Low", Status: db.FindingReady}
	s.DB.Create(&finding)

	req := httptest.NewRequest("POST", fmt.Sprintf("/findings/%d/public-issue", finding.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 when public issue skill not installed, got %d: %s", w.Code, w.Body)
	}
}

func TestRepoShow_findingsTabAggregatesAcrossScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/agg", Name: "agg"}
	s.DB.Create(&repo)

	// Older deep-dive scan with findings in active and closed states.
	older := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: deepDiveSkillName, Status: db.ScanDone}
	s.DB.Create(&older)
	s.DB.Create(&db.Finding{ScanID: older.ID, RepositoryID: repo.ID, Title: "old-high", Severity: "High", Status: db.FindingNew})
	s.DB.Create(&db.Finding{ScanID: older.ID, RepositoryID: repo.ID, Title: "old-noise", Severity: "Low", Status: db.FindingRejected})
	s.DB.Create(&db.Finding{ScanID: older.ID, RepositoryID: repo.ID, Title: "old-fixed", Severity: "High", Status: db.FindingFixed})
	s.DB.Create(&db.Finding{ScanID: older.ID, RepositoryID: repo.ID, Title: "old-published", Severity: "High", Status: db.FindingPublished})

	// A non-deep-dive skill also produced a finding.
	other := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "secrets", Status: db.ScanDone}
	s.DB.Create(&other)
	s.DB.Create(&db.Finding{ScanID: other.ID, RepositoryID: repo.ID, Title: "leaked-key", Severity: "Critical", Status: db.FindingTriaged})

	// Latest deep-dive scan completed with zero findings. Previously this
	// hid the Findings tab entirely (#72).
	latest := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: deepDiveSkillName, Status: db.ScanDone}
	s.DB.Create(&latest)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	if !strings.Contains(body, "old-high") {
		t.Errorf("finding from older scan not shown")
	}
	if !strings.Contains(body, "leaked-key") {
		t.Errorf("finding from non-deep-dive skill not shown")
	}
	for _, hidden := range []string{"old-noise", "old-fixed", "old-published"} {
		if strings.Contains(body, hidden) {
			t.Errorf("closed finding %q should be hidden from the tab", hidden)
		}
	}
	// Deep-dive output and tool-scanner output render in separate tabs so the
	// curated audit list isn't drowned out by lint noise.
	if !strings.Contains(body, `id="rp11"`) {
		t.Errorf("expected Scanners tab when non-deep-dive findings exist")
	}
	deepPanel := tabPanelBody(body, `id="rp4"`)
	scannerPanel := tabPanelBody(body, `id="rp11"`)
	if !strings.Contains(deepPanel, "old-high") || strings.Contains(deepPanel, "leaked-key") {
		t.Errorf("Findings tab should hold deep-dive results only")
	}
	if !strings.Contains(scannerPanel, "leaked-key") || strings.Contains(scannerPanel, "old-high") {
		t.Errorf("Scanners tab should hold non-deep-dive results only")
	}
}

func TestRepoShow_tabRowCapAppliesAndShowsNotice(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/cap", Name: "cap", Owner: "capowner"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: deepDiveSkillName, Status: db.ScanDone}
	s.DB.Create(&scan)

	// Seed past the cap on findings, dependents, and advisories so each tab
	// renders exactly tabRowCap rows plus the "Showing N of M" notice. Batched
	// inserts keep the test under a second.
	over := tabRowCap + 5
	fs := make([]db.Finding, over)
	deps := make([]db.Dependent, over)
	advs := make([]db.Advisory, over)
	for i := range over {
		fs[i] = db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
			Title: fmt.Sprintf("f%d", i), Severity: "High", Status: db.FindingNew}
		deps[i] = db.Dependent{RepositoryID: repo.ID, Name: fmt.Sprintf("dep%d", i), Ecosystem: "npm"}
		advs[i] = db.Advisory{RepositoryID: repo.ID, Title: fmt.Sprintf("a%d", i), Severity: "High"}
	}
	s.DB.CreateInBatches(&fs, 100)
	s.DB.CreateInBatches(&deps, 100)
	s.DB.CreateInBatches(&advs, 100)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	// Each capped tab shows exactly tabRowCap rows.
	if n := strings.Count(body, `id="finding-card-`); n != tabRowCap {
		t.Errorf("rendered %d finding cards, want %d", n, tabRowCap)
	}
	notice := fmt.Sprintf("Showing %d of %d.", tabRowCap, over)
	if got := strings.Count(body, notice); got != 3 {
		t.Errorf("found %d %q notices, want 3 (findings, dependents, advisories)", got, notice)
	}
	if !strings.Contains(body, "/findings?owner=capowner&amp;category=") {
		t.Error("findings cap notice should link to the owner+category-filtered findings index")
	}
}

func TestRepoShow_depsCapAppliesAfterRuntimeFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/deps", Name: "deps"}
	s.DB.Create(&repo)

	// Seed tabRowCap+5 dev deps (sort early by ecosystem) and 3 runtime deps
	// (sort later). Before the fix, the cap fired on the dev deps and the
	// runtime-only default view came up empty.
	devDeps := make([]db.Dependency, tabRowCap+5)
	for i := range devDeps {
		devDeps[i] = db.Dependency{RepositoryID: repo.ID, Name: fmt.Sprintf("dev%03d", i),
			Ecosystem: "aaa", DependencyType: db.DependencyDev, ManifestPath: "package.json"}
	}
	s.DB.CreateInBatches(&devDeps, 100)
	for i := range 3 {
		s.DB.Create(&db.Dependency{RepositoryID: repo.ID, Name: fmt.Sprintf("rt%d", i),
			Ecosystem: "zzz", DependencyType: db.DependencyRuntime, ManifestPath: "package.json"})
	}

	// Default (runtime-only) view shows the 3 runtime deps and no cap notice.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"rt0", "rt1", "rt2"} {
		if !strings.Contains(body, want) {
			t.Errorf("runtime-only view missing %q (cap fired before filter)", want)
		}
	}
	if strings.Contains(body, "Dependency list capped") {
		t.Error("runtime-only view should not show cap notice (only 3 runtime deps)")
	}
	if !strings.Contains(body, fmt.Sprintf("%d test/build/dev row(s) hidden", tabRowCap+5)) {
		t.Error("hidden-deps count should be the SQL total, not capped")
	}

	// deps=all view caps at tabRowCap and shows the notice with the all-deps total.
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d?deps=all", repo.ID)))
	body = w.Body.String()
	if !strings.Contains(body, fmt.Sprintf("first %d of %d rows", tabRowCap, tabRowCap+5+3)) {
		t.Errorf("deps=all view missing cap notice with total=%d", tabRowCap+5+3)
	}
}

func TestFindingShow_historyCapAppliesAndShowsNotice(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/hist", Name: "hist"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "t", Severity: "High"}
	s.DB.Create(&f)

	over := historyRowCap + 5
	rows := make([]db.FindingHistory, over)
	for i := range over {
		rows[i] = db.FindingHistory{FindingID: f.ID, Field: "observed",
			NewValue: fmt.Sprintf("scan %d", i), Source: db.SourceTool}
	}
	s.DB.CreateInBatches(&rows, 100)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/findings/%d", f.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	notice := fmt.Sprintf("Showing %d of %d.", historyRowCap, over)
	if !strings.Contains(body, notice) {
		t.Errorf("missing history cap notice %q", notice)
	}
}

func TestRepoShow_categoryFilterKeepsScannerTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/cat", Name: "cat"}
	s.DB.Create(&repo)

	deep := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: deepDiveSkillName, Status: db.ScanDone}
	s.DB.Create(&deep)
	s.DB.Create(&db.Finding{ScanID: deep.ID, RepositoryID: repo.ID,
		Title: "memory-bug", Severity: "High", CWE: "CWE-416"})

	scanner := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "secrets", Status: db.ScanDone}
	s.DB.Create(&scanner)
	s.DB.Create(&db.Finding{ScanID: scanner.ID, RepositoryID: repo.ID,
		Title: "leaked-key", Severity: "Critical", CWE: "CWE-798"})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET",
		fmt.Sprintf("/repositories/%d?category=%s", repo.ID, url.QueryEscape("Injection"))))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	deepPanel := tabPanelBody(body, `id="rp4"`)
	scannerPanel := tabPanelBody(body, `id="rp11"`)
	if strings.Contains(deepPanel, ">memory-bug</a>") {
		t.Errorf("deep-dive finding outside category should be filtered out")
	}
	if !strings.Contains(body, `id="rp11"`) {
		t.Errorf("Scanners tab vanished when a category was selected")
	}
	if !strings.Contains(scannerPanel, ">leaked-key</a>") {
		t.Errorf("scanner finding should remain regardless of category filter")
	}
}

// tabPanelBody returns the substring of body starting at marker through the
// next closing </div> that matches the panel's opening div. Cheap-and-good-
// enough for assertions about which tab a finding renders inside.
func tabPanelBody(body, marker string) string {
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	end := strings.Index(body[i:], "</div>\n  </div>")
	if end < 0 {
		return body[i:]
	}
	return body[i : i+end]
}

func TestRepoShow_displaysFindingStatus(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/fstatus", Name: "fstatus"}
	s.DB.Create(&repo)

	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: deepDiveSkillName, Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rce", Severity: "High", Status: db.FindingTriaged})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/repositories/%d", repo.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()

	// The finding renders once in the Summary tab's latest-scan table and
	// once as a card in the Findings tab; both must show the lifecycle
	// status (#82).
	if n := strings.Count(body, "triaged"); n < 2 {
		t.Errorf("expected finding status to render in both Summary and Findings tabs, saw %d occurrences", n)
	}
}

func TestDependentScan_dedupesAgainstNormalisedRepo(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})

	// Repo added through the form (normalised, no .git).
	existing := db.Repository{URL: "https://github.com/rack/rack", Name: "rack"}
	s.DB.Create(&existing)

	// Dependent whose RepositoryURL came from ecosyste.ms with .git.
	dep := db.Dependent{RepositoryID: existing.ID, Name: "rack",
		RepositoryURL: "https://github.com/rack/rack.git"}
	s.DB.Create(&dep)

	req := httptest.NewRequest("POST", fmt.Sprintf("/dependents/%d/scan", dep.ID), nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repos []db.Repository
	s.DB.Find(&repos)
	if len(repos) != 1 {
		t.Fatalf("want 1 repo row, got %d: %+v", len(repos), repos)
	}
	if got, want := w.Header().Get("Location"), fmt.Sprintf("/repositories/%d", existing.ID); got != want {
		t.Errorf("redirect = %q, want %q", got, want)
	}
}

func TestBulkImport_dedupesNormalisedURLs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})

	// Same repo five ways: canonical, mixed case, trailing slash, .git, query string.
	urls := strings.Join([]string{
		"https://github.com/rails/rails",
		"https://github.com/Rails/Rails",
		"https://github.com/rails/rails/",
		"https://github.com/rails/rails.git",
		"https://GitHub.com/rails/rails?tab=readme",
	}, "\n")
	form := url.Values{"urls": {urls}}
	req := httptest.NewRequest("POST", "/repositories/bulk", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "1 added") || !strings.Contains(f.Title, "4 already present") {
		t.Errorf("flash title = %q, want 1 added / 4 already present", f.Title)
	}

	var repos []db.Repository
	s.DB.Find(&repos)
	if len(repos) != 1 || repos[0].URL != "https://github.com/rails/rails" {
		t.Fatalf("want one normalised row, got %+v", repos)
	}
}

func TestBulkImport_createsAndEnqueues(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	triage := db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&triage)

	urls := "https://github.com/foo/one.git\nhttps://github.com/foo/two.git\n"
	form := url.Values{"urls": {urls}}
	req := httptest.NewRequest("POST", "/repositories/bulk", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if w.Header().Get("Location") != "/" {
		t.Errorf("Location = %q", w.Header().Get("Location"))
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "2 added") {
		t.Errorf("flash missing '2 added': %+v", f)
	}

	var repos []db.Repository
	s.DB.Order("url").Find(&repos)
	if len(repos) != 2 {
		t.Fatalf("want 2 repos, got %d", len(repos))
	}
	var scans []db.Scan
	s.DB.Where("skill_id = ?", triage.ID).Find(&scans)
	if len(scans) != 2 {
		t.Fatalf("want 2 triage scans, got %d", len(scans))
	}
}

func TestBulkImport_branchFromTreeURL(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})

	urls := "https://github.com/symfony/symfony/tree/7.2\nhttps://github.com/spf13/cobra\n"
	form := url.Values{"urls": {urls}}
	req := httptest.NewRequest("POST", "/repositories/bulk", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	refFor := func(repoURL string) string {
		t.Helper()
		var repo db.Repository
		if err := s.DB.Where("url = ?", repoURL).First(&repo).Error; err != nil {
			t.Fatalf("repo %s: %v", repoURL, err)
		}
		var scan db.Scan
		if err := s.DB.Where("repository_id = ?", repo.ID).First(&scan).Error; err != nil {
			t.Fatalf("scan for %s: %v", repoURL, err)
		}
		return scan.Ref
	}
	// The /tree/7.2 line pins that scan to 7.2; the plain URL stays on the
	// default branch (empty Ref) — the per-line branch syntax in bulk.
	if got := refFor("https://github.com/symfony/symfony"); got != "7.2" {
		t.Errorf("symfony scan.Ref = %q, want 7.2 (from /tree/ line)", got)
	}
	if got := refFor("https://github.com/spf13/cobra"); got != "" {
		t.Errorf("cobra scan.Ref = %q, want empty (default branch)", got)
	}
}

func TestBulkImport_skipsDuplicates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	triage := db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&triage)
	s.DB.Create(&db.Repository{URL: "https://github.com/foo/one", Name: "one"})

	form := url.Values{"urls": {"https://github.com/foo/one.git\nhttps://github.com/foo/two.git"}}
	req := httptest.NewRequest("POST", "/repositories/bulk", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "1 added") || !strings.Contains(f.Title, "1 already present") {
		t.Errorf("flash missing expected counts: %+v", f)
	}

	var scans []db.Scan
	s.DB.Where("skill_id = ?", triage.ID).Find(&scans)
	if len(scans) != 1 {
		t.Errorf("want 1 new scan (only the new repo), got %d", len(scans))
	}
}

func TestBulkImport_rejectsNonHTTPS(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	triage := db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&triage)

	lines := "https://github.com/foo/ok.git\n" +
		"git@github.com:foo/bar.git\n" +
		"file:///etc/passwd\n" +
		"ext::nope\n"
	form := url.Values{"urls": {lines}}
	req := httptest.NewRequest("POST", "/repositories/bulk", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repos []db.Repository
	s.DB.Find(&repos)
	if len(repos) != 1 {
		t.Errorf("want 1 repo (only the https one), got %d", len(repos))
	}
	f := flashFrom(t, w)
	if !strings.Contains(f.Title, "1 added") || !strings.Contains(f.Title, "3 invalid") {
		t.Errorf("flash missing counts: %+v", f)
	}
}

func TestBulkImport_emptyIs422(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	form := url.Values{"urls": {"  \n\n\t\n"}}
	req := httptest.NewRequest("POST", "/repositories/bulk", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422 for empty submission, got %d", w.Code)
	}
}

func TestBulkImport_dialogRendered(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	body := w.Body.String()
	if !strings.Contains(body, `id="bulk-add-repo"`) {
		t.Error("layout missing bulk dialog")
	}
	if !strings.Contains(body, `name="urls"`) {
		t.Error("bulk dialog missing urls textarea")
	}
	if !strings.Contains(body, "Add multiple") {
		t.Error("add-repo dialog missing 'Add multiple' link to bulk dialog")
	}
	if !strings.Contains(body, `data-dialog="bulk-add-repo"`) {
		t.Error("'Add multiple' link not wired to bulk dialog")
	}
}

func TestCreateRepo_parsesGitHubTreeURL(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	triage := db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&triage)

	form := url.Values{"url": {"https://github.com/apache/airflow/tree/main/airflow-core"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repo db.Repository
	if err := s.DB.First(&repo).Error; err != nil {
		t.Fatal(err)
	}
	if repo.URL != "https://github.com/apache/airflow" {
		t.Errorf("repo.URL = %q, want clone URL without /tree/", repo.URL)
	}
	var scan db.Scan
	s.DB.First(&scan)
	if scan.SubPath != "airflow-core" {
		t.Errorf("scan.SubPath = %q, want airflow-core", scan.SubPath)
	}
}

func TestCreateRepo_branchPrecedence(t *testing.T) {
	// The URL always carries /tree/6.4; the ref field decides the outcome:
	// a non-empty field wins, a blank one falls back to the URL's branch.
	cases := []struct{ name, ref, wantRef string }{
		{"field overrides /tree/", "7.2", "7.2"},
		{"blank field falls back to /tree/", "  ", "6.4"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			s.DB.Create(&db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1})

			form := url.Values{"url": {"https://github.com/symfony/symfony/tree/6.4"}, "ref": {c.ref}}
			req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
			req.Host = testHost
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}

			var scan db.Scan
			if err := s.DB.First(&scan).Error; err != nil {
				t.Fatal(err)
			}
			if scan.Ref != c.wantRef {
				t.Errorf("scan.Ref = %q, want %q", scan.Ref, c.wantRef)
			}
		})
	}
}

func TestRepoBranches_rendersDatalistFromStub(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	var gotURL string
	s.listBranches = func(_ context.Context, cloneURL string) ([]string, error) {
		gotURL = cloneURL
		return []string{"6.4", "7.2", "main"}, nil
	}

	q := url.Values{"url": {"https://github.com/symfony/symfony/tree/6.4"}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/repositories/branches?"+q.Encode()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, b := range []string{"6.4", "7.2", "main"} {
		if !strings.Contains(body, `<option value="`+b+`">`) {
			t.Errorf("datalist missing option %q; body=%q", b, body)
		}
	}
	if gotURL != "https://github.com/symfony/symfony" {
		t.Errorf("listBranches got url %q, want normalized clone URL", gotURL)
	}
}

func TestRepoBranches_localURLSkipsLookup(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	called := false
	s.listBranches = func(context.Context, string) ([]string, error) {
		called = true
		return []string{"x"}, nil
	}

	q := url.Values{"url": {"/srv/local/repo"}}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/repositories/branches?"+q.Encode()))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if called {
		t.Error("a local path must not trigger a remote branch lookup")
	}
	if strings.Contains(w.Body.String(), "<option") {
		t.Errorf("local path should yield an empty datalist, got %q", w.Body.String())
	}
}

func TestRepoList_showsBranchTags(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	symfony := db.Repository{URL: "https://github.com/symfony/symfony", Name: "symfony"}
	s.DB.Create(&symfony)
	s.DB.Create(&db.Scan{RepositoryID: symfony.ID, Kind: "skill", SkillName: "triage", Status: db.ScanDone, Ref: "7.2"})

	cobra := db.Repository{URL: "https://github.com/spf13/cobra", Name: "cobra"}
	s.DB.Create(&cobra)
	s.DB.Create(&db.Scan{RepositoryID: cobra.ID, Kind: "skill", SkillName: "triage", Status: db.ScanDone, Ref: ""})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, `data-lucide="git-branch"`) || !strings.Contains(body, "7.2") {
		t.Errorf("repo list should tag symfony's scanned branch; body=%q", body)
	}
	// Exactly one tag: the default-only repo (empty Ref) must not get one.
	if n := strings.Count(body, `data-lucide="git-branch"`); n != 1 {
		t.Errorf("want exactly 1 branch tag, got %d", n)
	}
}

func TestRepoList_showsLastScanDate(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/example/repo", Name: "repo"}
	s.DB.Create(&repo)
	created := time.Date(2026, time.June, 16, 19, 15, 8, 0, time.UTC)
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID,
		Kind:         "skill",
		SkillName:    "triage",
		Status:       db.ScanDone,
		CreatedAt:    created,
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	row := requireRepoListRow(t, w.Body.String(), repo.ID)
	if !strings.Contains(row, "2026-06-16 19:15") {
		t.Errorf("repo row missing date-bearing last scan timestamp: %s", row)
	}
	if !strings.Contains(row, `title="2026-06-16 19:15:08 UTC"`) {
		t.Errorf("repo row missing full last scan tooltip: %s", row)
	}
}

func TestRepoList_statusScanPrecedence(t *testing.T) {
	type scanSeed struct {
		status db.ScanStatus
		at     time.Time
	}
	cases := []struct {
		name       string
		scans      []scanSeed
		wantBadge  string
		wantAbsent string
		wantLatest string
	}{
		{
			name: "running beats newer queued",
			scans: []scanSeed{
				{status: db.ScanRunning, at: time.Date(2026, time.July, 1, 9, 45, 0, 0, time.UTC)},
				{status: db.ScanQueued, at: time.Date(2026, time.July, 1, 9, 47, 0, 0, time.UTC)},
			},
			wantBadge:  "running",
			wantAbsent: "queued",
			wantLatest: "2026-07-01 09:47",
		},
		{
			name: "queued beats newer paused",
			scans: []scanSeed{
				{status: db.ScanQueued, at: time.Date(2026, time.July, 1, 10, 1, 0, 0, time.UTC)},
				{status: db.ScanPaused, at: time.Date(2026, time.July, 1, 10, 2, 0, 0, time.UTC)},
			},
			wantBadge:  "queued",
			wantLatest: "2026-07-01 10:02",
		},
		{
			name: "paused beats newer terminal",
			scans: []scanSeed{
				{status: db.ScanPaused, at: time.Date(2026, time.July, 1, 10, 3, 0, 0, time.UTC)},
				{status: db.ScanDone, at: time.Date(2026, time.July, 1, 10, 4, 0, 0, time.UTC)},
			},
			wantBadge:  "paused",
			wantLatest: "2026-07-01 10:04",
		},
		{
			name: "terminal only uses latest terminal",
			scans: []scanSeed{
				{status: db.ScanDone, at: time.Date(2026, time.July, 1, 10, 5, 0, 0, time.UTC)},
				{status: db.ScanFailed, at: time.Date(2026, time.July, 1, 10, 6, 0, 0, time.UTC)},
			},
			wantBadge:  "failed",
			wantLatest: "2026-07-01 10:06",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := db.Repository{URL: "https://github.com/homebrew/ruby-macho/" + strings.ReplaceAll(tc.name, " ", "-"), Name: "ruby-macho"}
			s.DB.Create(&repo)
			for i, seed := range tc.scans {
				s.DB.Create(&db.Scan{
					RepositoryID: repo.ID,
					Kind:         "skill",
					SkillName:    fmt.Sprintf("skill-%d", i),
					Status:       seed.status,
					CreatedAt:    seed.at,
				})
			}

			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq("GET", "/"))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			row := requireRepoListRow(t, w.Body.String(), repo.ID)
			if !strings.Contains(row, " "+tc.wantBadge+"</span>") {
				t.Errorf("repo row status = %s, want %s", row, tc.wantBadge)
			}
			if tc.wantAbsent != "" && strings.Contains(row, " "+tc.wantAbsent+"</span>") {
				t.Errorf("repo row should not render %s: %s", tc.wantAbsent, row)
			}
			if !strings.Contains(row, tc.wantLatest) {
				t.Errorf("last scan timestamp should still come from the newest scan: %s", row)
			}
		})
	}
}

func TestLayout_linksToProjectResources(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{
		`href="https://github.com/alpha-omega-security/scrutineer"`,
		`href="https://github.com/alpha-omega-security/scrutineer#readme"`,
		`href="https://github.com/alpha-omega-security/scrutineer/issues/new"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("layout missing project link %s", want)
		}
	}
}

func TestScansIndex_showsBranchTag(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/symfony/symfony", Name: "symfony"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: "triage",
		Status: db.ScanDone, StatusPriority: db.StatusPriorityFor(db.ScanDone), Ref: "7.2",
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `data-lucide="git-branch"`) || !strings.Contains(body, "7.2") {
		t.Errorf("scans index should tag the scan's branch (ref); body=%q", body)
	}
}

func TestScansIndex_noBranchTagForDefaultBranch(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/spf13/cobra", Name: "cobra"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: "triage",
		Status: db.ScanDone, StatusPriority: db.StatusPriorityFor(db.ScanDone), Ref: "",
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), `data-lucide="git-branch"`) {
		t.Error("a default-branch scan (empty Ref) must not render a branch tag")
	}
}

func TestScansIndex_maxTurnsScanShowsBadgeAndRetry(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/spf13/cobra", Name: "cobra"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "security-deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: "security-deep-dive",
		SkillID: &skill.ID, Status: db.ScanDone, StatusPriority: db.StatusPriorityFor(db.ScanDone),
		MaxTurnsHit: true, SessionID: "sess-1",
	}
	s.DB.Create(&scan)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	if !strings.Contains(body, "max turns") {
		t.Error("max-turns scan should render a badge")
	}
	if !strings.Contains(body, fmt.Sprintf(`/scans/%d/retry`, scan.ID)) {
		t.Error("max-turns scan should render retry action")
	}
}

func TestRetry_preservesScanFields(t *testing.T) {
	cases := []struct {
		name  string
		set   func(*db.Scan)
		check func(*testing.T, db.Scan)
	}{
		{"sub_path", func(sc *db.Scan) { sc.SubPath = "airflow-core" }, func(t *testing.T, f db.Scan) {
			if f.SubPath != "airflow-core" {
				t.Errorf("retry lost sub-path: got %q, want airflow-core", f.SubPath)
			}
		}},
		{"scan_group", func(sc *db.Scan) { sc.ScanGroup = "grp-7" }, func(t *testing.T, f db.Scan) {
			if f.ScanGroup != "grp-7" {
				t.Errorf("retry lost scan group: got %q, want grp-7", f.ScanGroup)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()

			repo := db.Repository{URL: "https://github.com/apache/airflow.git", Name: "airflow"}
			s.DB.Create(&repo)
			skill := db.Skill{Name: "security-deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
			s.DB.Create(&skill)
			orig := db.Scan{
				RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed,
				SkillID: &skill.ID, SkillName: "security-deep-dive",
				FinishedAt: new(time.Now()),
			}
			tc.set(&orig)
			s.DB.Create(&orig)

			req := httptest.NewRequest("POST", fmt.Sprintf("/scans/%d/retry", orig.ID), nil)
			req.Host = testHost
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("retry status %d: %s", w.Code, w.Body)
			}

			var fresh db.Scan
			s.DB.Where("id != ?", orig.ID).First(&fresh)
			tc.check(t, fresh)
		})
	}
}

func TestRetry_maxTurnsDoneScanResumesSession(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/apache/airflow.git", Name: "airflow"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "security-deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	orig := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillID: &skill.ID, SkillName: "security-deep-dive",
		SessionID: "sess-1", MaxTurnsHit: true, FinishedAt: new(time.Now()),
	}
	s.DB.Create(&orig)

	req := httptest.NewRequest("POST", fmt.Sprintf("/scans/%d/retry", orig.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}

	var fresh db.Scan
	s.DB.Where("id != ?", orig.ID).First(&fresh)
	if fresh.SessionID != "sess-1" {
		t.Errorf("retry session id = %q, want sess-1", fresh.SessionID)
	}
	if fresh.ResumedFromScanID == nil || *fresh.ResumedFromScanID != orig.ID {
		t.Errorf("retry resumed_from_scan_id = %v, want %d", fresh.ResumedFromScanID, orig.ID)
	}
	if fresh.MaxTurnsHit {
		t.Error("fresh retry should not inherit MaxTurnsHit before it runs")
	}
}

func TestRetry_preservesImportPayload(t *testing.T) {
	// An ingest scan's input is the uploaded payload, not ./src. Both
	// retry paths must carry it or the rerun stages no import/report.
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "ingest", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	payload := []byte(`{"vendor":"weird","items":[1]}`)
	orig := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed,
		SkillID: &skill.ID, SkillName: "ingest",
		ImportPayload: payload, FinishedAt: new(time.Now()),
	}
	s.DB.Create(&orig)

	req := httptest.NewRequest("POST", fmt.Sprintf("/scans/%d/retry", orig.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}

	var fresh db.Scan
	s.DB.Where("id != ?", orig.ID).First(&fresh)
	if string(fresh.ImportPayload) != string(payload) {
		t.Errorf("single retry lost import payload: got %q", fresh.ImportPayload)
	}

	// Bulk retry-failed path uses a column Select; it must include the
	// payload column too.
	s.DB.Where("id != ?", orig.ID).Delete(&db.Scan{})
	req = httptest.NewRequest("POST", "/scans/retry-failed", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("retry-failed status %d: %s", w.Code, w.Body)
	}

	var bulk db.Scan
	s.DB.Where("id != ?", orig.ID).First(&bulk)
	if string(bulk.ImportPayload) != string(payload) {
		t.Errorf("bulk retry lost import payload: got %q", bulk.ImportPayload)
	}
}

func TestScansRetryFailed(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	other := db.Skill{Name: "triage", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&other)

	mk := func(status db.ScanStatus, kind, skillName string, skillID *uint, subPath string) uint {
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: kind, Status: status,
			StatusPriority: db.StatusPriorityFor(status),
			SkillID:        skillID, SkillName: skillName, SubPath: subPath,
		}
		s.DB.Create(&sc)
		return sc.ID
	}
	failedDeep := mk(db.ScanFailed, "skill", "deep-dive", &skill.ID, "core")
	failedTriage := mk(db.ScanFailed, "skill", "triage", &other.ID, "core")
	failedNoSkill := mk(db.ScanFailed, "skill", "", nil, "core")
	failedMeta := mk(db.ScanFailed, "metadata", "", nil, "core")
	cancelledDeep := mk(db.ScanCancelled, "skill", "deep-dive", &skill.ID, "core")
	// Different sub-path so this done scan does NOT dedupe failedDeep.
	doneDeep := mk(db.ScanDone, "skill", "deep-dive", &skill.ID, "other")

	req := httptest.NewRequest("POST", "/scans/retry-failed", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/scans?status=failed" {
		t.Errorf("redirect = %q, want /scans?status=failed", loc)
	}

	originals := []uint{failedDeep, failedTriage, failedNoSkill, failedMeta, cancelledDeep, doneDeep}
	var fresh []db.Scan
	if err := s.DB.Where("id NOT IN ?", originals).Order("id").Find(&fresh).Error; err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 2 {
		t.Fatalf("expected 2 new queued scans, got %d", len(fresh))
	}
	for _, sc := range fresh {
		if sc.Status != db.ScanQueued {
			t.Errorf("new scan %d status = %s, want queued", sc.ID, sc.Status)
		}
		if sc.SubPath != "core" {
			t.Errorf("new scan %d sub_path = %q, want core", sc.ID, sc.SubPath)
		}
	}

	for _, id := range originals {
		var sc db.Scan
		s.DB.First(&sc, id)
		if sc.ID != id {
			t.Errorf("original scan %d went missing", id)
		}
	}
}

func TestScansRetryFailed_preservesScanFields(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Server, *db.Scan)
		check func(*testing.T, db.Scan)
	}{
		{"effort", func(s *Server, sc *db.Scan) {
			// Force the runtime default away from the scan's effort so a dropped
			// `effort` column in the retry Select would surface as "low", not "max".
			s.SetDefaultEffort("low")
			sc.Effort = "max"
		}, func(t *testing.T, f db.Scan) {
			if f.Effort != "max" {
				t.Errorf("retry lost effort: got %q, want max", f.Effort)
			}
		}},
		{"scan_group", func(_ *Server, sc *db.Scan) { sc.ScanGroup = "grp-7" }, func(t *testing.T, f db.Scan) {
			if f.ScanGroup != "grp-7" {
				t.Errorf("retry lost scan group: got %q, want grp-7", f.ScanGroup)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()

			repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
			s.DB.Create(&repo)
			skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
			s.DB.Create(&skill)
			orig := db.Scan{
				RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed,
				StatusPriority: db.StatusPriorityFor(db.ScanFailed),
				SkillID:        &skill.ID, SkillName: "deep-dive",
			}
			tc.setup(s, &orig)
			s.DB.Create(&orig)

			req := httptest.NewRequest("POST", "/scans/retry-failed", nil)
			req.Host = testHost
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}

			var fresh db.Scan
			if err := s.DB.Where("id != ?", orig.ID).First(&fresh).Error; err != nil {
				t.Fatal(err)
			}
			tc.check(t, fresh)
		})
	}
}

func TestScansRetryFailed_skipsAlreadyRetried(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)

	// A real Finding so the FK on Scan.FindingID resolves.
	seedScan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillID: &skill.ID, SkillName: "deep-dive"}
	s.DB.Create(&seedScan)
	seedFinding := db.Finding{ScanID: seedScan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "t", Severity: "High", Status: db.FindingNew}
	s.DB.Create(&seedFinding)

	mk := func(status db.ScanStatus, subPath string, findingID *uint) {
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", Status: status,
			StatusPriority: db.StatusPriorityFor(status),
			SkillID:        &skill.ID, SkillName: "deep-dive",
			SubPath:   subPath,
			FindingID: findingID,
		}
		s.DB.Create(&sc)
	}

	// Failed then a later queued retry with the SAME tuple → skip.
	mk(db.ScanFailed, "core", nil)
	mk(db.ScanQueued, "core", nil)

	// Failed then a later done scan with the SAME tuple → skip.
	mk(db.ScanFailed, "api", nil)
	mk(db.ScanDone, "api", nil)

	// Failed then a later running scan with the SAME tuple → skip.
	mk(db.ScanFailed, "", &seedFinding.ID)
	mk(db.ScanRunning, "", &seedFinding.ID)

	// Failed with no later live scan with the same tuple → retry.
	mk(db.ScanFailed, "lonely", nil)

	// Failed with a later done scan but DIFFERENT sub-path → retry.
	mk(db.ScanFailed, "left", nil)
	mk(db.ScanDone, "right", nil)

	// Failed with a later cancelled scan with same tuple → still retry
	// (cancelled does not count as "already running/done").
	mk(db.ScanFailed, "cancelled-tuple", nil)
	mk(db.ScanCancelled, "cancelled-tuple", nil)

	var maxID uint
	if err := s.DB.Model(&db.Scan{}).Select("MAX(id)").Row().Scan(&maxID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/scans/retry-failed", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var newScans []db.Scan
	if err := s.DB.Where("id > ?", maxID).Order("id").Find(&newScans).Error; err != nil {
		t.Fatal(err)
	}
	if len(newScans) != 3 {
		t.Fatalf("expected 3 fresh retries (freshA/B/C), got %d", len(newScans))
	}
	gotPaths := map[string]bool{}
	for _, sc := range newScans {
		if sc.Status != db.ScanQueued {
			t.Errorf("new scan %d status = %s, want queued", sc.ID, sc.Status)
		}
		gotPaths[sc.SubPath] = true
	}
	for _, want := range []string{"lonely", "left", "cancelled-tuple"} {
		if !gotPaths[want] {
			t.Errorf("missing fresh retry for sub_path=%q", want)
		}
	}
}

func TestScansRetryFailed_filtersBySkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	a := db.Skill{Name: "alpha", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	b := db.Skill{Name: "bravo", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&a)
	s.DB.Create(&b)

	// Distinct sub_paths keep the two alpha failures in separate tuples, so
	// both are eligible under the newest-failure-per-tuple dedup.
	mk := func(name string, sk uint, subPath string) {
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed,
			StatusPriority: db.StatusPriorityFor(db.ScanFailed),
			SkillID:        &sk, SkillName: name, SubPath: subPath,
		}
		s.DB.Create(&sc)
	}
	mk("alpha", a.ID, "one")
	mk("alpha", a.ID, "two")
	mk("bravo", b.ID, "")

	req := httptest.NewRequest("POST", "/scans/retry-failed?skill=alpha", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/scans?status=failed&skill=alpha" {
		t.Errorf("redirect = %q", loc)
	}

	var queued int64
	s.DB.Model(&db.Scan{}).Where("status = ? AND skill_id = ?", db.ScanQueued, a.ID).Count(&queued)
	if queued != 2 {
		t.Errorf("queued alpha scans = %d, want 2", queued)
	}
	var queuedBravo int64
	s.DB.Model(&db.Scan{}).Where("status = ? AND skill_id = ?", db.ScanQueued, b.ID).Count(&queuedBravo)
	if queuedBravo != 0 {
		t.Errorf("bravo should not have been retried, got %d new queued", queuedBravo)
	}
}

func TestScansRetryFailed_emptyAndButtonHidden(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	req := httptest.NewRequest("POST", "/scans/retry-failed", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d", w.Code)
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	if strings.Contains(w.Body.String(), "Retry all failed") {
		t.Error("button should not appear without status=failed filter")
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans?status=failed"))
	if strings.Contains(w.Body.String(), "Retry all failed") {
		t.Error("button should not appear when no failed scans exist")
	}
}

func TestScansRetryFailed_buttonVisibleWhenFiltered(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	sc := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed,
		StatusPriority: db.StatusPriorityFor(db.ScanFailed),
		SkillID:        &skill.ID, SkillName: "deep-dive",
	}
	s.DB.Create(&sc)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans?status=failed"))
	if !strings.Contains(w.Body.String(), "Retry all failed") {
		t.Error("button missing on failed-filtered view with failed scans")
	}
	if !strings.Contains(w.Body.String(), `action="/scans/retry-failed`) {
		t.Error("button form action missing")
	}
}

func TestRepoShow_retryFailedButton(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/rep", Name: "rep"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)

	// No failed scans yet: button should not render.
	body := getRepoPage(t, s, repo.ID)
	if strings.Contains(body, "Retry failed") {
		t.Error("button should not appear when no failed scans")
	}

	// One failed scan: button renders with count and the repo-scoped form
	// action so the handler comes back to this Scans tab on completion.
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed,
		StatusPriority: db.StatusPriorityFor(db.ScanFailed),
		SkillID:        &skill.ID, SkillName: "deep-dive",
	})
	body = getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "Retry failed (1)") {
		t.Errorf("expected 'Retry failed (1)' button; body=%s", body)
	}
	if !strings.Contains(body, fmt.Sprintf(`/scans/retry-failed?repository=%d`, repo.ID)) {
		t.Error("button form action should scope retry to this repository")
	}
}

func TestRepoShow_verifyAllButton(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/rep", Name: "rep"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: deepDiveSkillName}
	s.DB.Create(&scan)

	// A triaged finding does not count as awaiting verification, so no button.
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "T1", Title: "x", Severity: "High", Status: db.FindingTriaged})
	if body := getRepoPage(t, s, repo.ID); strings.Contains(body, "Verify all new") {
		t.Error("button should not appear when no findings await verification")
	}

	// Two new findings: button renders with the count and repo-scoped action.
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "N1", Title: "x", Severity: "High", Status: db.FindingNew})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID,
		FindingID: "N2", Title: "x", Severity: "High", Status: db.FindingNew})
	body := getRepoPage(t, s, repo.ID)
	if !strings.Contains(body, "Verify all new (2)") {
		t.Errorf("expected 'Verify all new (2)' button; body=%s", body)
	}
	if !strings.Contains(body, fmt.Sprintf(`/repositories/%d/verify-all`, repo.ID)) {
		t.Error("button form action should scope verify-all to this repository")
	}
}

func TestScansRetryFailed_repositoryScopeRedirects(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	rA := db.Repository{URL: "https://example.com/a", Name: "a"}
	s.DB.Create(&rA)
	rB := db.Repository{URL: "https://example.com/b", Name: "b"}
	s.DB.Create(&rB)
	skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	// Distinct sub_paths keep rA's two failures in separate tuples, so both
	// are eligible under the newest-failure-per-tuple dedup.
	mk := func(repoID uint, subPath string) {
		s.DB.Create(&db.Scan{
			RepositoryID: repoID, Kind: "skill", Status: db.ScanFailed,
			StatusPriority: db.StatusPriorityFor(db.ScanFailed),
			SkillID:        &skill.ID, SkillName: "deep-dive", SubPath: subPath,
		})
	}
	mk(rA.ID, "one")
	mk(rA.ID, "two")
	mk(rB.ID, "")

	req := httptest.NewRequest("POST",
		fmt.Sprintf("/scans/retry-failed?repository=%d", rA.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d", w.Code)
	}
	if got := w.Header().Get("Location"); got != fmt.Sprintf("/repositories/%d#rt3", rA.ID) {
		t.Errorf("redirect = %q, want repo Scans tab", got)
	}

	// Other repo's failed scan must remain untouched: only rA's two failed
	// scans should have been requeued.
	var queued int64
	s.DB.Model(&db.Scan{}).
		Where("status = ? AND repository_id = ?", db.ScanQueued, rA.ID).
		Count(&queued)
	if queued != 2 {
		t.Errorf("rA queued count = %d, want 2", queued)
	}
	s.DB.Model(&db.Scan{}).
		Where("status = ? AND repository_id = ?", db.ScanQueued, rB.ID).
		Count(&queued)
	if queued != 0 {
		t.Errorf("rB queued count = %d, want 0 (repo scope leaked)", queued)
	}
}

func TestJobs_defaultSortFloatsActiveFirst(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/order", Name: "order"}
	s.DB.Create(&repo)
	// Created in id order: done, running, queued. Default sort should
	// surface running, then queued, then done regardless of id.
	mk := func(st db.ScanStatus) uint {
		sc := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "x", Status: st, StatusPriority: db.StatusPriorityFor(st)}
		s.DB.Create(&sc)
		return sc.ID
	}
	doneID := mk(db.ScanDone)
	runID := mk(db.ScanRunning)
	queueID := mk(db.ScanQueued)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	pos := func(id uint) int { return strings.Index(body, fmt.Sprintf(`/scans/%d"`, id)) }
	r, q, d := pos(runID), pos(queueID), pos(doneID)
	if r < 0 || q < 0 || d < 0 {
		t.Fatalf("scan rows not rendered: running=%d queued=%d done=%d", r, q, d)
	}
	if r >= q || q >= d {
		t.Errorf("expected running < queued < done, got running=%d queued=%d done=%d", r, q, d)
	}
}

func TestScanCancel_queued(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanQueued}
	s.DB.Create(&scan)

	req := httptest.NewRequest("POST", fmt.Sprintf("/scans/%d/cancel", scan.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("cancel status %d: %s", w.Code, w.Body)
	}

	var got db.Scan
	s.DB.First(&got, scan.ID)
	if got.Status != db.ScanCancelled {
		t.Errorf("status = %s, want cancelled", got.Status)
	}
	if got.FinishedAt == nil {
		t.Error("FinishedAt not set")
	}
	if got.Error != "cancelled by user" {
		t.Errorf("error = %q", got.Error)
	}
}

func TestScanCancel_terminalRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, FinishedAt: new(time.Now())}
	s.DB.Create(&scan)

	req := httptest.NewRequest("POST", fmt.Sprintf("/scans/%d/cancel", scan.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
}

func TestScansPauseQueued(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	queued := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanQueued, StatusPriority: db.StatusPriorityFor(db.ScanQueued)}
	running := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanRunning, StatusPriority: db.StatusPriorityFor(db.ScanRunning)}
	s.DB.Create(&queued)
	s.DB.Create(&running)

	req := httptest.NewRequest("POST", "/scans/pause-queued", nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("pause status %d: %s", w.Code, w.Body)
	}
	if loc := w.Header().Get("Location"); loc != "/scans?status=paused" {
		t.Errorf("redirect = %q, want paused filter", loc)
	}

	var gotQueued, gotRunning db.Scan
	s.DB.First(&gotQueued, queued.ID)
	s.DB.First(&gotRunning, running.ID)
	if gotQueued.Status != db.ScanPaused {
		t.Errorf("queued status = %s, want paused", gotQueued.Status)
	}
	if gotQueued.StatusPriority != db.StatusPriorityFor(db.ScanPaused) {
		t.Errorf("paused priority = %d", gotQueued.StatusPriority)
	}
	if gotRunning.Status != db.ScanRunning {
		t.Errorf("running status = %s, want running", gotRunning.Status)
	}
}

func TestScanResumePaused(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanPaused,
		StatusPriority: db.StatusPriorityFor(db.ScanPaused),
		SkillID:        &skill.ID, SkillName: skill.Name, Error: "paused by user",
	}
	s.DB.Create(&scan)

	req := httptest.NewRequest("POST", fmt.Sprintf("/scans/%d/resume", scan.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("resume status %d: %s", w.Code, w.Body)
	}

	var got db.Scan
	s.DB.First(&got, scan.ID)
	if got.Status != db.ScanQueued {
		t.Errorf("status = %s, want queued", got.Status)
	}
	if got.StatusPriority != db.StatusPriorityFor(db.ScanQueued) {
		t.Errorf("priority = %d", got.StatusPriority)
	}
	if got.Error != "" {
		t.Errorf("error = %q, want cleared", got.Error)
	}
}

func TestJobs_showsAccountPauseResumeActions(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/x.git", Name: "x"}
	s.DB.Create(&repo)
	resetAt := time.Date(2026, 7, 1, 12, 30, 0, 0, time.UTC)
	// A scan auto-paused because the account hit an account-level Claude problem.
	// The banner should surface it and the Resume-paused action should be offered.
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanPaused,
		StatusPriority: db.StatusPriorityFor(db.ScanPaused),
		Error:          worker.AccountPausePrefix + " Queued scan paused automatically; resume once the account recovers.",
		PausedUntil:    &resetAt,
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{worker.AccountPausePrefix, "/scans/resume-paused", "2026-07-01 12:30 UTC"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in jobs body", want)
		}
	}
}

func TestSubprojectsRenderedOnRepoPage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/apache/airflow.git", Name: "airflow", FetchedAt: new(time.Now())}
	s.DB.Create(&repo)
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "airflow-core", Name: "airflow-core", Kind: "python-package", Description: "Core runtime"})
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "providers/amazon", Kind: "python-package", Description: "AWS provider"})

	req := httptest.NewRequest("GET", fmt.Sprintf("/repositories/%d", repo.ID), nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("repo show status %d", w.Code)
	}
	for _, want := range []string{"Subprojects", "airflow-core", "providers/amazon", "python-package", "Core runtime", "AWS provider", `name="sub_path"`} {
		if !strings.Contains(body, want) {
			t.Errorf("repo page missing %q", want)
		}
	}
}

func TestScanShowRenders(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "u", Name: "n"}
	s.DB.Create(&repo)
	now := time.Now()
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "claude", Status: db.ScanDone,
		StartedAt: &now, FinishedAt: &now, Report: "# hi", Log: "line1\n",
	}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rce", Severity: "High", Status: db.FindingTriaged})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans/1"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "# hi") || !strings.Contains(body, "line1") {
		t.Errorf("missing report/log: %s", body)
	}
	if !strings.Contains(body, "triaged") {
		t.Errorf("finding status not rendered in scan results table")
	}
}

func TestSettingsShow_rendersThemeOptions(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/settings"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, theme := range []string{"claude", "ocean-breeze", "catppuccin", "sunset-horizon", "midnight-bloom", "northern-lights"} {
		if !strings.Contains(body, `value="`+theme+`"`) {
			t.Errorf("settings page missing theme option %q", theme)
		}
	}
}

func TestSettingsShow_rendersAboutAndScannerFindings(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	s.Commit = "abcdef1234567890"

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/settings"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"Scanner findings", "About", "Scrutineer commit", "Backend (claude)", "Semgrep", "Zizmor", "Container runtime"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page missing %q", want)
		}
	}
	// Commit is rendered short (first 12 chars).
	if !strings.Contains(body, "abcdef123456") {
		t.Error("settings page missing shortened commit SHA")
	}
}

func TestSettingsUpdateTheme_setsCookie(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"theme": {"catppuccin"}}
	req := httptest.NewRequest("POST", "/settings/theme", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var found bool
	for _, sc := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, "theme=catppuccin") {
			found = true
		}
	}
	if !found {
		t.Errorf("theme cookie not set; cookies: %v", w.Header().Values("Set-Cookie"))
	}
}

func TestSettingsUpdateTheme_rejectsInvalid(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"theme": {"nope"}}
	req := httptest.NewRequest("POST", "/settings/theme", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422 for invalid theme, got %d", w.Code)
	}
}

func TestSettingsUpdateColorScheme_setsCookie(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"color_scheme": {"dark"}}
	req := httptest.NewRequest("POST", "/settings/color-scheme", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var found bool
	for _, sc := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, "color_scheme=dark") {
			found = true
		}
	}
	if !found {
		t.Errorf("color_scheme cookie not set; cookies: %v", w.Header().Values("Set-Cookie"))
	}
}

func TestSettingsUpdateColorScheme_rejectsInvalid(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"color_scheme": {"sepia"}}
	req := httptest.NewRequest("POST", "/settings/color-scheme", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422 for invalid color scheme, got %d", w.Code)
	}
}

func TestHumanDuration(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{999 * time.Millisecond, "0s"},
		{45 * time.Second, "45s"},
		{3 * time.Minute, "3m"},
		{2 * time.Hour, "2h"},
		{2*time.Hour + 30*time.Minute, "2h30m"},
		{50 * time.Hour, "2d"},
	} {
		if got := humanDuration(tc.d); got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestOrgActivityLess(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	a := orgRow{LastActivity: &early}
	b := orgRow{LastActivity: &late}
	n := orgRow{LastActivity: nil}

	if !orgActivityLess(a, b) || orgActivityLess(b, a) {
		t.Errorf("earlier activity should sort before later")
	}
	// nil (never active) sorts oldest, so it comes before any real timestamp
	// under the ascending comparator; dirLess flips this to newest-first.
	if !orgActivityLess(n, a) || orgActivityLess(a, n) {
		t.Errorf("nil LastActivity should sort before any real timestamp")
	}
	if orgActivityLess(n, orgRow{}) {
		t.Errorf("nil vs nil should not sort strictly-before")
	}
}

func TestSettingsUpdateEffort_setsDefault(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"effort": {"max"}}
	req := httptest.NewRequest("POST", "/settings/effort", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if got := s.DefaultEffort(); got != "max" {
		t.Errorf("DefaultEffort() = %q, want max", got)
	}
}

func TestSettingsUpdateEffort_rejectsInvalid(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"effort": {"extreme"}}
	req := httptest.NewRequest("POST", "/settings/effort", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422 for invalid effort, got %d", w.Code)
	}
}

func TestThemeCookie_appliedToRenderedPage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	req := localReq("GET", "/")
	req.AddCookie(&http.Cookie{Name: "theme", Value: "ocean-breeze"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `data-theme="ocean-breeze"`) {
		t.Error("theme cookie not reflected in data-theme attribute")
	}
}

func TestNavKey_settings(t *testing.T) {
	if got := navKey("/settings"); got != "settings" {
		t.Errorf("navKey(/settings) = %q, want settings", got)
	}
}

func TestScanShowSkillLink(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "u", Name: "n"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "security-deep-dive", Description: "d"}
	s.DB.Create(&skill)

	skillID := skill.ID
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillID: &skillID, SkillName: "security-deep-dive",
	}
	s.DB.Create(&scan)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/scans/%d", scan.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	wantLink := fmt.Sprintf(`/skills/%d`, skillID)
	if !strings.Contains(body, wantLink) {
		t.Errorf("scan show page missing skill link %q", wantLink)
	}
	if !strings.Contains(body, "security-deep-dive") {
		t.Errorf("scan show page missing skill name")
	}
}

func TestScanShowSkillNameWithoutID(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "u", Name: "n"}
	s.DB.Create(&repo)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName: "deleted-skill",
	}
	s.DB.Create(&scan)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/scans/%d", scan.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "deleted-skill") {
		t.Errorf("scan show page missing skill name for deleted skill")
	}
	if strings.Contains(body, `/skills/0`) {
		t.Errorf("scan show page should not link to skill when SkillID is nil")
	}
}

func TestMaintainerShow_displaysFindingStatus(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/m", Name: "m"}
	s.DB.Create(&repo)
	m := db.Maintainer{Login: "alice", Repositories: []db.Repository{repo}}
	s.DB.Create(&m)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "rce", Severity: "High", Status: db.FindingReported})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", fmt.Sprintf("/maintainers/%d", m.ID)))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "reported") {
		t.Errorf("finding status not rendered in maintainer findings tab")
	}
}

func TestRepoCreate_seedsOwnerAndFullNameFromURL(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Skill{Name: "triage", Active: true, Source: "test", Body: "test", OutputFile: "report.json", OutputKind: "freeform", Version: 1})

	form := url.Values{"url": {"https://github.com/simonw/datasette"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repo db.Repository
	if err := s.DB.Where("url = ?", "https://github.com/simonw/datasette").First(&repo).Error; err != nil {
		t.Fatalf("repo not created: %v", err)
	}
	if repo.Owner != "simonw" {
		t.Errorf("Owner = %q, want simonw (so orgs view groups before metadata fetch)", repo.Owner)
	}
	if repo.Name != "datasette" {
		t.Errorf("Name = %q, want datasette", repo.Name)
	}
	if repo.FullName != "simonw/datasette" {
		t.Errorf("FullName = %q, want simonw/datasette", repo.FullName)
	}
}

func TestRepoCreate_branchURLTriggersTriageWithRef(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Skill{Name: "triage", Active: true, Source: "test", Body: "test", OutputFile: "report.json", OutputKind: "freeform", Version: 1})

	form := url.Values{"url": {"https://github.com/apache/httpd/tree/2.4.x"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var scan db.Scan
	if err := s.DB.First(&scan).Error; err != nil {
		t.Fatalf("no scan created: %v", err)
	}
	if scan.Ref != "2.4.x" {
		t.Errorf("scan.Ref = %q, want %q", scan.Ref, "2.4.x")
	}
}

func TestRepoCreate_localDirectoryStoredAsFileURL(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Skill{Name: "triage", Active: true, Source: "test", Body: "b", OutputFile: "report.json", OutputKind: "freeform", Version: 1})

	dir := t.TempDir()
	form := url.Values{"url": {dir}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repo db.Repository
	if err := s.DB.Where("url = ?", "file://"+dir).First(&repo).Error; err != nil {
		t.Fatalf("local repo not created: %v", err)
	}
	if !repo.IsLocal() {
		t.Errorf("repo.IsLocal() = false, want true")
	}
}

func TestRepoCreate_localDirectorySkipsRequiresRemoteDefaultSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Skill{Name: "triage", Active: true, Source: "test", Body: "b",
		OutputFile: "report.json", OutputKind: "freeform", Version: 1, RequiresRemote: true})

	dir := t.TempDir()
	form := url.Values{"url": {dir}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repo db.Repository
	if err := s.DB.Where("url = ?", "file://"+dir).First(&repo).Error; err != nil {
		t.Fatalf("local repo not created: %v", err)
	}
	var scanCount int64
	s.DB.Model(&db.Scan{}).Where("repository_id = ?", repo.ID).Count(&scanCount)
	if scanCount != 0 {
		t.Errorf("scans created = %d, want 0 (default skill is RequiresRemote on a local repo)", scanCount)
	}
}

func TestRepoCreate_missingLocalPathRejected(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	form := url.Values{"url": {"/does/not/exist/scrutineer-test-xyz"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusSeeOther {
		t.Fatalf("expected error for missing local path, got 303")
	}
}

func TestRepoCreate_existingRepoWithBranchEnqueuesScan(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Skill{Name: "triage", Active: true, Source: "test", Body: "test", OutputFile: "report.json", OutputKind: "freeform", Version: 1})
	s.DB.Create(&db.Repository{URL: "https://github.com/apache/httpd", Name: "httpd"})

	form := url.Values{"url": {"https://github.com/apache/httpd/tree/2.4.x"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var scan db.Scan
	if err := s.DB.First(&scan).Error; err != nil {
		t.Fatalf("no scan created for existing repo with branch: %v", err)
	}
	if scan.Ref != "2.4.x" {
		t.Errorf("scan.Ref = %q, want %q", scan.Ref, "2.4.x")
	}
}

func TestRepoCreate_existingRepoWithoutBranchDoesNotEnqueue(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	s.DB.Create(&db.Skill{Name: "triage", Active: true, Source: "test", Body: "test", OutputFile: "report.json", OutputKind: "freeform", Version: 1})
	s.DB.Create(&db.Repository{URL: "https://github.com/apache/httpd", Name: "httpd"})

	form := url.Values{"url": {"https://github.com/apache/httpd"}}
	req := httptest.NewRequest("POST", "/repositories", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var count int64
	s.DB.Model(&db.Scan{}).Count(&count)
	if count != 0 {
		t.Errorf("expected no scan for plain re-add, got %d", count)
	}
}
