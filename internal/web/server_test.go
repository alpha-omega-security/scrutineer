package web

import (
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
)

func newTestServer(t *testing.T) (*Server, func()) {
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
	s, err := New(gdb, q, log, NewBroker())
	if err != nil {
		t.Fatal(err)
	}
	return s, func() { _ = sqldb.Close() }
}

func localReq(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	r.Host = "127.0.0.1:8080"
	return r
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

func TestOrgsList_sortOptions(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	mk := func(owner, name string, findings int) {
		r := db.Repository{URL: "https://example.com/" + owner + "/" + name, Name: name, Owner: owner}
		s.DB.Create(&r)
		if findings > 0 {
			scan := db.Scan{RepositoryID: r.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
			s.DB.Create(&scan)
			for i := 0; i < findings; i++ {
				s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: r.ID,
					Title: fmt.Sprintf("F-%d", i), Severity: "High"})
			}
		}
	}
	// acme: 1 repo, 5 findings. globex: 3 repos, 1 finding. umbrella: 2 repos, 0 findings.
	mk("acme", "one", 5)
	mk("globex", "a", 0)
	mk("globex", "b", 1)
	mk("globex", "c", 0)
	mk("umbrella", "x", 0)
	mk("umbrella", "y", 0)

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

	for _, tc := range []struct {
		sort string
		want []string
	}{
		{"name", []string{"acme", "globex", "umbrella"}},
		{"findings", []string{"acme", "globex", "umbrella"}},    // 5 > 1 > 0
		{"repos", []string{"globex", "umbrella", "acme"}},        // 3 > 2 > 1
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/orgs?sort="+tc.sort))
		if w.Code != 200 {
			t.Fatalf("sort=%s status %d", tc.sort, w.Code)
		}
		got := orderFromBody(w.Body.String(), "acme", "globex", "umbrella")
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
	scan := db.Scan{RepositoryID: r.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
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
	sa := db.Scan{RepositoryID: a.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&sa)
	sg := db.Scan{RepositoryID: g.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
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

func TestOrgReport_rendersFindingsAcrossRepos(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	r1 := db.Repository{URL: "https://example.com/acme/one", Name: "one", Owner: "acme", Description: "first repo"}
	s.DB.Create(&r1)
	r2 := db.Repository{URL: "https://example.com/acme/two", Name: "two", Owner: "acme"}
	s.DB.Create(&r2)
	_ = db.Repository{URL: "https://example.com/globex/svc", Name: "svc", Owner: "globex"}

	scan1 := db.Scan{RepositoryID: r1.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan1)
	s.DB.Create(&db.Finding{ScanID: scan1.ID, RepositoryID: r1.ID,
		Title: "SSRF in image fetch", Severity: "High", Location: "fetch.go:42",
		CWE: "CWE-918", Trace: "Attacker controls URL...", Status: db.FindingTriaged})
	s.DB.Create(&db.Finding{ScanID: scan1.ID, RepositoryID: r1.ID,
		Title: "Path traversal", Severity: "Medium", Location: "io.go:10"})

	scan2 := db.Scan{RepositoryID: r2.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
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

	scan1 := db.Scan{RepositoryID: r1.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
	s.DB.Create(&scan1)
	s.DB.Create(&db.Finding{ScanID: scan1.ID, RepositoryID: r1.ID,
		Title: "Open redirect in /api/sso", Severity: "High",
		Location: "src/route.ts:46", Rating: "**High.** Auth-adjacent; token leakage.",
		Trace: "should not appear in summary"})

	scan2 := db.Scan{RepositoryID: r2.ID, Kind: "skill", Status: db.ScanDone, SkillName: "x"}
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
		"rails", "django",
		"9.8", "5.4",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
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
			if i := strings.Index(body, want); i >= 0 {
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
	if w.Code != 204 {
		t.Fatalf("create status %d: %s", w.Code, w.Body)
	}
	if w.Header().Get("HX-Redirect") == "" {
		t.Error("expected HX-Redirect")
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
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !strings.HasPrefix(w.Header().Get("HX-Redirect"), "/scans/") {
		t.Errorf("expected HX-Redirect to scan, got %q", w.Header().Get("HX-Redirect"))
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
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var row db.Scan
	s.DB.Where("skill_id = ?", patch.ID).First(&row)
	if row.FindingID == nil || *row.FindingID != finding.ID {
		t.Errorf("scan FindingID = %v, want %d", row.FindingID, finding.ID)
	}
}

func TestFindingPatchDownload(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	finding := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, FindingID: "F1", Title: "x", Severity: "High", Status: db.FindingTriaged}
	s.DB.Create(&finding)

	fid := finding.ID
	finished := time.Now()
	report := `{"patch":"diff --git a/foo.go b/foo.go\n@@ -1 +1 @@\n-old\n+new\n","rationale":"adds guard","files_changed":["foo.go"],"base_commit":"abc123","tests_added":false}`
	patchScan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		SkillName:  "patch",
		FindingID:  &fid,
		FinishedAt: &finished,
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
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if w.Header().Get("HX-Redirect") != "/" {
		t.Errorf("HX-Redirect = %q", w.Header().Get("HX-Redirect"))
	}
	trigger := w.Header().Get("HX-Trigger")
	if !strings.Contains(trigger, "2 added") {
		t.Errorf("HX-Trigger toast missing '2 added': %s", trigger)
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

func TestBulkImport_skipsDuplicates(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	triage := db.Skill{Name: "triage", Description: "o", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&triage)
	s.DB.Create(&db.Repository{URL: "https://github.com/foo/one.git", Name: "one"})

	form := url.Values{"urls": {"https://github.com/foo/one.git\nhttps://github.com/foo/two.git"}}
	req := httptest.NewRequest("POST", "/repositories/bulk", strings.NewReader(form.Encode()))
	req.Host = testHost
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	trigger := w.Header().Get("HX-Trigger")
	if !strings.Contains(trigger, "1 added") || !strings.Contains(trigger, "1 already present") {
		t.Errorf("toast missing expected counts: %s", trigger)
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
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repos []db.Repository
	s.DB.Find(&repos)
	if len(repos) != 1 {
		t.Errorf("want 1 repo (only the https one), got %d", len(repos))
	}
	trigger := w.Header().Get("HX-Trigger")
	if !strings.Contains(trigger, "1 added") || !strings.Contains(trigger, "3 invalid") {
		t.Errorf("toast missing counts: %s", trigger)
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
	if !strings.Contains(body, "getElementById('bulk-add-repo').showModal()") {
		t.Error("'Add multiple' button does not open bulk dialog")
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
	if w.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}

	var repo db.Repository
	if err := s.DB.First(&repo).Error; err != nil {
		t.Fatal(err)
	}
	if repo.URL != "https://github.com/apache/airflow.git" {
		t.Errorf("repo.URL = %q, want clone URL without /tree/", repo.URL)
	}
	var scan db.Scan
	s.DB.First(&scan)
	if scan.SubPath != "airflow-core" {
		t.Errorf("scan.SubPath = %q, want airflow-core", scan.SubPath)
	}
}

func TestRetry_preservesSubPath(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://github.com/apache/airflow.git", Name: "airflow"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "security-deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	finished := time.Now()
	orig := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", Status: db.ScanFailed,
		SkillID: &skill.ID, SkillName: "security-deep-dive",
		SubPath: "airflow-core", FinishedAt: &finished,
	}
	s.DB.Create(&orig)

	req := httptest.NewRequest("POST", fmt.Sprintf("/scans/%d/retry", orig.ID), nil)
	req.Host = testHost
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}

	var fresh db.Scan
	s.DB.Where("id != ?", orig.ID).First(&fresh)
	if fresh.SubPath != "airflow-core" {
		t.Errorf("retry lost sub-path: got %q, want airflow-core", fresh.SubPath)
	}
}

func TestSubprojectsRenderedOnRepoPage(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	now := time.Now()
	repo := db.Repository{URL: "https://github.com/apache/airflow.git", Name: "airflow", FetchedAt: &now}
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

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans/1"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, "# hi") || !strings.Contains(body, "line1") {
		t.Errorf("missing report/log: %s", body)
	}
}
