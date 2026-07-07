package web

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestSplitSort(t *testing.T) {
	for _, tc := range []struct {
		token, defDir string
		wantKey       string
		wantDir       string
	}{
		{"severity.asc", "", "severity", "asc"},
		{"severity.desc", "", "severity", "desc"},
		{"severity", "", "severity", ""},
		{"severity", "desc", "severity", "desc"},
		{"", "asc", "", "asc"},
		// An unrecognised direction suffix is not a direction: the whole token
		// is treated as the key, so it falls through to a handler's default.
		{"severity.bogus", "", "severity.bogus", ""},
	} {
		key, dir := splitSort(tc.token, tc.defDir)
		if key != tc.wantKey || dir != tc.wantDir {
			t.Errorf("splitSort(%q,%q) = (%q,%q), want (%q,%q)",
				tc.token, tc.defDir, key, dir, tc.wantKey, tc.wantDir)
		}
	}
}

func TestSortCtxURL(t *testing.T) {
	c := sortCtx{path: "/findings", query: url.Values{
		"sort": {"severity"}, "status": {"all"}, "page": {"3"},
	}}

	// The active column (default desc) flips to asc, drops the page so
	// re-sorting starts at page 1, and preserves other filters.
	got := c.URL("severity", "desc")
	if !strings.Contains(got, "sort=severity.asc") {
		t.Errorf("active column should flip to asc: %s", got)
	}
	if strings.Contains(got, "page=") {
		t.Errorf("re-sort should drop page: %s", got)
	}
	if !strings.Contains(got, "status=all") {
		t.Errorf("filters should be preserved: %s", got)
	}

	// An inactive column applies its own default direction as a bare token.
	got = c.URL("title", "asc")
	if !strings.Contains(got, "sort=title") || strings.Contains(got, "title.") {
		t.Errorf("inactive column should use bare default token: %s", got)
	}
}

func TestSortCtxDir(t *testing.T) {
	active := sortCtx{query: url.Values{"sort": {"severity"}}}
	if got := active.Dir("severity", "desc"); got != "desc" {
		t.Errorf("active-at-default dir = %q, want desc", got)
	}
	if got := active.Dir("title", "asc"); got != "" {
		t.Errorf("inactive column dir = %q, want empty", got)
	}
	pinned := sortCtx{query: url.Values{"sort": {"severity.asc"}}}
	if got := pinned.Dir("severity", "desc"); got != "asc" {
		t.Errorf("pinned dir = %q, want asc", got)
	}
}

// TestFindings_sortDirection proves the folded-token direction actually
// reaches the ORDER BY: the same column reverses between .asc and its default.
func TestFindings_sortDirection(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://example.com/dir", Name: "dir"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone, SkillName: "security-deep-dive"}
	s.DB.Create(&scan)
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "crit-one", Severity: "Critical", Status: db.FindingNew})
	s.DB.Create(&db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "low-one", Severity: "Low", Status: db.FindingNew})

	get := func(q string) string {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/findings"+q))
		if w.Code != 200 {
			t.Fatalf("GET /findings%s status %d", q, w.Code)
		}
		return w.Body.String()
	}

	// Default severity direction is desc: Critical before Low.
	body := get("?sort=severity")
	if strings.Index(body, "crit-one") > strings.Index(body, "low-one") {
		t.Errorf("sort=severity should put Critical before Low")
	}
	// The active header must offer the flip to ascending.
	if !strings.Contains(body, "sort=severity.asc") {
		t.Errorf("active severity header should link to the ascending flip")
	}
	// Columns are clickable via the shared partial.
	if !strings.Contains(body, `class="th-sort"`) {
		t.Errorf("headers should render as th-sort links")
	}
	// The active column exposes its direction to assistive tech.
	if !strings.Contains(body, `aria-sort="descending"`) {
		t.Errorf("active severity header should set aria-sort=descending")
	}
	// Inactive sortable columns (e.g. Title) show the idle affordance so the
	// header reads as sortable before any click.
	if !strings.Contains(body, `data-lucide="chevrons-up-down"`) {
		t.Errorf("inactive sortable headers should show the idle chevron")
	}

	// Explicit ascending reverses it: Low before Critical.
	body = get("?sort=severity.asc")
	if strings.Index(body, "low-one") > strings.Index(body, "crit-one") {
		t.Errorf("sort=severity.asc should put Low before Critical")
	}
}

// TestSort_derivedColumns covers the columns that sort via a correlated
// subquery or denormalised key rather than a plain column: repo Last scan /
// Status and the scans Findings count.
func TestSort_derivedColumns(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repoOld := db.Repository{URL: "https://x/repo-old", Name: "repo-old"}
	repoNew := db.Repository{URL: "https://x/repo-new", Name: "repo-new"}
	s.DB.Create(&repoOld)
	s.DB.Create(&repoNew)
	// repoOld scanned first (lower id) and finished; repoNew scanned later
	// (higher id) and still running, with more findings.
	s.DB.Create(&db.Scan{RepositoryID: repoOld.ID, Kind: "skill", Status: db.ScanDone,
		StatusPriority: db.StatusPriorityFor(db.ScanDone), FindingsCount: 2})
	s.DB.Create(&db.Scan{RepositoryID: repoNew.ID, Kind: "skill", Status: db.ScanRunning,
		StatusPriority: db.StatusPriorityFor(db.ScanRunning), FindingsCount: 9})

	get := func(path string) string {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", path))
		if w.Code != 200 {
			t.Fatalf("GET %s status %d", path, w.Code)
		}
		return w.Body.String()
	}
	before := func(body, a, b string) bool { return strings.Index(body, a) < strings.Index(body, b) }

	// Last scan: most-recently-scanned repo first, reversed under .asc.
	if b := get("/?sort=scanned"); !before(b, "repo-new", "repo-old") {
		t.Errorf("sort=scanned should put the most-recently-scanned repo first")
	}
	if b := get("/?sort=scanned.asc"); !before(b, "repo-old", "repo-new") {
		t.Errorf("sort=scanned.asc should reverse")
	}
	// Status: running (rank 0) before done (rank 3) under the asc default.
	if b := get("/?sort=status"); !before(b, "repo-new", "repo-old") {
		t.Errorf("sort=status should rank the running repo before the done repo")
	}
	// Scans Findings: the higher findings_count first under the desc default.
	if b := get("/scans?sort=findings"); !before(b, "repo-new", "repo-old") {
		t.Errorf("/scans?sort=findings should rank the 9-finding scan before the 2-finding scan")
	}
}

// TestSort_maliciousParamFallsBackSafely feeds hostile ?sort= values (unknown
// keys, SQLi payloads, bad directions) to the index handlers and asserts they
// fall back to the default order — HTTP 200, no error — and that no injected
// statement executed (the tables survive with their row counts intact). This
// is the regression guard for the switch dispatch + orderByExpr: if a later
// refactor lets request text reach an ORDER BY, a DROP/DELETE payload would
// drop a table and fail these assertions loudly.
func TestSort_maliciousParamFallsBackSafely(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{URL: "https://x/keep", Name: "keep"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, Kind: "skill", Status: db.ScanDone,
		StatusPriority: db.StatusPriorityFor(db.ScanDone), FindingsCount: 1})

	payloads := []string{
		"name); DROP TABLE repositories;--",
		"scanned; DROP TABLE scans",
		"status.asc'); DROP TABLE repositories;--",
		"scanned.desc; DELETE FROM scans",
		"findings) UNION SELECT 1--",
		"status.evil",
		"' OR '1'='1",
		"(SELECT 1)",
	}
	// Both the repo index (/) and the scans index (/scans) go through the same
	// allowlists, so exercise both with every payload.
	for _, base := range []string{"/", "/scans"} {
		for _, p := range payloads {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq("GET", base+"?sort="+url.QueryEscape(p)))
			if w.Code != 200 {
				t.Errorf("GET %s?sort=%q: status %d, want 200 (should fall back, not error)", base, p, w.Code)
			}
			// If any payload had been executed, a table would be gone and these
			// counts would error or read zero.
			var repos, scans int64
			if err := s.DB.Model(&db.Repository{}).Count(&repos).Error; err != nil || repos != 1 {
				t.Fatalf("after %s?sort=%q: repositories table harmed (count=%d err=%v)", base, p, repos, err)
			}
			if err := s.DB.Model(&db.Scan{}).Count(&scans).Error; err != nil || scans != 1 {
				t.Fatalf("after %s?sort=%q: scans table harmed (count=%d err=%v)", base, p, scans, err)
			}
		}
	}
}
