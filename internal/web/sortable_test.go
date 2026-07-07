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

	// Explicit ascending reverses it: Low before Critical.
	body = get("?sort=severity.asc")
	if strings.Index(body, "low-one") > strings.Index(body, "crit-one") {
		t.Errorf("sort=severity.asc should put Low before Critical")
	}
}
