package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

// TestBreadcrumbsFollowTheEntityHierarchy pins the trail on detail pages to
// Section > entity > sub-page, with a finding filed under its repository.
func TestBreadcrumbsFollowTheEntityHierarchy(t *testing.T) {
	s, done := newTestServer(t)
	defer done()

	repo := db.Repository{Name: "widget-server", URL: "https://example.com/acme/widget-server"}
	s.DB.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone}
	s.DB.Create(&scan)
	f := db.Finding{ScanID: scan.ID, RepositoryID: repo.ID, Title: "crumbs"}
	s.DB.Create(&f)
	skill := db.Skill{Name: "crumb-skill", Active: true}
	s.DB.Create(&skill)

	repoCrumb := `<a href="/repositories/` + strconv.FormatUint(uint64(repo.ID), 10) + `" class="hover:text-foreground">widget-server</a>`
	cases := []struct {
		name   string
		path   string
		want   []string
		absent []string
	}{
		{
			name:   "finding",
			path:   "/findings/" + strconv.FormatUint(uint64(f.ID), 10),
			want:   []string{`<a href="/" class="hover:text-foreground">Repositories</a>`, repoCrumb, `<span class="text-foreground">Finding #` + strconv.FormatUint(uint64(f.ID), 10) + `</span>`},
			absent: []string{`<a href="/findings" class="hover:text-foreground">Findings</a>`},
		},
		{
			name:   "scan",
			path:   "/scans/" + strconv.FormatUint(uint64(scan.ID), 10),
			want:   []string{`<a href="/" class="hover:text-foreground">Repositories</a>`, repoCrumb, `<span class="text-foreground">Scan #` + strconv.FormatUint(uint64(scan.ID), 10) + `</span>`},
			absent: []string{`>scan #` + strconv.FormatUint(uint64(scan.ID), 10) + `</span>`},
		},
		{
			name:   "skill",
			path:   "/skills/" + strconv.FormatUint(uint64(skill.ID), 10),
			want:   []string{`<a href="/skills" class="hover:text-foreground">Skills</a>`, `<span class="text-foreground">crumb-skill</span>`},
			absent: []string{`</a> / crumb-skill`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, localReq("GET", tc.path))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d", w.Code)
			}
			body := w.Body.String()
			end := strings.Index(body, "</ol>")
			if end < 0 {
				t.Fatal("no breadcrumb trail rendered")
			}
			trail := body[:end]
			for _, want := range tc.want {
				if !strings.Contains(trail, want) {
					t.Errorf("trail missing %q", want)
				}
			}
			for _, a := range tc.absent {
				if strings.Contains(body, a) {
					t.Errorf("page still contains %q", a)
				}
			}
		})
	}
}
