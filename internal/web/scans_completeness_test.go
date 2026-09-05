package web

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestJobsCompletenessFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/completeness", Name: "completeness"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	var scans []db.Scan
	for _, value := range []string{"complete", "partial", "unknown", "", "null"} {
		scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: "alpha", Status: db.ScanDone, Completeness: value}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		if value == "null" {
			if err := s.DB.Model(&scan).UpdateColumn("completeness", nil).Error; err != nil {
				t.Fatal(err)
			}
		}
		scans = append(scans, scan)
	}
	for _, tc := range []struct {
		value string
		want  []int
	}{
		{"", []int{0, 1, 2, 3, 4}},
		{"complete", []int{0}},
		{"partial", []int{1}},
		{"unknown", []int{2, 3, 4}},
	} {
		for _, hx := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hx=%t", tc.value, hx), func(t *testing.T) {
				r := localReq(http.MethodGet, "/scans?completeness="+tc.value+"&sort=repository")
				if hx {
					r.Header.Set("HX-Request", "true")
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					t.Fatalf("status = %d: %s", w.Code, w.Body)
				}
				body := w.Body.String()
				assertCompletenessRows(t, body, scans, tc.want, tc.value)
			})
		}
	}
}

func assertCompletenessRows(t *testing.T, body string, scans []db.Scan, want []int, value string) {
	t.Helper()
	for i, scan := range scans {
		if got := strings.Contains(body, fmt.Sprintf(`id="scan-%d"`, scan.ID)); got != slices.Contains(want, i) {
			t.Errorf("scan %d rendered = %t", scan.ID, got)
		}
	}
	if value != "" && !strings.Contains(body, `aria-current="true">`+value+`</a>`) {
		t.Error("selected completeness is not marked")
	}
	if value == "unknown" && strings.Count(body, `<span class="text-muted-foreground">unknown</span>`) != len(want) {
		t.Error("legacy and explicit unknown rows must display unknown")
	}
}

func TestJobsCompletenessPreservesCombinedFilters(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/combined-coverage"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	var matching []db.Scan
	for i := range perPage + 1 {
		scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: "alpha", Status: db.ScanDone, Completeness: "partial"}
		if i%2 == 0 {
			scan.SkillName = "bravo"
		}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		matching = append(matching, scan)
	}
	nonmatching := []db.Scan{
		{RepositoryID: repo.ID, SkillName: "charlie", Status: db.ScanDone, Completeness: "partial"},
		{RepositoryID: repo.ID, SkillName: "alpha", Status: db.ScanFailed, Completeness: "partial"},
		{RepositoryID: repo.ID, SkillName: "alpha", Status: db.ScanDone, Completeness: "complete"},
	}
	if err := s.DB.Create(&nonmatching).Error; err != nil {
		t.Fatal(err)
	}
	for _, hx := range []bool{false, true} {
		r := localReq(http.MethodGet, "/scans?skill=alpha,bravo&status=done&completeness=partial&sort=id&page=2")
		if hx {
			r.Header.Set("HX-Request", "true")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body)
		}
		body := html.UnescapeString(w.Body.String())
		if strings.Count(body, `id="scan-`) != 1 || !strings.Contains(body, fmt.Sprintf(`id="scan-%d"`, matching[0].ID)) {
			t.Fatal("page 2 should contain exactly the oldest matching scan")
		}
		for _, want := range []string{
			`href="/scans?completeness=partial&page=1&skill=alpha%2Cbravo&sort=id&status=done"`,
			`href="/scans?completeness=partial&skill=alpha%2Cbravo&sort=id.asc&status=done"`,
			`href="/scans?status=done&sort=id&completeness=partial"`,
			`href="/scans?skill=alpha%2cbravo&sort=id&completeness=partial"`,
			`href="/scans?skill=alpha%2cbravo&status=done&sort=repository&completeness=partial"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("missing filter-preserving link %s", want)
			}
		}
		if !hx && !strings.Contains(body, `hx-get="/scans?completeness=partial&page=2&skill=alpha%2Cbravo&sort=id&status=done"`) {
			t.Error("live refresh URL lost filters")
		}
	}
}

func TestScanCompletenessRejectsInvalidFilter(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/scans"},
		{http.MethodPost, "/scans/retry-failed"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq(tc.method, tc.path+"?completeness=invalid"))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", tc.path, w.Code)
		}
	}
}

func TestScansRetryFailedFiltersByCompleteness(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/retry-completeness"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: "alpha", Body: "b", OutputFile: "report.json", OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
	if err := s.DB.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"partial", "complete", "unknown"} {
		scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillID: &skill.ID, SkillName: skill.Name, Status: db.ScanFailed, Completeness: value, SubPath: value}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodGet, "/scans?skill=alpha&status=failed&completeness=partial"))
	if w.Code != http.StatusOK || !strings.Contains(html.UnescapeString(w.Body.String()), `action="/scans/retry-failed?skill=alpha&completeness=partial"`) {
		t.Fatal("retry form must carry the completeness selection")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq(http.MethodPost, "/scans/retry-failed?skill=alpha&completeness=partial"))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); got != "/scans?status=failed&skill=alpha&completeness=partial" {
		t.Errorf("redirect = %q", got)
	}
	var queued []db.Scan
	if err := s.DB.Where("status = ?", db.ScanQueued).Find(&queued).Error; err != nil {
		t.Fatal(err)
	}
	if len(queued) != 1 || queued[0].SubPath != "partial" {
		t.Fatalf("expected only the partial scan to be retried: %+v", queued)
	}
}
