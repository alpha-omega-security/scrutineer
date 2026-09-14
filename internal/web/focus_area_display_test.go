package web

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestJobsCombinedBatchFiltersSurviveLiveRefresh(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/combined-batch"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	scans := []db.Scan{
		{SkillName: "alpha", ScanGroup: "batch-a", Completeness: "partial"},
		{SkillName: "bravo", ScanGroup: "batch-a", Completeness: "partial"},
		{SkillName: "charlie", ScanGroup: "batch-a", Completeness: "partial"},
		{SkillName: "alpha", ScanGroup: "batch-b", Completeness: "partial"},
		{SkillName: "alpha", ScanGroup: "batch-a", Completeness: "complete"},
	}
	for i := range scans {
		scans[i].RepositoryID = repo.ID
		scans[i].Status = db.ScanFailed
		scans[i].FocusArea = fmt.Sprintf(`{"name":"Area %d","paths":["config/**"]}`, i)
		if err := s.DB.Create(&scans[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, hx := range []bool{false, true} {
		r := localReq(http.MethodGet, "/scans?skill=alpha,bravo&status=failed&completeness=partial&group=batch-a")
		if hx {
			r.Header.Set("HX-Request", "true")
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		body := html.UnescapeString(w.Body.String())
		for i, scan := range scans {
			if got := strings.Contains(body, fmt.Sprintf(`id="scan-%d"`, scan.ID)); got != (i < 2) {
				t.Errorf("HX=%v: scan %d presence = %v", hx, scan.ID, got)
			}
		}
		for _, want := range []string{
			"Focus area", "Area 0", "Area 1", "config/**", "2 skills", "Showing one batch:",
			`href="/scans?group=batch-a"`,
			`/scans/retry-failed?skill=alpha%2cbravo&completeness=partial&group=batch-a`,
			`/scans?skill=alpha%2cbravo&status=failed&sort=repository&completeness=partial&group=batch-a`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("HX=%v: missing %q", hx, want)
			}
		}
	}
}

func TestScansRetryFailed_batchScoped(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/laravel/pint", Name: "pint"}
	s.DB.Create(&repo)
	skill := db.Skill{Name: "security-deep-dive", Description: "x", Body: "b", Active: true, Source: "ui", Version: 1}
	s.DB.Create(&skill)
	for _, group := range []string{"focus-1", "focus-2"} {
		s.DB.Create(&db.Scan{
			RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: skill.Name, SkillID: &skill.ID,
			Status: db.ScanFailed, StatusPriority: db.StatusPriorityFor(db.ScanFailed),
			ScanGroup: group,
			FocusArea: `{"name":"Area ` + group + `","paths":["app/a.php"],"surface":"cli input"}`,
		})
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", "/scans/retry-failed?group=focus-1"))
	if w.Code != http.StatusOK && w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var requeued []db.Scan
	s.DB.Where("status = ?", db.ScanQueued).Find(&requeued)
	if len(requeued) != 1 {
		t.Fatalf("retried %d scans, want only the batch's one", len(requeued))
	}
	if requeued[0].ScanGroup != "focus-1" {
		t.Errorf("retried batch %q, want focus-1", requeued[0].ScanGroup)
	}
}

func TestScansIndex_noFocusColumnWithoutFannedOutScans(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/spf13/cobra", Name: "cobra"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: "security-deep-dive",
		Status: db.ScanDone, StatusPriority: db.StatusPriorityFor(db.ScanDone),
	})

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "Focus area") {
		t.Error("unscoped scans must not add a focus-area column")
	}
}

func TestScanFocus(t *testing.T) {
	for _, raw := range []string{"", "not json", `{"name":" "}`} {
		if got := scanFocus(db.Scan{FocusArea: raw}); got != (focusAreaView{}) {
			t.Errorf("focus(%q) = %+v, want empty view", raw, got)
		}
	}
	got := scanFocus(db.Scan{
		FocusArea: `{"name":" Worker Spawning ","paths":["a.php","b/**"],"surface":" process args "}`,
		ScanGroup: "batch-a",
	})
	want := focusAreaView{Name: "Worker Spawning", Paths: "a.php, b/**", Surface: "process args", Group: "batch-a"}
	if got != want {
		t.Errorf("focus = %+v, want %+v", got, want)
	}
	if tip := got.Tooltip(); tip != "paths: a.php, b/**\nsurface: process args\nbatch: batch-a" {
		t.Errorf("tooltip = %q", tip)
	}
	if got := scanFocus(db.Scan{FocusArea: `{"name":"Legacy Area","paths":[]}`}); got.Name != "Legacy Area" {
		t.Errorf("legacy area = %+v", got)
	}
}
