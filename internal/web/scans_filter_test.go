package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func TestParseScanSkillFilter(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantNames []string
		wantValue string
		wantLabel string
	}{
		{name: "empty", raw: "", wantNames: []string{}},
		{name: "only separators", raw: " , , ", wantNames: []string{}},
		{name: "single", raw: " security-deep-dive ", wantNames: []string{"security-deep-dive"}, wantValue: "security-deep-dive", wantLabel: "security-deep-dive"},
		{name: "multiple normalized", raw: " alpha, bravo,,alpha, charlie ", wantNames: []string{"alpha", "bravo", "charlie"}, wantValue: "alpha,bravo,charlie", wantLabel: "3 skills"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseScanSkillFilter(test.raw)
			if !slices.Equal(got.names, test.wantNames) {
				t.Errorf("names = %v, want %v", got.names, test.wantNames)
			}
			if got.value() != test.wantValue {
				t.Errorf("value() = %q, want %q", got.value(), test.wantValue)
			}
			if got.label() != test.wantLabel {
				t.Errorf("label() = %q, want %q", got.label(), test.wantLabel)
			}
		})
	}
}

func TestJobs_filtersBySingleSkill(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/single-filter", Name: "single-filter"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	makeScan := func(name string) db.Scan {
		scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: name, Status: db.ScanDone,
			StatusPriority: db.StatusPriorityFor(db.ScanDone)}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		return scan
	}
	alpha := makeScan("alpha")
	bravo := makeScan("bravo")

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans?skill=alpha"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body)
	}
	body := w.Body.String()
	if !strings.Contains(body, fmt.Sprintf(`/scans/%d"`, alpha.ID)) {
		t.Errorf("matching alpha scan %d is missing", alpha.ID)
	}
	if strings.Contains(body, fmt.Sprintf(`/scans/%d"`, bravo.ID)) {
		t.Errorf("non-matching bravo scan %d was rendered", bravo.ID)
	}
	if !strings.Contains(body, `aria-current="true">alpha</a>`) {
		t.Error("single skill filter is not marked as current")
	}
}

func TestJobs_filtersByMultipleSkillsAndPreservesNormalizedQuery(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/filter", Name: "filter"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	var alphaID, bravoID uint
	for i := range 21 {
		name := "alpha"
		if i >= 11 {
			name = "bravo"
		}
		scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: name, Status: db.ScanDone,
			StatusPriority: db.StatusPriorityFor(db.ScanDone)}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
		if name == "alpha" {
			alphaID = scan.ID
		} else {
			bravoID = scan.ID
		}
	}
	charlie := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillName: "charlie", Status: db.ScanDone,
		StatusPriority: db.StatusPriorityFor(db.ScanDone)}
	if err := s.DB.Create(&charlie).Error; err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans?skill=%20alpha%20,%20bravo,,alpha&status=done&sort=skill"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, id := range []uint{alphaID, bravoID} {
		if !strings.Contains(body, fmt.Sprintf(`/scans/%d"`, id)) {
			t.Errorf("matching scan %d is missing", id)
		}
	}
	if strings.Contains(body, fmt.Sprintf(`/scans/%d"`, charlie.ID)) {
		t.Errorf("non-matching charlie scan %d was rendered", charlie.ID)
	}
	if !strings.Contains(body, "2 skills") {
		t.Error("combined filter label is missing")
	}
	if !strings.Contains(body, `aria-label="Skills: alpha,bravo"`) {
		t.Error("combined filter accessible label does not list the selected skills")
	}
	if !strings.Contains(body, "skill=alpha%2Cbravo") {
		t.Error("normalized skill filter is missing from sort or pagination links")
	}
	if strings.Contains(body, `aria-current="true">alpha</a>`) || strings.Contains(body, `aria-current="true">bravo</a>`) {
		t.Error("combined filter marked an individual skill as current")
	}
}

func TestScansRetryFailed_filtersByMultipleSkills(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/retry-filter", Name: "retry-filter"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	skills := make(map[string]db.Skill)
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		skill := db.Skill{Name: name, Description: name, Body: "b", OutputFile: "report.json",
			OutputKind: "freeform", Version: 1, Active: true, Source: "ui"}
		if err := s.DB.Create(&skill).Error; err != nil {
			t.Fatal(err)
		}
		skills[name] = skill
		scan := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, SkillID: &skill.ID, SkillName: name,
			Status: db.ScanFailed, StatusPriority: db.StatusPriorityFor(db.ScanFailed)}
		if err := s.DB.Create(&scan).Error; err != nil {
			t.Fatal(err)
		}
	}

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("POST", "/scans/retry-failed?skill=%20alpha%20,bravo,,alpha"))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", w.Code, w.Body)
	}
	if got := w.Header().Get("Location"); got != "/scans?status=failed&skill=alpha%2Cbravo" {
		t.Errorf("redirect = %q, want normalized combined filter", got)
	}
	for _, test := range []struct {
		name string
		want int64
	}{{"alpha", 1}, {"bravo", 1}, {"charlie", 0}} {
		var queued int64
		if err := s.DB.Model(&db.Scan{}).
			Where("status = ? AND skill_id = ?", db.ScanQueued, skills[test.name].ID).
			Count(&queued).Error; err != nil {
			t.Fatal(err)
		}
		if queued != test.want {
			t.Errorf("queued %s scans = %d, want %d", test.name, queued, test.want)
		}
	}
}
