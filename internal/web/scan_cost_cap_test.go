package web

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/worker"
)

func postSkillScanForm(s *Server, repo db.Repository, skill db.Skill, maxCost string) *httptest.ResponseRecorder {
	form := url.Values{"skill_id": {strconv.Itoa(int(skill.ID))}, "max_cost_usd": {maxCost}}
	req := httptest.NewRequest("POST", "/repositories/"+strconv.Itoa(int(repo.ID))+"/skill-scan", strings.NewReader(form.Encode()))
	asOperator(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestEnqueueSkillWith_storesMaxCostUSD(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)

	id, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, ScanOpts{MaxCostUSD: 3.5})
	if err != nil {
		t.Fatal(err)
	}
	var got db.Scan
	s.DB.First(&got, id)
	if got.MaxCostUSD != 3.5 || got.CostCapped {
		t.Errorf("MaxCostUSD %v CostCapped %v, want 3.5 and false", got.MaxCostUSD, got.CostCapped)
	}
}

func TestEnqueueSkillWith_rejectsInvalidMaxCostUSD(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)

	for _, v := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		_, err := s.enqueueSkillWith(context.Background(), repo.ID, skill.ID, ScanOpts{MaxCostUSD: v})
		if !errors.Is(err, ErrInvalidMaxCost) {
			t.Errorf("MaxCostUSD %v: err = %v, want ErrInvalidMaxCost", v, err)
		}
	}
	if n := len(skillScans(s)); n != 0 {
		t.Errorf("%d scans created, want 0", n)
	}
}

func TestSkillRun_maxCostUSDForm(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)

	if w := postSkillScanForm(s, repo, skill, " 2.5 "); w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if w := postSkillScanForm(s, repo, skill, ""); w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	scans := skillScans(s)
	if len(scans) != 2 || scans[0].MaxCostUSD != 2.5 || scans[1].MaxCostUSD != 0 {
		t.Fatalf("scans = %+v, want caps [2.5, 0]", scans)
	}
	for _, bad := range []string{"-1", "abc", "NaN", "Inf"} {
		if w := postSkillScanForm(s, repo, skill, bad); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("max_cost_usd %q: status %d, want 422", bad, w.Code)
		}
	}
	if n := len(skillScans(s)); n != 2 {
		t.Errorf("%d scans, want 2", n)
	}
}

func TestAPIRunSkill_maxCostUSD(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, caller := seedRunningScan(t, s)
	skill := db.Skill{Name: "metadata", Description: "m", Body: "b", OutputFile: "report.json", Version: 1, Active: true, Source: "ui"}
	s.DB.Create(&skill)

	w := runSkillAPIJSON(t, s, repo, caller, "metadata", `{"max_cost_usd": 1.25}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var got db.Scan
	s.DB.Where("skill_id = ?", skill.ID).First(&got)
	if got.MaxCostUSD != 1.25 {
		t.Errorf("MaxCostUSD = %v, want 1.25", got.MaxCostUSD)
	}
	if !strings.Contains(w.Body.String(), `"max_cost_usd":1.25`) {
		t.Errorf("response lacks max_cost_usd: %s", w.Body)
	}

	s.DB.Model(&got).Update("status", db.ScanDone)
	w = runSkillAPIJSON(t, s, repo, caller, "metadata", `{"max_cost_usd": -1}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("negative cap: status %d, want 400: %s", w.Code, w.Body)
	}
}

func TestScanRetry_carriesMaxCostUSD(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)
	if w := postSkillScanForm(s, repo, skill, "4"); w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	first := skillScans(s)[0]
	s.DB.Model(&first).Updates(map[string]any{"status": db.ScanFailed, "status_priority": db.StatusPriorityFor(db.ScanFailed)})

	if w := retryScan(s, first.ID); w.Code != http.StatusSeeOther {
		t.Fatalf("retry status %d: %s", w.Code, w.Body)
	}
	scans := skillScans(s)
	if len(scans) != 2 || scans[1].MaxCostUSD != 4 {
		t.Fatalf("scans = %+v, want the retry to carry the cap 4", scans)
	}

}

func TestScansRetryFailed_carriesMaxCostUSD(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)
	failed := db.Scan{RepositoryID: repo.ID, Kind: worker.JobSkill, Status: db.ScanFailed,
		StatusPriority: db.StatusPriorityFor(db.ScanFailed), SkillID: &skill.ID, SkillName: skill.Name, MaxCostUSD: 4}
	s.DB.Create(&failed)

	w := httptest.NewRecorder()
	s.scansRetryFailed(w, localReq("POST", "/scans/retry-failed"))
	var retry db.Scan
	if err := s.DB.Where("parent_scan_id = ?", failed.ID).First(&retry).Error; err != nil {
		t.Fatalf("no retry created: %v", err)
	}
	if retry.MaxCostUSD != 4 {
		t.Errorf("retry MaxCostUSD = %v, want 4", retry.MaxCostUSD)
	}
}

func TestScanShow_costCappedBadgeAndNotice(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: skill.Name, SkillID: &skill.ID,
		Status: db.ScanDone, StatusPriority: db.StatusPriorityFor(db.ScanDone),
		CostCapped: true, MaxCostUSD: 2, CostUSD: 2.1, SessionID: "sess-1",
	}
	s.DB.Create(&scan)

	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans/"+strconv.Itoa(int(scan.ID))))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, body)
	}
	for _, want := range []string{"cost cap</span>", "Cost cap", "reached its cost cap of", "/scans/" + strconv.Itoa(int(scan.ID)) + "/retry"} {
		if !strings.Contains(body, want) {
			t.Errorf("scan page lacks %q", want)
		}
	}

	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans"))
	if !strings.Contains(w.Body.String(), "cost cap</span>") {
		t.Error("scans index lacks the cost cap badge")
	}
}

func TestScanSummaryAndExport_costCapFields(t *testing.T) {
	sc := db.Scan{MaxCostUSD: 1.5, CostCapped: true}
	for name, m := range map[string]map[string]any{"summary": scanSummary(sc), "export": scanExport(sc)} {
		if m["max_cost_usd"] != 1.5 || m["cost_capped"] != true {
			t.Errorf("%s: max_cost_usd %v cost_capped %v", name, m["max_cost_usd"], m["cost_capped"])
		}
	}
}
