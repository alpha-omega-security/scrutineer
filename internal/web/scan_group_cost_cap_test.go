package web

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func seedGroupBudgetRepo(t *testing.T, s *Server) db.Repository {
	t.Helper()
	repo := db.Repository{URL: "https://github.com/foo/bar", Name: "bar"}
	s.DB.Create(&repo)
	for _, name := range []string{reconSkillName, historySkillName, "embedded-native", threatModelSkillName, "semgrep", "betterleaks", deepDiveSkillName} {
		s.DB.Create(&db.Skill{Name: name, Body: "b", OutputFile: "r.json",
			OutputKind: "freeform", Version: 1, Active: true, Source: "ui"})
	}
	s.DB.Create(&db.Subproject{RepositoryID: repo.ID, Path: "a", Name: "a"})
	return repo
}

func postGroupLaunch(s *Server, repo db.Repository, route string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", fmt.Sprintf("/repositories/%d/%s", repo.ID, route), strings.NewReader(form.Encode()))
	asOperator(req)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestGroupLaunchHandlers_storeGroupBudget(t *testing.T) {
	cases := []struct {
		name  string
		route string
		form  url.Values
	}{
		{"new scan", "scan", url.Values{}},
		{"diff rescan", "scan", url.Values{"rescan_mode": {db.ScanRescanModeDiff}}},
		{"scan all", "scan-all", url.Values{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := seedGroupBudgetRepo(t, s)
			tc.form.Set("group_max_cost_usd", " 7.5 ")
			if w := postGroupLaunch(s, repo, tc.route, tc.form); w.Code >= http.StatusBadRequest {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			var scans []db.Scan
			s.DB.Where("repository_id = ?", repo.ID).Find(&scans)
			if len(scans) == 0 || scans[0].ScanGroup == "" {
				t.Fatalf("scans = %+v, want grouped scans", scans)
			}
			for _, sc := range scans {
				if sc.ScanGroup != scans[0].ScanGroup {
					t.Errorf("scan %d group %q, want %q", sc.ID, sc.ScanGroup, scans[0].ScanGroup)
				}
				if sc.MaxCostUSD != 0 {
					t.Errorf("scan %d MaxCostUSD = %v, want 0", sc.ID, sc.MaxCostUSD)
				}
			}
			got, err := db.ScanGroupBudgetFor(s.DB, scans[0].ScanGroup)
			if err != nil || got != 7.5 {
				t.Errorf("group budget = %v, %v, want 7.5", got, err)
			}
			var rows int64
			s.DB.Model(&db.ScanGroupBudget{}).Count(&rows)
			if rows != 1 {
				t.Errorf("budget rows = %d, want 1", rows)
			}
		})
	}
}

func TestGroupLaunchHandlers_noFieldStoresNoBudget(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedGroupBudgetRepo(t, s)
	if w := postGroupLaunch(s, repo, "scan", url.Values{"group_max_cost_usd": {""}}); w.Code >= http.StatusBadRequest {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var rows int64
	s.DB.Model(&db.ScanGroupBudget{}).Count(&rows)
	if rows != 0 {
		t.Errorf("budget rows = %d, want 0", rows)
	}
}

func TestGroupLaunchHandlers_rejectInvalidGroupBudget(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := seedGroupBudgetRepo(t, s)
	forms := map[string]url.Values{
		"scan":     {},
		"scan-all": {},
	}
	for route, form := range forms {
		for _, bad := range []string{"-1", "abc", "NaN", "Inf"} {
			form.Set("group_max_cost_usd", bad)
			if w := postGroupLaunch(s, repo, route, form); w.Code != http.StatusUnprocessableEntity {
				t.Errorf("%s group_max_cost_usd %q: status %d, want 422", route, bad, w.Code)
			}
		}
	}
	diff := url.Values{"rescan_mode": {db.ScanRescanModeDiff}, "group_max_cost_usd": {"-1"}}
	if w := postGroupLaunch(s, repo, "scan", diff); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("diff rescan: status %d, want 422", w.Code)
	}
	var scans, rows int64
	s.DB.Model(&db.Scan{}).Count(&scans)
	s.DB.Model(&db.ScanGroupBudget{}).Count(&rows)
	if scans != 0 || rows != 0 {
		t.Errorf("%d scans and %d budgets, want none", scans, rows)
	}
}

func TestEnqueueSkillWith_rejectsInvalidGroupMaxCostUSD(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)
	for _, bad := range []float64{-1, math.NaN(), math.Inf(1)} {
		_, err := s.enqueueSkillWith(t.Context(), repo.ID, skill.ID, ScanOpts{ScanGroup: "g", GroupMaxCostUSD: bad})
		if !errors.Is(err, ErrInvalidMaxCost) {
			t.Errorf("GroupMaxCostUSD %v: err = %v, want ErrInvalidMaxCost", bad, err)
		}
	}
}

func TestEnqueueSkillWith_groupBudgetNeedsGroup(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)
	if _, err := s.enqueueSkillWith(t.Context(), repo.ID, skill.ID, ScanOpts{GroupMaxCostUSD: 5}); err != nil {
		t.Fatal(err)
	}
	var rows int64
	s.DB.Model(&db.ScanGroupBudget{}).Count(&rows)
	if rows != 0 {
		t.Errorf("budget rows = %d, want 0 without a group", rows)
	}
}

func TestScanShow_groupCostCap(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)
	mk := func(group string, cost float64) db.Scan {
		sc := db.Scan{
			RepositoryID: repo.ID, Kind: "skill", SkillName: skill.Name, SkillID: &skill.ID,
			Status: db.ScanDone, StatusPriority: db.StatusPriorityFor(db.ScanDone),
			ScanGroup: group, CostUSD: cost,
		}
		s.DB.Create(&sc)
		return sc
	}
	scan := mk("grp", 1.25)
	mk("grp", 2)
	mk("other", 9)
	other := mk("nobudget", 1)
	if err := db.SetScanGroupBudget(s.DB, "grp", repo.ID, 10); err != nil {
		t.Fatal(err)
	}

	get := func(id uint) string {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, localReq("GET", "/scans/"+strconv.Itoa(int(id))))
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body)
		}
		return w.Body.String()
	}
	body := get(scan.ID)
	for _, want := range []string{"Group cost cap", "$10.00", "$3.25 spent"} {
		if !strings.Contains(body, want) {
			t.Errorf("scan page lacks %q", want)
		}
	}
	if strings.Contains(get(other.ID), "Group cost cap") {
		t.Error("scan without a group budget shows a group cost cap")
	}
}

func TestScanShow_groupCostCappedNotice(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo, skill := seedEgressPolicyFixture(t, s)
	scan := db.Scan{
		RepositoryID: repo.ID, Kind: "skill", SkillName: skill.Name, SkillID: &skill.ID,
		Status: db.ScanDone, StatusPriority: db.StatusPriorityFor(db.ScanDone),
		ScanGroup: "grp", CostCapped: true, CostUSD: 1,
	}
	s.DB.Create(&scan)
	if err := db.SetScanGroupBudget(s.DB, "grp", repo.ID, 4); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/scans/"+strconv.Itoa(int(scan.ID))))
	if !strings.Contains(w.Body.String(), "group cost cap of $4.00") {
		t.Errorf("scan page lacks the group cap notice: %s", w.Body)
	}
}
