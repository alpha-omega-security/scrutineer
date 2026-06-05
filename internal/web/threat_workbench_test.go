package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestNormaliseThreatModel(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty allowed", "", "", false},
		{"whitespace allowed", "   \n  ", "", false},
		{"valid object", `{"a":1}`, "{\n  \"a\": 1\n}", false},
		{"valid indented input", "{\n  \"a\": 1\n}", "{\n  \"a\": 1\n}", false},
		{"invalid json", "{not json}", "", true},
		{"trailing comma rejected", `{"a":1,}`, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normaliseThreatModel(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

const ddReportA = `{
  "inventory": [
    {"id":"S1","location":"lib/a.rb:10","class":"Command execution"},
    {"id":"S2","location":"lib/b.rb:20","class":"Path handling"},
    {"id":"S3","location":"lib/c.rb:30","class":"Deserialisation"},
    {"id":"S4","location":"lib/d.rb:40","class":"Network"}
  ],
  "findings": [
    {"sinks":["S1"],"title":"shell injection in run","severity":"High"}
  ],
  "ruled_out": [
    {"sinks":["S2"],"reason":"out_of_model_trusted_input: path is operator-set\nlonger explanation"},
    {"sinks":["S3"],"reason":"by_design_disclaimed: caller's job"},
    {"sinks":["S4"],"reason":"known_non_finding: gated behind allowlist"}
  ]
}`

const ddReportB = `{
  "inventory": [
    {"id":"S1","location":"lib/a.rb:10","class":"Command execution"},
    {"id":"S2","location":"lib/b.rb:20","class":"Path handling"},
    {"id":"S3","location":"lib/c.rb:30","class":"Deserialisation"},
    {"id":"S5","location":"lib/e.rb:50","class":"Template"}
  ],
  "findings": [
    {"sinks":["S2"],"title":"path traversal in open","severity":"Medium"}
  ],
  "ruled_out": [
    {"sinks":["S1"],"reason":"out_of_model_trusted_input: argv only from operator"},
    {"sinks":["S3"],"reason":"out_of_model_adversary: requires local access"},
    {"sinks":["S5"],"reason":"known_non_finding"}
  ]
}`

func TestSinkOutcomes(t *testing.T) {
	out := sinkOutcomes(ddReportA)
	if len(out) != 4 {
		t.Fatalf("len = %d, want 4", len(out))
	}
	a := out["lib/a.rb:10"]
	if !a.Finding || a.Title != "shell injection in run" || a.Severity != "High" {
		t.Errorf("S1 outcome = %+v", a)
	}
	b := out["lib/b.rb:20"]
	if b.Finding || b.Reason != "out_of_model_trusted_input: path is operator-set" {
		t.Errorf("S2 outcome = %+v (reason should be first line only)", b)
	}
}

func TestSinkOutcomes_invalidJSON(t *testing.T) {
	if got := sinkOutcomes("not json"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestDiffDeepDive(t *testing.T) {
	d := diffDeepDive(ddReportA, ddReportB)

	if len(d.NowReported) != 1 || d.NowReported[0].Location != "lib/b.rb:20" {
		t.Errorf("NowReported = %+v", d.NowReported)
	}
	if d.NowReported[0].After != "Medium: path traversal in open" {
		t.Errorf("NowReported[0].After = %q", d.NowReported[0].After)
	}

	if len(d.NowSuppressed) != 1 || d.NowSuppressed[0].Location != "lib/a.rb:10" {
		t.Errorf("NowSuppressed = %+v", d.NowSuppressed)
	}
	if d.NowSuppressed[0].Before != "High: shell injection in run" {
		t.Errorf("NowSuppressed[0].Before = %q", d.NowSuppressed[0].Before)
	}

	if len(d.ReasonChanged) != 1 || d.ReasonChanged[0].Location != "lib/c.rb:30" {
		t.Errorf("ReasonChanged = %+v", d.ReasonChanged)
	}

	if d.OnlyInCurr != 1 {
		t.Errorf("OnlyInCurr = %d, want 1 (lib/e.rb:50)", d.OnlyInCurr)
	}
	if d.OnlyInPrev != 1 {
		t.Errorf("OnlyInPrev = %d, want 1 (lib/d.rb:40)", d.OnlyInPrev)
	}
	if d.Unchanged != 0 {
		t.Errorf("Unchanged = %d, want 0", d.Unchanged)
	}
	if d.Empty() {
		t.Error("Empty() = true, want false")
	}
}

func TestDiffDeepDive_identicalReports(t *testing.T) {
	d := diffDeepDive(ddReportA, ddReportA)
	if !d.Empty() {
		t.Errorf("identical reports should diff empty, got %+v", d)
	}
	if d.Unchanged != 4 {
		t.Errorf("Unchanged = %d, want 4", d.Unchanged)
	}
}

func TestRepoThreatModelSave(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r", Name: "r"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/threat-model", repo.ID),
		url.Values{"threat_model": {`{"spec_version":1,"adversaries":{"in_scope":["network peer"]}}`}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if !strings.Contains(got.ThreatModel, `"spec_version": 1`) {
		t.Errorf("ThreatModel not saved/normalised: %q", got.ThreatModel)
	}
}

func TestRepoThreatModelSave_rejectsInvalidJSON(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r2", Name: "r2"}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/threat-model", repo.ID),
		url.Values{"threat_model": {"{not json"}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ThreatModel != "" {
		t.Errorf("ThreatModel = %q, want empty after rejected save", got.ThreatModel)
	}
}

func TestRepoThreatModelRun_savesAndEnqueues(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r3", Name: "r3"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Skill{Name: deepDiveSkillName, Active: true, Body: "b", OutputFile: "report.json"})

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/threat-model/run", repo.ID),
		url.Values{"threat_model": {`{"spec_version":1}`}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ThreatModel == "" {
		t.Error("ThreatModel not saved")
	}
	var scan db.Scan
	if err := s.DB.Where("repository_id = ? AND skill_name = ?", repo.ID, deepDiveSkillName).First(&scan).Error; err != nil {
		t.Fatalf("no deep-dive scan enqueued: %v", err)
	}
}

func TestRepoThreatModelClear(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r4", Name: "r4", ThreatModel: `{"x":1}`}
	s.DB.Create(&repo)

	w := postForm(t, s, fmt.Sprintf("/repositories/%d/threat-model/clear", repo.ID), url.Values{})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d", w.Code)
	}
	var got db.Repository
	s.DB.First(&got, repo.ID)
	if got.ThreatModel != "" {
		t.Errorf("ThreatModel = %q, want empty", got.ThreatModel)
	}
}

func TestLoadWorkbench_seedsFromScanWhenNoOverride(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r5", Name: "r5"}
	s.DB.Create(&repo)

	wb := loadWorkbench(s.DB, &repo, `{"seed":true}`)
	if wb.HasOverride {
		t.Error("HasOverride = true, want false")
	}
	if wb.Model != `{"seed":true}` {
		t.Errorf("Model = %q, want seed", wb.Model)
	}
}

func TestLoadWorkbench_prefersOverrideAndDiffs(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r6", Name: "r6", ThreatModel: `{"override":true}`}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanDone, Report: ddReportA})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanDone, Report: ddReportB})

	wb := loadWorkbench(s.DB, &repo, `{"seed":true}`)
	if !wb.HasOverride {
		t.Error("HasOverride = false, want true")
	}
	if wb.Model != `{"override":true}` {
		t.Errorf("Model = %q, want override", wb.Model)
	}
	if len(wb.Runs) != 2 {
		t.Fatalf("Runs len = %d, want 2", len(wb.Runs))
	}
	if len(wb.Diff.NowReported) != 1 || len(wb.Diff.NowSuppressed) != 1 {
		t.Errorf("Diff = %+v", wb.Diff)
	}
}

// TestLoadWorkbench_ignoresSubPathDeepDives pins that a subproject
// deep-dive does not leak into the root-scoped workbench history.
// Without the sub_path filter, a recent subproject run would show its
// inventory drift as a model effect against the previous root run.
func TestLoadWorkbench_ignoresSubPathDeepDives(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r-sub", Name: "r-sub"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanDone, Report: ddReportA})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanDone, Report: ddReportB, SubPath: "packages/inner"})

	wb := loadWorkbench(s.DB, &repo, "")
	if len(wb.Runs) != 1 {
		t.Fatalf("Runs len = %d, want 1 (sub_path run must be filtered out)", len(wb.Runs))
	}
	if wb.Runs[0].SubPath != "" {
		t.Errorf("Runs[0].SubPath = %q, want root", wb.Runs[0].SubPath)
	}
}

// TestRepoShow_subPathThreatModelDoesNotSeedRootWorkbench pins that a
// threat-model scan with a non-empty SubPath does not become the root
// workbench's editor seed. The workbench override lives on Repository
// and runs at root scope, so a subproject threat model is the wrong
// starting point.
func TestRepoShow_subPathThreatModelDoesNotSeedRootWorkbench(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r-sub-seed", Name: "r-sub-seed"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, SkillName: threatModelSkillName,
		Status: db.ScanDone, Report: `{"sub":"path","model":"x"}`,
		SubPath: "packages/inner",
	})

	r := localReq("GET", "/repositories/"+strconv.Itoa(int(repo.ID)))
	r.SetPathValue("id", strconv.Itoa(int(repo.ID)))
	w := httptest.NewRecorder()
	s.repoShow(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), `"sub":"path"`) {
		t.Error("workbench editor seeded from sub_path threat-model scan; should be empty at root")
	}
}

func TestRepoShow_rendersWorkbenchTab(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://github.com/o/r7", Name: "r7", ThreatModel: `{"x":1}`}
	s.DB.Create(&repo)
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanDone, Report: ddReportA})
	s.DB.Create(&db.Scan{RepositoryID: repo.ID, SkillName: deepDiveSkillName, Status: db.ScanDone, Report: ddReportB})

	r := localReq("GET", "/repositories/"+strconv.Itoa(int(repo.ID)))
	r.SetPathValue("id", strconv.Itoa(int(repo.ID)))
	w := httptest.NewRecorder()
	s.repoShow(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, want := range []string{"Workbench", "Now reported", "Now suppressed", "lib/b.rb:20"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}
