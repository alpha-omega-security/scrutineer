package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
	"scrutineer/internal/worker"
)

type fallbackAuditRunner struct{}

func (fallbackAuditRunner) SkillDir(root, name string) string {
	return filepath.Join(root, "skills", name)
}

func (fallbackAuditRunner) RunSkill(_ context.Context, job worker.SkillJob, _ func(worker.Event)) (worker.SkillResult, error) {
	if job.Name != deepDiveSkillName {
		return worker.SkillResult{}, fmt.Errorf("unexpected skill: %s", job.Name)
	}
	return worker.SkillResult{Commit: "abc", Report: `{"findings":[]}`}, nil
}

func TestQueuedThreatModelPrereqFailureRunsFallback(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/prereq-fallback", Name: "prereq-fallback"}
	prereq := db.Skill{Name: "embedded-native", Body: "Inspect native code", Active: true}
	threatModel := db.Skill{Name: threatModelSkillName, Body: "Model threats", Requires: prereq.Name, Active: true}
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "Audit", Requires: "threat-model\nembedded-native", OutputFile: "report.json", OutputKind: "findings", Active: true}
	for _, row := range []any{&repo, &prereq, &threatModel, &deepDive} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	failed := db.Scan{RepositoryID: repo.ID, SkillID: &prereq.ID, SkillName: prereq.Name, Kind: worker.JobSkill, Status: db.ScanFailed, ScanGroup: "triage-1"}
	parent := db.Scan{RepositoryID: repo.ID, SkillID: &threatModel.ID, SkillName: threatModel.Name, Kind: worker.JobSkill, Status: db.ScanQueued, ScanGroup: failed.ScanGroup, SubPath: "services/api", Ref: "release"}
	for _, row := range []any{&failed, &parent} {
		if err := s.DB.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	w := s.Worker
	w.Log, w.DataDir, w.Runner = s.Log, t.TempDir(), fallbackAuditRunner{}
	w.PrepareRepoSrc = func(_ context.Context, _, _, root string, _ func(worker.Event)) (string, error) {
		return "abc", os.MkdirAll(filepath.Join(root, "src", parent.SubPath), 0o755)
	}
	w.Register(s.Queue)
	s.Queue.Reconfigure(1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	onFinalized := w.OnScanFinalized
	w.OnScanFinalized = func(scan *db.Scan) {
		onFinalized(scan)
		if scan.SkillName == deepDiveSkillName {
			cancel()
		}
	}
	if err := s.Queue.Enqueue(ctx, worker.JobSkill, parent.ID, worker.PrioScan); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() { s.Queue.Start(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("fallback audit did not complete")
	}
	if err := s.DB.First(&parent, parent.ID).Error; err != nil {
		t.Fatal(err)
	}
	if parent.Status != db.ScanFailed || !strings.Contains(parent.Error, "embedded-native") {
		t.Fatalf("parent status = %s, error = %s", parent.Status, parent.Error)
	}
	var children []db.Scan
	if err := s.DB.Where("repository_id = ? AND skill_id = ?", repo.ID, deepDive.ID).Find(&children).Error; err != nil {
		t.Fatal(err)
	}
	if len(children) != 1 {
		t.Fatalf("fallback scans = %d, want 1", len(children))
	}
	child := children[0]
	if child.Status != db.ScanDone || child.Report != `{"findings":[]}` || child.FocusArea != "" || child.ScanGroup != parent.ScanGroup || child.SubPath != parent.SubPath || child.Ref != parent.Ref {
		t.Fatalf("unexpected fallback: %+v", child)
	}
	if child.FallbackFromScanID == nil || *child.FallbackFromScanID != parent.ID {
		t.Fatalf("fallback source = %v, want %d", child.FallbackFromScanID, parent.ID)
	}
	var recipe worker.ScanRecipe
	if err := json.Unmarshal([]byte(child.Recipe), &recipe); err != nil {
		t.Fatal(err)
	}
	if recipe.FallbackFromScanID == nil || *recipe.FallbackFromScanID != parent.ID {
		t.Fatalf("recipe lost fallback source: %s", child.Recipe)
	}
}

func TestFallbackAuditRetryPreservesSource(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprint(bulk), func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := db.Repository{URL: "https://example.com/fallback-retry", Name: "fallback-retry"}
			skill := db.Skill{Name: deepDiveSkillName, Body: "Audit", Active: true}
			for _, row := range []any{&repo, &skill} {
				if err := s.DB.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			source := db.Scan{RepositoryID: repo.ID, SkillName: threatModelSkillName, Status: db.ScanFailed}
			if err := s.DB.Create(&source).Error; err != nil {
				t.Fatal(err)
			}
			failed := db.Scan{RepositoryID: repo.ID, SkillID: &skill.ID, SkillName: skill.Name, Kind: worker.JobSkill, Status: db.ScanFailed, FallbackFromScanID: &source.ID}
			if err := s.DB.Create(&failed).Error; err != nil {
				t.Fatal(err)
			}
			path := fmt.Sprintf("/scans/%d/retry", failed.ID)
			if bulk {
				path = "/scans/retry-failed"
			}
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, localReq(http.MethodPost, path))
			if response.Code != http.StatusSeeOther {
				t.Fatalf("HTTP %d: %s", response.Code, response.Body)
			}
			var retry db.Scan
			if err := s.DB.Where("parent_scan_id = ?", failed.ID).First(&retry).Error; err != nil {
				t.Fatal(err)
			}
			if retry.FallbackFromScanID == nil || *retry.FallbackFromScanID != source.ID {
				t.Fatalf("retry lost fallback source: %+v", retry)
			}
		})
	}
}

func TestAutoEnqueueFocusAreaDeepDives(t *testing.T) {
	withTestModels(t, []Model{
		{Name: "Test High", ID: "test-high"},
		{Name: "Test Max", ID: "test-max"},
	})
	s, done := newTestServer(t)
	defer done()
	if err := db.SetSetting(s.DB, db.SettingModelTierMax, "test-max"); err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{
		URL: "https://example.com/focus", Name: "focus", ScanConfig: `focus_areas:
  - name: XML parser
    paths: [lib/xml*.c]
    surface: untrusted XML
  - name: CLI parser
    paths: [cmd/**]
    surface: operator arguments
`,
	}
	s.DB.Create(&repo)
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json", OutputKind: "findings", Active: true, Source: "ui", Model: ModelTierMax}
	s.DB.Create(&deepDive)
	// The parent threat-model scan stores a resolved concrete model id (high
	// tier). The fan-out must not inherit it — the deep-dive skill declares
	// max, and that is what focus-area scans should run on. #879.
	parent := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: threatModelSkillName, ScanGroup: "triage-1", Effort: "high", Model: "test-high"}
	s.DB.Create(&parent)

	s.autoEnqueueFocusAreaDeepDives(&parent)
	s.autoEnqueueFocusAreaDeepDives(&parent) // completion delivery is idempotent.

	var scans []db.Scan
	if err := s.DB.Where("repository_id = ? AND skill_id = ?", repo.ID, deepDive.ID).Order("id").Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if len(scans) != 2 {
		t.Fatalf("deep-dive scans = %d, want 2", len(scans))
	}
	got := map[string]db.Scan{}
	for _, scan := range scans {
		area, err := repoconfig.DecodeFocusAreaJSON(scan.FocusArea)
		if err != nil {
			t.Fatalf("decode focus area: %v", err)
		}
		got[area.Name] = scan
		if scan.ScanGroup != parent.ScanGroup || scan.Effort != parent.Effort {
			t.Errorf("scan = %+v, want parent effort and group", scan)
		}
		if scan.Model != "test-max" {
			t.Errorf("scan.Model = %q, want deep-dive skill's max tier (test-max), not parent's %q", scan.Model, parent.Model)
		}
	}
	if got["XML parser"].FocusArea == "" || got["CLI parser"].FocusArea == "" {
		t.Errorf("focus areas = %+v, want both configured areas", got)
	}
}

func TestAutoEnqueueFocusAreaDeepDivesFallsBackToUnscoped(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/unscoped-focus", Name: "unscoped-focus"}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json", OutputKind: "findings", Active: true, Source: "ui"}
	if err := s.DB.Create(&deepDive).Error; err != nil {
		t.Fatal(err)
	}
	parent := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		ScanGroup:    "triage-1",
	}
	if err := s.DB.Create(&parent).Error; err != nil {
		t.Fatal(err)
	}

	s.autoEnqueueFocusAreaDeepDives(&parent)
	s.autoEnqueueFocusAreaDeepDives(&parent) // completion delivery is idempotent.

	var scans []db.Scan
	if err := s.DB.Where("repository_id = ? AND skill_id = ?", repo.ID, deepDive.ID).Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("deep-dive scans = %d, want 1", len(scans))
	}
	if scans[0].FocusArea != "" {
		t.Errorf("focus_area = %q, want empty unscoped fallback", scans[0].FocusArea)
	}
	if scans[0].ScanGroup != parent.ScanGroup {
		t.Errorf("scan_group = %q, want %q", scans[0].ScanGroup, parent.ScanGroup)
	}
}

func TestAutoEnqueueFocusAreaDeepDivesFallsBackAfterThreatModelFailure(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{
		URL: "https://example.com/failing-focus", Name: "failing-focus", ScanConfig: `focus_areas:
  - name: XML parser
    paths: [lib/xml*.c]
    surface: untrusted XML
`,
	}
	if err := s.DB.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json", OutputKind: "findings", Active: true, Source: "ui"}
	if err := s.DB.Create(&deepDive).Error; err != nil {
		t.Fatal(err)
	}
	parent := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanFailed,
		SkillName:    threatModelSkillName,
		ScanGroup:    "triage-1",
		SubPath:      "services/api",
		Ref:          "release/v1",
	}
	if err := s.DB.Create(&parent).Error; err != nil {
		t.Fatal(err)
	}

	s.autoEnqueueFocusAreaDeepDives(&parent)
	s.autoEnqueueFocusAreaDeepDives(&parent)

	var scans []db.Scan
	if err := s.DB.Where("repository_id = ? AND skill_id = ?", repo.ID, deepDive.ID).Find(&scans).Error; err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("deep-dive scans = %d, want 1", len(scans))
	}
	child := scans[0]
	if child.FocusArea != "" {
		t.Errorf("focus_area = %q, want unscoped fallback", child.FocusArea)
	}
	if child.SubPath != parent.SubPath || child.Ref != parent.Ref || child.ScanGroup != parent.ScanGroup {
		t.Errorf("child scope = (%q, %q, %q), want (%q, %q, %q)",
			child.SubPath, child.Ref, child.ScanGroup, parent.SubPath, parent.Ref, parent.ScanGroup)
	}
}

func TestAutoEnqueueFocusAreaDeepDivesSeedsThenFansOut(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{URL: "https://example.com/seed-focus", Name: "seed-focus"}
	s.DB.Create(&repo)
	s.DB.Create(&db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json", OutputKind: "findings", Active: true, Source: "ui"})
	parent := db.Scan{
		RepositoryID: repo.ID, Status: db.ScanDone, SkillName: threatModelSkillName,
		Report: `{"scan_config":{"focus_areas":[{"name":"parser","paths":["src/**"],"surface":"request bytes"}]}}`,
	}
	s.DB.Create(&parent)

	s.onScanFinalized(&parent)
	var deepDives []db.Scan
	s.DB.Where("repository_id = ? AND skill_name = ?", repo.ID, deepDiveSkillName).Find(&deepDives)
	if len(deepDives) != 1 || !strings.Contains(deepDives[0].FocusArea, `"name":"parser"`) {
		t.Fatalf("deep dives = %+v", deepDives)
	}
}

func TestAutoEnqueueFocusAreaDeepDivesPreservesScope(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
	repo := db.Repository{
		URL: "https://example.com/scoped-focus", Name: "scoped-focus", ScanConfig: `focus_areas:
  - name: API parser
    paths: [internal/api/**]
    surface: API requests
`,
	}
	s.DB.Create(&repo)
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json", OutputKind: "findings", Active: true, Source: "ui"}
	s.DB.Create(&deepDive)
	focusArea, err := repoconfig.EncodeFocusAreaJSON(repoconfig.FocusArea{
		Name: "API parser", Paths: []string{"internal/api/**"}, Surface: "API requests",
	})
	if err != nil {
		t.Fatal(err)
	}
	parent := db.Scan{
		RepositoryID: repo.ID,
		Status:       db.ScanDone,
		SkillName:    threatModelSkillName,
		ScanGroup:    "diff-1",
		SubPath:      "services/api",
		Ref:          "release/v1",
	}
	s.DB.Create(&parent)
	// A same-group scan for another ref/subpath must not suppress this fan-out.
	s.DB.Create(&db.Scan{
		RepositoryID: repo.ID, SkillID: &deepDive.ID, SkillName: deepDiveSkillName,
		Status: db.ScanDone, ScanGroup: parent.ScanGroup, SubPath: "services/other",
		Ref: "main", FocusArea: focusArea,
	})

	s.autoEnqueueFocusAreaDeepDives(&parent)

	var child db.Scan
	if err := s.DB.Where("repository_id = ? AND skill_id = ? AND sub_path = ? AND ref = ?", repo.ID, deepDive.ID, parent.SubPath, parent.Ref).First(&child).Error; err != nil {
		t.Fatal(err)
	}
	if child.SubPath != parent.SubPath || child.Ref != parent.Ref || child.ScanGroup != parent.ScanGroup {
		t.Errorf("child scope = (%q, %q, %q), want (%q, %q, %q)",
			child.SubPath, child.Ref, child.ScanGroup, parent.SubPath, parent.Ref, parent.ScanGroup)
	}
}
