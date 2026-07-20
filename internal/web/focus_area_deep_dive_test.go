package web

import (
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

func TestAutoEnqueueFocusAreaDeepDives(t *testing.T) {
	s, done := newTestServer(t)
	defer done()
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
	deepDive := db.Skill{Name: deepDiveSkillName, Body: "b", OutputFile: "r.json", OutputKind: "findings", Active: true, Source: "ui"}
	s.DB.Create(&deepDive)
	parent := db.Scan{RepositoryID: repo.ID, Status: db.ScanDone, SkillName: threatModelSkillName, ScanGroup: "triage-1", Effort: "high"}
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
