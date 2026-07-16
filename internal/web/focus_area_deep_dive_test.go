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
