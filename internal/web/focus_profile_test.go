package web

import (
	"testing"

	"scrutineer/internal/db"
)

func TestFocusAreaFanoutPreservesOnlyRequestedProfile(t *testing.T) {
	for _, tt := range []struct{ name, recipe, profile, want string }{
		{"automatic PHP parent", `{"skill":"threat-model"}`, "php", ""},
		{"explicit PHP", `{"profile":"php"}`, "php", "php"},
		{"explicit default", `{"profile":"default"}`, "default", "default"},
		{"legacy", "", "php", "php"},
		{"malformed legacy", "broken", "php", "php"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, done := newTestServer(t)
			defer done()
			repo := db.Repository{URL: "https://example.com/mixed", ScanConfig: "focus_areas:\n  - name: Redux actions\n    paths: [packages/utils-redux/src/**]\n    surface: actions\n"}
			if err := s.DB.Create(&repo).Error; err != nil {
				t.Fatal(err)
			}
			skill := db.Skill{Name: deepDiveSkillName, Body: "audit", OutputKind: "findings", Active: true, Source: "ui"}
			if err := s.DB.Create(&skill).Error; err != nil {
				t.Fatal(err)
			}
			parent := db.Scan{RepositoryID: repo.ID, SkillName: threatModelSkillName, Status: db.ScanDone, Profile: tt.profile, Recipe: tt.recipe}
			if err := s.DB.Create(&parent).Error; err != nil {
				t.Fatal(err)
			}
			s.autoEnqueueFocusAreaDeepDives(&parent)
			var child db.Scan
			if err := s.DB.Where("repository_id = ? AND skill_id = ? AND focus_area != ''", repo.ID, skill.ID).First(&child).Error; err != nil {
				t.Fatal(err)
			}
			if child.Profile != tt.want {
				t.Fatalf("persisted profile = %q, want %q", child.Profile, tt.want)
			}
			if child.FocusArea == "" {
				t.Fatal("missing focus area")
			}
		})
	}
}
