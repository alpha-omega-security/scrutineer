package db

import (
	"path/filepath"
	"testing"
)

func TestEffectiveDisclosureChannel(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://github.com/rails/rails", Name: "rails", DisclosureChannel: "repo@example.org"}
	gdb.Create(&repo)
	gdb.Create(&Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport", DisclosureChannel: "as@example.org"})
	gdb.Create(&Subproject{RepositoryID: repo.ID, Path: "actionpack", Name: "actionpack"}) // no channel of its own

	cases := []struct {
		subPath string
		want    string
	}{
		{"activesupport", "as@example.org"}, // sub-package with its own channel
		{"actionpack", "repo@example.org"},  // sub-package without one -> repo fallback
		{"", "repo@example.org"},            // repo-root finding -> repo channel
		{"unknownpath", "repo@example.org"}, // sub-path with no subproject row -> repo fallback
	}
	for _, tc := range cases {
		if got := EffectiveDisclosureChannel(gdb, repo.ID, tc.subPath); got != tc.want {
			t.Errorf("EffectiveDisclosureChannel(%q) = %q, want %q", tc.subPath, got, tc.want)
		}
	}
}

func TestEnsureSubproject(t *testing.T) {
	gdb, err := Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)

	if err := EnsureSubproject(gdb, repo.ID, "packages/core"); err != nil {
		t.Fatal(err)
	}
	var sub Subproject
	gdb.Where("repository_id = ? AND path = ?", repo.ID, "packages/core").First(&sub)
	if sub.Name != "core" {
		t.Errorf("name = %q, want core (last path segment)", sub.Name)
	}
	firstID := sub.ID

	// Idempotent: a second call adopts the existing row, keeps its id, and does
	// not clobber a name the subprojects skill later enriched.
	gdb.Model(&sub).Update("name", "core-enriched")
	if err := EnsureSubproject(gdb, repo.ID, "packages/core"); err != nil {
		t.Fatal(err)
	}
	var sub2 Subproject
	gdb.Where("repository_id = ? AND path = ?", repo.ID, "packages/core").First(&sub2)
	if sub2.ID != firstID {
		t.Errorf("id churned: was %d now %d", firstID, sub2.ID)
	}
	if sub2.Name != "core-enriched" {
		t.Errorf("EnsureSubproject clobbered enriched name: %q", sub2.Name)
	}

	// Empty path is a no-op.
	if err := EnsureSubproject(gdb, repo.ID, "  "); err != nil {
		t.Fatal(err)
	}
	var n int64
	gdb.Model(&Subproject{}).Where("repository_id = ?", repo.ID).Count(&n)
	if n != 1 {
		t.Errorf("subproject count = %d, want 1 (empty path is a no-op)", n)
	}
}
