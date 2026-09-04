package worker

import (
	"io"
	"log/slog"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
)

func TestReconcileSubprojectLinks(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://github.com/rails/rails", Name: "rails"}
	gdb.Create(&repo)
	as := db.Subproject{RepositoryID: repo.ID, Path: "activesupport", Name: "activesupport"}
	ap := db.Subproject{RepositoryID: repo.ID, Path: "actionpack", Name: "actionpack"}
	gdb.Create(&as)
	gdb.Create(&ap)
	gdb.Create(&db.Package{RepositoryID: repo.ID, Name: "activesupport", Ecosystem: "rubygems"})
	gdb.Create(&db.Package{RepositoryID: repo.ID, Name: "actionpack", Ecosystem: "rubygems"})
	gdb.Create(&db.Package{RepositoryID: repo.ID, Name: "railties", Ecosystem: "rubygems"}) // matches no subproject
	gdb.Create(&db.Advisory{RepositoryID: repo.ID, UUID: "u1", Packages: "actionpack,actionview"})
	gdb.Create(&db.Advisory{RepositoryID: repo.ID, UUID: "u2", Packages: "nokogiri"}) // unmatched

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MonorepoAttribution: true}
	if err := w.reconcileSubprojectLinks(repo.ID); err != nil {
		t.Fatal(err)
	}

	linked := func(name string) *uint {
		var p db.Package
		gdb.Where("repository_id = ? AND name = ?", repo.ID, name).First(&p)
		return p.SubprojectID
	}
	if got := linked("activesupport"); got == nil || *got != as.ID {
		t.Errorf("activesupport package link = %v, want subproject %d", got, as.ID)
	}
	if got := linked("actionpack"); got == nil || *got != ap.ID {
		t.Errorf("actionpack package link = %v, want subproject %d", got, ap.ID)
	}
	if got := linked("railties"); got != nil {
		t.Errorf("railties package should be repo-level (nil), got %d", *got)
	}

	advLink := func(uuid string) *uint {
		var a db.Advisory
		gdb.Where("uuid = ?", uuid).First(&a)
		return a.SubprojectID
	}
	if got := advLink("u1"); got == nil || *got != ap.ID {
		t.Errorf("advisory u1 link = %v, want actionpack subproject %d", got, ap.ID)
	}
	if got := advLink("u2"); got != nil {
		t.Errorf("advisory u2 should be repo-level, got %d", *got)
	}

	// Self-heal: remove the actionpack subproject and re-run — its package and
	// advisory must revert to repo-level rather than dangle on a deleted id.
	gdb.Delete(&ap)
	if err := w.reconcileSubprojectLinks(repo.ID); err != nil {
		t.Fatal(err)
	}
	if got := linked("actionpack"); got != nil {
		t.Errorf("actionpack package should revert to repo-level after subproject removed, got %d", *got)
	}
	if got := advLink("u1"); got != nil {
		t.Errorf("advisory u1 should revert to repo-level after subproject removed, got %d", *got)
	}
}

// A directory basename matches when the manifest name is absent, but an
// explicit manifest name always wins.
func TestReconcileSubprojectLinks_directoryFallback(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/mono", Name: "mono"}
	gdb.Create(&repo)
	// No Name set: only the directory basename is available to match.
	sub := db.Subproject{RepositoryID: repo.ID, Path: "libs/widget"}
	gdb.Create(&sub)
	gdb.Create(&db.Package{RepositoryID: repo.ID, Name: "widget", Ecosystem: "npm"})

	w := &Worker{DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MonorepoAttribution: true}
	if err := w.reconcileSubprojectLinks(repo.ID); err != nil {
		t.Fatal(err)
	}
	var p db.Package
	gdb.Where("repository_id = ? AND name = ?", repo.ID, "widget").First(&p)
	if p.SubprojectID == nil || *p.SubprojectID != sub.ID {
		t.Errorf("widget package should match by directory basename, got %v", p.SubprojectID)
	}
}
