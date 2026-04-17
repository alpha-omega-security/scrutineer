package web

import (
	"testing"

	"scrutineer/internal/db"
)

func TestKnownPURLsMatchWithAndWithoutQualifiers(t *testing.T) {
	gdb, err := db.Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	defer func() { _ = sqldb.Close() }()
	repo1 := db.Repository{URL: "https://github.com/splitrb/split", Name: "split"}
	repo2 := db.Repository{URL: "https://github.com/ruby/bigdecimal", Name: "bigdecimal"}
	gdb.Create(&repo1)
	gdb.Create(&repo2)

	// Package with qualifier (from gem.coop registry)
	gdb.Create(&db.Package{
		RepositoryID: repo2.ID,
		Name:         "bigdecimal",
		Ecosystem:    "gem",
		PURL:         "pkg:gem/bigdecimal?repository_url=https://gem.coop",
	})
	// Package without qualifier (from rubygems.org)
	gdb.Create(&db.Package{
		RepositoryID: repo2.ID,
		Name:         "bigdecimal",
		Ecosystem:    "gem",
		PURL:         "pkg:gem/bigdecimal",
	})

	// Dependency row from git-pkgs (always bare PURL)
	gdb.Create(&db.Dependency{
		RepositoryID: repo1.ID,
		Name:         "bigdecimal",
		Ecosystem:    "gem",
		PURL:         "pkg:gem/bigdecimal",
	})

	// Simulate what repoShow does to build KnownPURLs
	knownPURLs := buildKnownPURLs(gdb)

	// bare PURL should resolve to repo2
	if rid := knownPURLs["pkg:gem/bigdecimal"]; rid != repo2.ID {
		t.Errorf("bare PURL: got repo %d, want %d", rid, repo2.ID)
	}
	// qualified PURL should also resolve
	if rid := knownPURLs["pkg:gem/bigdecimal?repository_url=https://gem.coop"]; rid != repo2.ID {
		t.Errorf("qualified PURL: got repo %d, want %d", rid, repo2.ID)
	}
	// unknown PURL should be 0
	if rid := knownPURLs["pkg:gem/nonexistent"]; rid != 0 {
		t.Errorf("unknown PURL: got repo %d, want 0", rid)
	}
}

func TestKnownURLsMatchDependents(t *testing.T) {
	gdb, err := db.Open("file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	defer func() { _ = sqldb.Close() }()

	repo := db.Repository{URL: "https://github.com/ruby/bigdecimal", Name: "bigdecimal"}
	gdb.Create(&repo)

	knownURLs := buildKnownURLs(gdb)
	if rid := knownURLs["https://github.com/ruby/bigdecimal"]; rid != repo.ID {
		t.Errorf("got repo %d, want %d", rid, repo.ID)
	}
	if rid := knownURLs["https://github.com/foo/bar"]; rid != 0 {
		t.Errorf("unknown URL: got repo %d, want 0", rid)
	}
}
