package db

import "testing"

func TestNameFromURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/foo/bar":      "bar",
		"https://github.com/foo/bar.git":  "bar",
		"https://github.com/foo/bar/":     "bar",
		"git@github.com:foo/bar.git":      "bar",
		"ssh://git@host.xz/path/to/repo":  "repo",
		"https://gitlab.com/g/sub/proj":   "proj",
		"":                                "repo",
	}
	for in, want := range cases {
		if got := NameFromURL(in); got != want {
			t.Errorf("NameFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpenAndMigrate(t *testing.T) {
	gdb, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	r := Repository{URL: "https://example.com/x", Name: "x"}
	if err := gdb.Create(&r).Error; err != nil {
		t.Fatal(err)
	}
	s := Scan{RepositoryID: r.ID, Kind: "claude", Status: ScanQueued}
	if err := gdb.Create(&s).Error; err != nil {
		t.Fatal(err)
	}
	var got Scan
	if err := gdb.Preload("Repository").First(&got, s.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Repository.URL != r.URL {
		t.Errorf("preload failed: %+v", got.Repository)
	}
}
