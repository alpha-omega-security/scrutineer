package web

import "testing"

func TestForgeBlobURL(t *testing.T) {
	cases := []struct {
		name               string
		htmlURL, commit, p string
		line               int
		want               string
	}{
		{"github no line", "https://github.com/owner/repo", "abc123", "lib/x.rb", 0,
			"https://github.com/owner/repo/blob/abc123/lib/x.rb"},
		{"github with line", "https://github.com/owner/repo", "abc123", "lib/x.rb", 42,
			"https://github.com/owner/repo/blob/abc123/lib/x.rb#L42"},
		{"github trailing slash", "https://github.com/owner/repo/", "abc123", "x.go", 0,
			"https://github.com/owner/repo/blob/abc123/x.go"},
		{"gitlab", "https://gitlab.com/g/p", "abc123", "src/a.rb", 7,
			"https://gitlab.com/g/p/-/blob/abc123/src/a.rb#L7"},
		{"gitlab self-hosted", "https://gitlab.example.com/g/p", "abc", "x", 0,
			"https://gitlab.example.com/g/p/-/blob/abc/x"},
		{"codeberg gitea-shape", "https://codeberg.org/owner/repo", "abc", "x.go", 3,
			"https://codeberg.org/owner/repo/src/commit/abc/x.go#L3"},
		{"bitbucket hashlines", "https://bitbucket.org/owner/repo", "abc", "x.go", 3,
			"https://bitbucket.org/owner/repo/src/abc/x.go#lines-3"},
		{"path escaped", "https://github.com/o/r", "abc", "a b/c.rb", 0,
			"https://github.com/o/r/blob/abc/a%20b/c.rb"},
		{"unknown host", "https://example.com/o/r", "abc", "x.go", 0, ""},
		{"empty htmlURL", "", "abc", "x.go", 0, ""},
		{"empty commit", "https://github.com/o/r", "", "x.go", 0, ""},
		{"empty path", "https://github.com/o/r", "abc", "", 0, ""},
		{"path traversal rejected", "https://github.com/o/r", "abc", "../etc/passwd", 0, ""},
		{"absolute path rejected", "https://github.com/o/r", "abc", "/etc/passwd", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := forgeBlobURL(c.htmlURL, c.commit, c.p, c.line)
			if got != c.want {
				t.Errorf("forgeBlobURL(%q,%q,%q,%d) = %q, want %q",
					c.htmlURL, c.commit, c.p, c.line, got, c.want)
			}
		})
	}
}

func TestForgeCommitURL(t *testing.T) {
	cases := []struct {
		name, htmlURL, commit, want string
	}{
		{"github", "https://github.com/o/r", "abc", "https://github.com/o/r/commit/abc"},
		{"gitlab", "https://gitlab.com/g/p", "abc", "https://gitlab.com/g/p/-/commit/abc"},
		{"gitlab self-hosted", "https://gitlab.foo.io/g/p", "abc", "https://gitlab.foo.io/g/p/-/commit/abc"},
		{"codeberg", "https://codeberg.org/o/r", "abc", "https://codeberg.org/o/r/commit/abc"},
		{"bitbucket plural", "https://bitbucket.org/o/r", "abc", "https://bitbucket.org/o/r/commits/abc"},
		{"unknown", "https://example.com/o/r", "abc", ""},
		{"empty htmlURL", "", "abc", ""},
		{"empty commit", "https://github.com/o/r", "", ""},
		{"trailing slash trimmed", "https://github.com/o/r/", "abc", "https://github.com/o/r/commit/abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := forgeCommitURL(c.htmlURL, c.commit)
			if got != c.want {
				t.Errorf("forgeCommitURL(%q,%q) = %q, want %q", c.htmlURL, c.commit, got, c.want)
			}
		})
	}
}
