package web

import "testing"

func TestLocationURL(t *testing.T) {
	cases := []struct {
		repoID      uint
		commit, loc string
		want        string
	}{
		{5, "abc123", "lib/x.rb:10", "/repositories/5/blob/abc123/lib/x.rb?line=10#L10"},
		{5, "abc123", "lib/x.rb:10-20", "/repositories/5/blob/abc123/lib/x.rb?line=10-20#L10"},
		{5, "abc123", "lib/x.rb", "/repositories/5/blob/abc123/lib/x.rb"},
		{5, "abc123", "./z.c:1", "/repositories/5/blob/abc123/z.c?line=1#L1"},
		{5, "abc123", "src/with space.go:3", "/repositories/5/blob/abc123/src/with%20space.go?line=3#L3"},
		{0, "abc", "x:1", ""},
		{5, "", "x:1", ""},
		{5, "abc", "", ""},
	}
	for _, c := range cases {
		if got := locationURL(c.repoID, c.commit, c.loc); got != c.want {
			t.Errorf("locationURL(%d,%q,%q) = %q, want %q", c.repoID, c.commit, c.loc, got, c.want)
		}
	}
}
