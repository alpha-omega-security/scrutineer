package worker

import "testing"

func TestCleanSubPath(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "", false},
		{"   ", "", false},
		{"/", "", false},
		{"activesupport", "activesupport", false},
		{"/activesupport/", "activesupport", false},
		{"  packages/core  ", "packages/core", false},
		{"packages//core", "packages/core", false},
		{"packages/./core", "packages/core", false},
		{"a/../b", "", true},
		{"..", "", true},
		{"../etc/passwd", "", true},
		{"packages/../../etc", "", true},
	}
	for _, tc := range cases {
		got, err := CleanSubPath(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("CleanSubPath(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("CleanSubPath(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CleanSubPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
