package db

import "testing"

func TestCVSSV4ScoreFromVector(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		ok     bool
	}{
		{"v4 critical", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", true},
		{"v4 medium", "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", true},
		{"empty", "", false},
		{"garbage", "not-a-vector", false},
		{"v3 rejected", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", false},
		{"truncated", "CVSS:4.0/AV:N/AC:L", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CVSSV4ScoreFromVector(tc.vector)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (score %v)", ok, tc.ok, got)
			}
			if ok && (got <= 0 || got > 10) {
				t.Errorf("score %v out of [0,10]", got)
			}
		})
	}
}

func TestCVSSV3ScoreFromVector(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
		ok     bool
	}{
		{"v3.1 critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, true},
		{"v3.1 medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3, true},
		{"v3.0 high", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5, true},
		{"empty", "", 0, false},
		{"garbage", "not-a-vector", 0, false},
		{"v3.1 truncated", "CVSS:3.1/AV:N/AC:L", 0, false},
		{"unsupported v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := CVSSV3ScoreFromVector(tc.vector)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("score = %v, want %v", got, tc.want)
			}
		})
	}
}
