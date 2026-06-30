package web

import "testing"

func TestRunnerImageRef(t *testing.T) {
	tests := []struct {
		name  string
		image string
		rev   string
		want  string
	}{
		{
			// 22-char revision; want pins the first 12 chars so the test fails
			// loudly if shortSHALen changes rather than silently tracking it.
			name:  "strips :latest and truncates revision",
			image: "ghcr.io/alpha-omega-security/scrutineer-runner:latest",
			rev:   "abcdef0123456789abcdef",
			want:  "ghcr.io/alpha-omega-security/scrutineer-runner @ abcdef012345",
		},
		{
			name:  "short revision kept whole",
			image: "ghcr.io/x/runner:latest",
			rev:   "abc123",
			want:  "ghcr.io/x/runner @ abc123",
		},
		{
			name:  "empty revision falls back to bare image",
			image: "ghcr.io/x/runner:latest",
			rev:   "",
			want:  "ghcr.io/x/runner:latest",
		},
		{
			name:  "non-latest tag is preserved",
			image: "ghcr.io/x/runner:v1.2.3",
			rev:   "deadbeefcafef00d",
			want:  "ghcr.io/x/runner:v1.2.3 @ deadbeefcafe",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := toolMetadata{RunnerImage: tc.image, Revision: tc.rev}
			if got := m.RunnerImageRef(); got != tc.want {
				t.Errorf("RunnerImageRef() = %q, want %q", got, tc.want)
			}
		})
	}
}
