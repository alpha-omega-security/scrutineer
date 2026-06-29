package worker

import (
	"testing"
	"time"
)

func TestParseImageInspect(t *testing.T) {
	const digest = "sha256:abc123"
	created := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		out         string
		wantDigest  string
		wantCreated time.Time
	}{
		{
			name:        "digest and created",
			out:         "ghcr.io/a/b@" + digest + "\n2026-06-01T12:00:00Z\n",
			wantDigest:  digest,
			wantCreated: created,
		},
		{
			name:       "missing created label leaves zero time",
			out:        "ghcr.io/a/b@" + digest + "\n<no value>\n",
			wantDigest: digest,
		},
		{
			// A locally-built image has no RepoDigests, so the first line is
			// empty; the empty line must not be mistaken for a digest.
			name:        "no repo digest",
			out:         "\n2026-06-01T12:00:00Z\n",
			wantCreated: created,
		},
		{
			name: "empty output",
			out:  "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotDigest, gotCreated := parseImageInspect(tc.out)
			if gotDigest != tc.wantDigest {
				t.Errorf("digest = %q, want %q", gotDigest, tc.wantDigest)
			}
			if !gotCreated.Equal(tc.wantCreated) {
				t.Errorf("created = %v, want %v", gotCreated, tc.wantCreated)
			}
		})
	}
}

func TestEvalRunnerStaleness(t *testing.T) {
	now := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	const img = "ghcr.io/alpha-omega-security/scrutineer-runner:latest"
	tests := []struct {
		name         string
		localDigest  string
		remoteDigest string
		created      time.Time
		wantStale    bool
		wantAgeDays  int
	}{
		{
			name:         "up to date, same digest",
			localDigest:  "sha256:same",
			remoteDigest: "sha256:same",
			created:      now.AddDate(0, 0, -30), // old but current digest
			wantStale:    false,
			wantAgeDays:  30,
		},
		{
			name:         "behind and old enough to nag",
			localDigest:  "sha256:old",
			remoteDigest: "sha256:new",
			created:      now.AddDate(0, 0, -8),
			wantStale:    true,
			wantAgeDays:  8,
		},
		{
			name:         "behind but under the age threshold",
			localDigest:  "sha256:old",
			remoteDigest: "sha256:new",
			created:      now.AddDate(0, 0, -3),
			wantStale:    false,
			wantAgeDays:  3,
		},
		{
			// Exactly the threshold counts: ">= 7 days" per the agreed plan.
			name:         "behind, exactly at threshold",
			localDigest:  "sha256:old",
			remoteDigest: "sha256:new",
			created:      now.AddDate(0, 0, -RunnerStaleThresholdDays),
			wantStale:    true,
			wantAgeDays:  RunnerStaleThresholdDays,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evalRunnerStaleness(img, tc.localDigest, tc.remoteDigest, tc.created, now, "docker")
			if got.Stale != tc.wantStale {
				t.Errorf("Stale = %v, want %v", got.Stale, tc.wantStale)
			}
			if got.AgeDays != tc.wantAgeDays {
				t.Errorf("AgeDays = %d, want %d", got.AgeDays, tc.wantAgeDays)
			}
			if want := "docker pull " + img; got.PullCommand != want {
				t.Errorf("PullCommand = %q, want %q", got.PullCommand, want)
			}
		})
	}
}

func TestRunnerImageStalenessEmptyImage(t *testing.T) {
	// No container runtime in use (--no-container) yields an empty image name;
	// the check must short-circuit to "can't tell" without shelling out.
	if _, ok := RunnerImageStaleness(t.Context(), ContainerRuntime{}, ""); ok {
		t.Error("expected ok=false for empty image")
	}
}
