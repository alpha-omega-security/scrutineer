package worker

import (
	"errors"
	"strings"
	"testing"
)

func TestContainerRuntimeBin(t *testing.T) {
	tests := []struct {
		rt   ContainerRuntime
		want string
	}{
		{ContainerRuntime{}, "docker"},
		{ContainerRuntime{Bin: "docker"}, "docker"},
		{ContainerRuntime{Bin: "podman"}, "podman"},
		{ContainerRuntime{Bin: "podman", Rootless: true}, "podman"},
	}
	for _, tc := range tests {
		if got := tc.rt.bin(); got != tc.want {
			t.Errorf("%+v.bin() = %q, want %q", tc.rt, got, tc.want)
		}
	}
}

func TestContainerRuntimeNeedsKeepID(t *testing.T) {
	// keep-id is the bind-mount ownership fix and must fire for rootless
	// podman ONLY: docker and rootful podman already run as the host uid, so
	// remapping there would break mounts.
	tests := []struct {
		rt   ContainerRuntime
		want bool
	}{
		{ContainerRuntime{}, false},                              // docker (zero value)
		{ContainerRuntime{Bin: "docker"}, false},                 // docker explicit
		{ContainerRuntime{Bin: "podman"}, false},                 // rootful podman
		{ContainerRuntime{Bin: "podman", Rootless: true}, true},  // rootless podman
		{ContainerRuntime{Bin: "docker", Rootless: true}, false}, // rootless flag ignored for docker
	}
	for _, tc := range tests {
		if got := tc.rt.needsKeepID(); got != tc.want {
			t.Errorf("%+v.needsKeepID() = %v, want %v", tc.rt, got, tc.want)
		}
	}
}

func TestContainerRuntimeNeedsHardenedNetVerify(t *testing.T) {
	// Per-scan --internal verification must fire for rootless podman ONLY:
	// docker and rootful podman use a trusted host-netns bridge (docker's model),
	// so they keep the trusted path and skip the probe cost.
	tests := []struct {
		rt   ContainerRuntime
		want bool
	}{
		{ContainerRuntime{}, false},                             // docker (zero value)
		{ContainerRuntime{Bin: "docker"}, false},                // docker explicit
		{ContainerRuntime{Bin: "podman"}, false},                // rootful podman -> trusted like docker
		{ContainerRuntime{Bin: "podman", Rootless: true}, true}, // rootless podman -> verified
	}
	for _, tc := range tests {
		if got := tc.rt.needsHardenedNetVerify(); got != tc.want {
			t.Errorf("%+v.needsHardenedNetVerify() = %v, want %v", tc.rt, got, tc.want)
		}
	}
}

func TestDetectRuntime(t *testing.T) {
	probeErr := errors.New("not installed")
	type call struct {
		name string
		args []string
	}
	tests := []struct {
		name     string
		prefer   string
		probeOut []byte
		probeErr error
		want     ContainerRuntime
		wantOK   bool
	}{
		{"docker ok", "docker", []byte("24.0.7\n"), nil, ContainerRuntime{Bin: "docker", Version: "24.0.7"}, true},
		{"empty defaults to docker", "", []byte("24.0.7\n"), nil, ContainerRuntime{Bin: "docker", Version: "24.0.7"}, true},
		{"podman rootless", "podman", []byte("4.9.4|true\n"), nil, ContainerRuntime{Bin: "podman", Rootless: true, Version: "4.9.4"}, true},
		{"podman rootful", "podman", []byte("4.9.4|false\n"), nil, ContainerRuntime{Bin: "podman", Rootless: false, Version: "4.9.4"}, true},
		// No fallback: a podman probe failure stays unavailable; the docker
		// default on a podman-only host likewise fails (explicit opt-in).
		{"podman unreachable", "podman", nil, probeErr, ContainerRuntime{}, false},
		{"docker unreachable", "docker", nil, probeErr, ContainerRuntime{}, false},
		{"podman malformed", "podman", []byte("nopipe\n"), nil, ContainerRuntime{}, false},
		{"docker empty output", "docker", []byte("  \n"), nil, ContainerRuntime{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []call
			probe := func(name string, args ...string) ([]byte, error) {
				calls = append(calls, call{name, append([]string(nil), args...)})
				return tc.probeOut, tc.probeErr
			}
			got, ok := detectRuntime(tc.prefer, probe)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("detectRuntime(%q) = %+v,%v; want %+v,%v", tc.prefer, got, ok, tc.want, tc.wantOK)
			}
			// docker's {{.ServerVersion}} errors against podman's schema and
			// podman's fields error against docker's; assert each engine only
			// ever sees its own template (guards the availability-flip risk).
			for _, c := range calls {
				joined := strings.Join(c.args, " ")
				if c.name == "podman" && strings.Contains(joined, "ServerVersion") {
					t.Errorf("podman probed with docker template: %v", c.args)
				}
				if c.name == "docker" && strings.Contains(joined, "Host.Security.Rootless") {
					t.Errorf("docker probed with podman template: %v", c.args)
				}
			}
		})
	}

	t.Run("bogus prefer never probes", func(t *testing.T) {
		called := false
		probe := func(string, ...string) ([]byte, error) { called = true; return nil, nil }
		if got, ok := detectRuntime("containerd", probe); ok || got != (ContainerRuntime{}) {
			t.Errorf("detectRuntime(bogus) = %+v,%v; want zero,false", got, ok)
		}
		if called {
			t.Error("bogus runtime should not shell out")
		}
	})
}

func TestParsePodmanInfo(t *testing.T) {
	tests := []struct {
		in       string
		wantVer  string
		wantRoot bool
		wantOK   bool
	}{
		{"4.9.4|true\n", "4.9.4", true, true},
		{"4.9.4|false", "4.9.4", false, true},
		{" 5.0.1 | true ", "5.0.1", true, true},
		{"nopipe", "", false, false},
		{"4.9.4|maybe", "", false, false},
		{"", "", false, false},
	}
	for _, tc := range tests {
		ver, root, ok := parsePodmanInfo([]byte(tc.in))
		if ver != tc.wantVer || root != tc.wantRoot || ok != tc.wantOK {
			t.Errorf("parsePodmanInfo(%q) = %q,%v,%v; want %q,%v,%v", tc.in, ver, root, ok, tc.wantVer, tc.wantRoot, tc.wantOK)
		}
	}
}

func TestPodmanHostGatewaySupported(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"4.7.0", true},
		{"4.7", true},
		{"4.9.4", true},
		{"5.0.1", true},
		{"4.6.9", false},
		{"3.4.0", false},
		{"", true},        // unparseable: don't warn
		{"garbage", true}, // unparseable: don't warn
		{"4", true},       // no minor: don't warn
	}
	for _, tc := range tests {
		if got := podmanHostGatewaySupported(tc.version); got != tc.want {
			t.Errorf("podmanHostGatewaySupported(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}
