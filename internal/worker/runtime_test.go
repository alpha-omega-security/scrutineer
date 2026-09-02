package worker

import (
	"runtime"
	"slices"
	"testing"
)

func TestRuntimeBin(t *testing.T) {
	tests := []struct {
		rt   ContainerRuntime
		want string
	}{
		{ContainerRuntime{}, "docker"},
		{ContainerRuntime{Bin: "docker"}, "docker"},
		{ContainerRuntime{Bin: "podman"}, "podman"},
		{ContainerRuntime{Bin: "podman", Rootless: true}, "podman"},
		{ContainerRuntime{Bin: "apple"}, "container"},
	}
	for _, tc := range tests {
		if got := runtimeBin(tc.rt); got != tc.want {
			t.Errorf("runtimeBin(%+v) = %q, want %q", tc.rt, got, tc.want)
		}
	}
}

func TestSidecarEgressNetwork(t *testing.T) {
	tests := []struct {
		rt   ContainerRuntime
		want string
	}{
		{ContainerRuntime{}, "bridge"},
		{ContainerRuntime{Bin: "docker", DockerDesktop: true}, "bridge"},
		{ContainerRuntime{Bin: "podman", Rootless: true}, "podman"},
	}
	for _, tc := range tests {
		if got := sidecarEgressNetwork(tc.rt); got != tc.want {
			t.Errorf("sidecarEgressNetwork(%+v) = %q, want %q", tc.rt, got, tc.want)
		}
	}
}

func TestHostGatewayProbeNetwork(t *testing.T) {
	tests := []struct {
		rt   ContainerRuntime
		want string
	}{
		{ContainerRuntime{Bin: "docker", Version: "24.0.7"}, "hardened"},
		{ContainerRuntime{Bin: "docker", DockerDesktop: true, Version: "24.0.7"}, ""},
		{ContainerRuntime{Bin: "podman", Rootless: true}, "hardened"},
		{ContainerRuntime{Bin: "apple"}, "hardened"},
	}
	for _, tc := range tests {
		if got := hostGatewayProbeNetwork(tc.rt, "hardened"); got != tc.want {
			t.Errorf("hostGatewayProbeNetwork(%+v) = %q, want %q", tc.rt, got, tc.want)
		}
	}
}

// TestContainerRuntimeEnginePredicates pins the keep-id, hardened-network and
// egress-sidecar matrix the scan argv branches on. The predicates live in the
// dependency now, and the last two are security boundaries, so a bump that
// widens or drops one has to fail here.
func TestContainerRuntimeEnginePredicates(t *testing.T) {
	wantUnknownDockerSidecar := runtime.GOOS != "linux"
	tests := []struct {
		name          string
		rt            ContainerRuntime
		wantKeepID    bool
		wantNetVerify bool
		wantSidecar   bool
	}{
		{"docker zero value", ContainerRuntime{}, false, wantUnknownDockerSidecar, wantUnknownDockerSidecar},
		{"docker engine", ContainerRuntime{Bin: "docker", Version: "24.0.7"}, false, false, false},
		{"docker desktop", ContainerRuntime{Bin: "docker", DockerDesktop: true, Version: "24.0.7"}, false, true, true},
		{"docker rootless flag ignored", ContainerRuntime{Bin: "docker", Rootless: true, Version: "24.0.7"}, false, false, false},
		{"rootful podman", ContainerRuntime{Bin: "podman"}, false, false, false},
		{"rootless podman", ContainerRuntime{Bin: "podman", Rootless: true}, true, true, true},
		// Apple has no podman subuid remap and keeps the in-process host
		// proxy, but its --internal network is still proven per scan.
		{"apple", ContainerRuntime{Bin: "apple"}, false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rt.NeedsKeepID(); got != tc.wantKeepID {
				t.Errorf("NeedsKeepID = %v, want %v", got, tc.wantKeepID)
			}
			if got := tc.rt.NeedsHardenedNetVerify(); got != tc.wantNetVerify {
				t.Errorf("NeedsHardenedNetVerify = %v, want %v", got, tc.wantNetVerify)
			}
			if got := tc.rt.NeedsEgressSidecar(); got != tc.wantSidecar {
				t.Errorf("NeedsEgressSidecar = %v, want %v", got, tc.wantSidecar)
			}
			// The sidecar argv stays gated on --hardened.
			if got := (ContainerRunner{Runtime: tc.rt}).usesEgressSidecar(); got {
				t.Errorf("usesEgressSidecar without --hardened = %v, want false", got)
			}
			if got := (ContainerRunner{Runtime: tc.rt, Hardened: true}).usesEgressSidecar(); got != tc.wantSidecar {
				t.Errorf("usesEgressSidecar with --hardened = %v, want %v", got, tc.wantSidecar)
			}
		})
	}
}

// TestContainerRuntimeCapabilityFlags is the run-flag parity matrix: for each
// runtime it pins exactly which Docker/Podman flags apply and how `run` starts.
// docker and podman are identical; apple diverges only where its CLI lacks the
// flag (--add-host, --pull never, --security-opt) and adds --progress none.
func TestContainerRuntimeCapabilityFlags(t *testing.T) {
	tests := []struct {
		name                string
		rt                  ContainerRuntime
		wantHostGatewayAdd  bool
		wantPullNever       bool
		wantNoNewPrivileges bool
		wantRunArgs         []string
	}{
		{"docker zero value", ContainerRuntime{}, true, true, true, []string{"run", "--rm"}},
		{"docker explicit", ContainerRuntime{Bin: "docker"}, true, true, true, []string{"run", "--rm"}},
		{"podman", ContainerRuntime{Bin: "podman"}, true, true, true, []string{"run", "--rm"}},
		{"apple", ContainerRuntime{Bin: "apple"}, false, false, false, []string{"run", "--progress", "none", "--rm"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := supportsHostGatewayAddHost(tc.rt); got != tc.wantHostGatewayAdd {
				t.Errorf("supportsHostGatewayAddHost = %v, want %v", got, tc.wantHostGatewayAdd)
			}
			if got := supportsPullNever(tc.rt); got != tc.wantPullNever {
				t.Errorf("supportsPullNever = %v, want %v", got, tc.wantPullNever)
			}
			if got := supportsNoNewPrivileges(tc.rt); got != tc.wantNoNewPrivileges {
				t.Errorf("supportsNoNewPrivileges = %v, want %v", got, tc.wantNoNewPrivileges)
			}
			if got := runtimeRunArgs(tc.rt, "--rm"); !slices.Equal(got, tc.wantRunArgs) {
				t.Errorf("runtimeRunArgs = %v, want %v", got, tc.wantRunArgs)
			}
		})
	}
}

// TestHardeningSupportError locks in the hardening parity: docker and podman
// accept both modes; apple accepts --hardened (its --internal host-only network
// is the enforcement, verified per scan) but refuses --hardened-runtime-only
// (the rootless-podman non-network half). This is the gate setupRunner applies
// at startup; testing it here keeps it covered even though setupRunner itself
// shells out to a live runtime.
func TestHardeningSupportError(t *testing.T) {
	tests := []struct {
		name                string
		rt                  ContainerRuntime
		hardenedRuntimeOnly bool
		wantErr             bool
	}{
		{"docker hardened-rootless", ContainerRuntime{Bin: "docker"}, true, false},
		{"podman rootless hardened-rootless", ContainerRuntime{Bin: "podman", Rootless: true}, true, false},
		{"apple plain (ordinary or --hardened)", ContainerRuntime{Bin: "apple"}, false, false},
		{"apple hardened-rootless refused", ContainerRuntime{Bin: "apple"}, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := HardeningSupportError(tc.rt, tc.hardenedRuntimeOnly)
			if (err != nil) != tc.wantErr {
				t.Errorf("HardeningSupportError(%v) err = %v, wantErr %v", tc.hardenedRuntimeOnly, err, tc.wantErr)
			}
		})
	}
}

func TestBindMount(t *testing.T) {
	cases := []struct {
		name     string
		src, dst string
		relabel  bool
		opts     []string
		want     string
	}{
		{"plain, no relabel", "/abs/work", "/work", false, nil, "/abs/work:/work"},
		{"plain, relabel", "/abs/work", "/work", true, nil, "/abs/work:/work:z"},
		{"ro, no relabel", "/abs/src", "/src", false, []string{"ro"}, "/abs/src:/src:ro"},
		{"ro, relabel appends to opts", "/abs/src", "/src", true, []string{"ro"}, "/abs/src:/src:ro,z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bindMount(c.src, c.dst, c.relabel, c.opts...); got != c.want {
				t.Errorf("bindMount(%q,%q,%v,%v) = %q, want %q", c.src, c.dst, c.relabel, c.opts, got, c.want)
			}
		})
	}
}
