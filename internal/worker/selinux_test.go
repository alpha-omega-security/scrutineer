package worker

import (
	"context"
	"testing"
)

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

func TestResolveSELinuxRelabel(t *testing.T) {
	if !ResolveSELinuxRelabel(SELinuxOn) {
		t.Errorf("%q must force relabeling on", SELinuxOn)
	}
	if ResolveSELinuxRelabel(SELinuxOff) {
		t.Errorf("%q must force relabeling off", SELinuxOff)
	}
	// "auto" and the empty default must track host detection exactly, so the fix
	// turns on only where it's needed and stays invisible elsewhere.
	want := HostSELinuxEnabled()
	if got := ResolveSELinuxRelabel(SELinuxAuto); got != want {
		t.Errorf("%q = %v, want HostSELinuxEnabled() = %v", SELinuxAuto, got, want)
	}
	if got := ResolveSELinuxRelabel(""); got != want {
		t.Errorf("\"\" = %v, want HostSELinuxEnabled() = %v", got, want)
	}
}

func TestHostSELinuxState(t *testing.T) {
	switch s := HostSELinuxState(); s {
	case SELinuxStateEnforcing, SELinuxStatePermissive, SELinuxStateDisabled:
		// ok
	default:
		t.Errorf("HostSELinuxState() = %q, want enforcing/permissive/disabled", s)
	}
	// State and HostSELinuxEnabled must agree: "disabled" iff not enabled.
	if (HostSELinuxState() == SELinuxStateDisabled) == HostSELinuxEnabled() {
		t.Errorf("HostSELinuxState()=%q disagrees with HostSELinuxEnabled()=%v",
			HostSELinuxState(), HostSELinuxEnabled())
	}
}

func TestVerifySELinuxMount_NoopCases(t *testing.T) {
	// relabel=false is the operator opting out: the check must never launch a
	// container or error, even with no runtime present.
	if err := VerifySELinuxMount(context.Background(), ContainerRuntime{}, "img:latest", false); err != nil {
		t.Errorf("VerifySELinuxMount(relabel=false) = %v, want nil (no-op)", err)
	}
	// relabel=true but an empty image short-circuits before any exec, so it stays
	// a no-op regardless of host runtime availability.
	if err := VerifySELinuxMount(context.Background(), ContainerRuntime{}, "", true); err != nil {
		t.Errorf("VerifySELinuxMount(empty image) = %v, want nil (no-op)", err)
	}
}
