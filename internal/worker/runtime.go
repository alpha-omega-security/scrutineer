package worker

// Engine traits and the bind-mount spec, restating what harness/container keeps
// unexported. container.go still builds the `run` argv itself, so it needs the
// same answers. Nothing ties these copies to the originals, so a divergence
// shows up only at runtime.

import (
	"fmt"
	"strings"

	"github.com/alpha-omega-security/harness/container"
)

// ContainerRuntime is harness/container's engine selection, aliased so callers
// here and in cmd stay on the type container.DetectRuntime returns.
type ContainerRuntime = container.Runtime

// runtimeApple is the ContainerRuntime.Bin value for Apple's container runtime.
// Hoisted to a constant because the identifier is checked throughout the package.
const runtimeApple = "apple"

// runtimePodman is the ContainerRuntime.Bin value for podman (rootful or
// rootless). Hoisted to a constant for the same reason as runtimeApple.
const runtimePodman = "podman"

// runtimeBin returns the executable name, defaulting to docker so the zero
// value stays valid. Mirrors ContainerRunner.image()'s empty-default pattern.
func runtimeBin(rt ContainerRuntime) string {
	switch rt.Bin {
	case "":
		return "docker"
	case runtimeApple:
		return "container"
	default:
		return rt.Bin
	}
}

// runtimeRunArgs starts a runtime `run` command, adding runtime-specific flags
// that must precede the common options. Apple's container CLI writes lifecycle
// progress to stdout by default; suppress it so probe parsers and Claude's
// stream-json reader only see the container payload.
func runtimeRunArgs(rt ContainerRuntime, args ...string) []string {
	out := []string{"run"}
	if rt.Bin == runtimeApple {
		out = append(out, "--progress", "none")
	}
	return append(out, args...)
}

// supportsHostGatewayAddHost reports whether the runtime accepts Docker's
// `--add-host name:host-gateway` marker. Apple's container CLI does not expose
// that flag; it reaches host services through the default gateway address
// instead.
func supportsHostGatewayAddHost(rt ContainerRuntime) bool { return rt.Bin != runtimeApple }

// supportsPullNever reports whether `run --pull never` is supported. Apple's
// container CLI does not expose a pull policy flag, so callers that need a
// no-pull probe must check the local image cache before running.
func supportsPullNever(rt ContainerRuntime) bool { return rt.Bin != runtimeApple }

// supportsNoNewPrivileges reports whether the runtime accepts Docker/Podman's
// `--security-opt no-new-privileges` hardening flag.
func supportsNoNewPrivileges(rt ContainerRuntime) bool { return rt.Bin != runtimeApple }

// sidecarEgressNetwork returns the runtime's named default bridge.
func sidecarEgressNetwork(rt ContainerRuntime) string {
	if rt.Bin == runtimePodman {
		return "podman"
	}
	return "bridge"
}

// hostGatewayProbeNetwork returns the network used to resolve host-gateway.
// Docker Desktop's sidecar reaches the host through its default bridge leg.
func hostGatewayProbeNetwork(rt ContainerRuntime, network string) string {
	if rt.NeedsEgressSidecar() && runtimeBin(rt) == "docker" {
		return ""
	}
	return network
}

// bindMount builds a `-v` value "src:dst[:opts]" for a runner bind mount,
// appending the SELinux relabel option "z" when relabel is true. opts carries
// any non-SELinux options (e.g. "ro"); "z" joins that comma-separated group, so
// an SELinux host gets "src:dst:ro,z" while every other host gets the spec
// unchanged.
//
// Why ":z" (shared) and not ":Z" (private):
//
//   - Host read-back. After a scan the scrutineer host process reads the output
//     report back out of /work (readCappedReport). ":z" relabels to the shared
//     type container_file_t with no MCS category, so the host can still read it;
//     ":Z" stamps a private per-container category that a host process in a
//     confined SELinux domain could be denied -- locking scrutineer out of the
//     very report it asked for.
//   - Overlapping mounts. /work and /src point at the same clone tree; one
//     shared label keeps the two relabels consistent instead of churning a
//     private category between them.
//   - Isolation model. scrutineer separates scans with per-scan work roots and,
//     under --hardened, per-scan --internal networks -- not SELinux MCS. ":Z"'s
//     extra container-to-container separation is not load-bearing here. The cost
//     ":z" accepts is that any container_t on the host could read a scan's
//     ephemeral workspace; that is outside the threat model (the concern is a
//     hostile repo escaping the sandbox, not a sibling local container reading a
//     throwaway clone).
//
// Operators who want the stricter per-scan MCS isolation can pre-label their data
// dir and run with --selinux=off; ":Z" is intentionally not exposed as a switch
// so the host read-back guarantee stays simple.
func bindMount(src, dst string, relabel bool, opts ...string) string {
	if relabel {
		opts = append(opts, "z")
	}
	spec := src + ":" + dst
	if len(opts) > 0 {
		spec += ":" + strings.Join(opts, ",")
	}
	return spec
}

// HardeningSupportError reports why the runtime cannot honour the requested
// hardening mode, or nil when it can. Apple's container runtime supports
// --hardened: its `container network create --internal` is a vmnet
// host-only network (external egress blocked, host gateway still reachable --
// the per-scan network enforcement --hardened needs), and the runner verifies
// that fail-closed per scan (see Runtime.NeedsHardenedNetVerify). The one flag
// Apple's CLI does not expose is --security-opt no-new-privileges, but on a
// VM-per-container runtime the VM boundary is the isolation, not in-guest
// privilege hardening: an escalated process is still trapped in a disposable VM
// with no host filesystem or credentials. Apple's own untrusted-code sandbox
// (containerization's examples/sandboxy) hardens exactly this way -- VM +
// read-only mounts + host-only network + allowlisting proxy, no
// no-new-privileges. So --hardened is accepted; only --hardened-runtime-only
// (the rootless-podman non-network half) is refused, since Apple's network half
// works. See docs/apple.md.
func HardeningSupportError(rt ContainerRuntime, hardenedRuntimeOnly bool) error {
	if rt.Bin == runtimeApple && hardenedRuntimeOnly {
		return fmt.Errorf("--runtime apple does not support --hardened-runtime-only " +
			"(that is the rootless-podman non-network half); use --hardened, whose " +
			"--internal host-only network Apple's container runtime supports")
	}
	return nil
}
