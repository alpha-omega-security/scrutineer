package worker

// Container runtime selection. scrutineer shells out to an OCI engine (docker,
// podman, or Apple's container) to run each scan in an ephemeral container.
// This file owns the engine choice and the small set of traits that changes the
// generated `run` flags so the rest of the package stays runtime-neutral.

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// runtimeApple is the ContainerRuntime.Bin value for Apple's container runtime.
// Hoisted to a constant because the identifier is checked throughout the package.
const runtimeApple = "apple"

// ContainerRuntime identifies the OCI engine scrutineer shells out to and the
// main trait that changes the generated `run` flags: rootless podman maps
// --user uid:gid through /etc/subuid, so files written to bind mounts land as
// the wrong host uid unless --userns=keep-id is set. docker and rootful podman
// both run the container process as the host uid directly, and Apple's
// per-container VMs do not use podman's subuid remap, so they need no remap.
// The zero value is the docker runtime, so a bare ContainerRunner{} (tests,
// RunnerImageName) keeps shelling out to "docker".
type ContainerRuntime struct {
	Bin      string // "docker", "podman", or "apple"; "" means docker
	Rootless bool   // true only for rootless podman
	// Version is the engine version captured at detection (e.g. "4.9.4").
	// Best-effort and only used for the startup host-gateway check; "" when
	// unknown. The settings page re-probes for a fresh value rather than
	// reusing this, so a daemon restart is reflected without a scrutineer
	// restart.
	Version string
}

// bin returns the executable name, defaulting to docker so the zero value
// stays valid. Mirrors ContainerRunner.image()'s empty-default pattern.
func (rt ContainerRuntime) bin() string {
	switch rt.Bin {
	case "":
		return "docker"
	case runtimeApple:
		return "container"
	default:
		return rt.Bin
	}
}

// needsKeepID reports whether `run` invocations must add --userns=keep-id to
// keep bind-mount writes owned by the invoking host user. True only for
// rootless podman: docker and rootful podman already run the container process
// as the host uid, so remapping there would be wrong.
func (rt ContainerRuntime) needsKeepID() bool {
	return rt.Bin == "podman" && rt.Rootless
}

// NeedsKeepID is the exported form of needsKeepID for callers outside the
// package. The startup path uses it to log a "warming" notice before the
// keep-id smoke test, since the first such run remaps the whole runner image
// into the subuid range and can take ~a minute.
func (rt ContainerRuntime) NeedsKeepID() bool {
	return rt.needsKeepID()
}

// needsHardenedNetVerify reports whether a hardened scan must prove its per-scan
// --internal network fail-closed before running. True for rootless podman and
// for Apple's container runtime. Rootless podman's pasta/slirp4netns host path
// is what varies across backends and what --internal can sever. Apple's vmnet
// host-only network has the right semantics (egress blocked, host reachable) but
// the implementation has known rough edges (DNS quirks, the host-access caveat
// in apple/container#1320, nftables filtering still pending), and this is a
// security boundary, so it is proven per scan rather than assumed. docker and
// rootful podman both run a bridge in the host netns (gateway on the host), so
// they keep the trusted path and pay no probe cost.
func (rt ContainerRuntime) needsHardenedNetVerify() bool {
	return rt.Bin == runtimeApple || (rt.Bin == "podman" && rt.Rootless)
}

// supportsHostGatewayAddHost reports whether the runtime accepts Docker's
// `--add-host name:host-gateway` marker. Apple's container CLI does not expose
// that flag; it reaches host services through the default gateway address
// instead.
func (rt ContainerRuntime) supportsHostGatewayAddHost() bool {
	return rt.Bin != runtimeApple
}

// supportsPullNever reports whether `run --pull never` is supported. Apple's
// container CLI does not expose a pull policy flag, so callers that need a
// no-pull probe must check the local image cache before running.
func (rt ContainerRuntime) supportsPullNever() bool {
	return rt.Bin != runtimeApple
}

// supportsNoNewPrivileges reports whether the runtime accepts Docker/Podman's
// `--security-opt no-new-privileges` hardening flag.
func (rt ContainerRuntime) supportsNoNewPrivileges() bool {
	return rt.Bin != runtimeApple
}

// HardeningSupportError reports why the runtime cannot honour the requested
// hardening mode, or nil when it can. Apple's container runtime supports
// --hardened: its `container network create --internal` is a vmnet host-only
// network (external egress blocked, host gateway still reachable -- the per-scan
// network enforcement --hardened needs), and the runner verifies that
// fail-closed per scan (see needsHardenedNetVerify). The one flag Apple's CLI
// does not expose is --security-opt no-new-privileges, but on a VM-per-container
// runtime the VM boundary is the isolation, not in-guest privilege hardening: an
// escalated process is still trapped in a disposable VM with no host filesystem
// or credentials. Apple's own untrusted-code sandbox (containerization's
// examples/sandboxy) hardens exactly this way -- VM + read-only mounts +
// host-only network + allowlisting proxy, no no-new-privileges. So --hardened is
// accepted; only --hardened-rootless-runtime (the rootless-podman non-network
// half) is refused, since Apple's network half works. See docs/apple.md.
func (rt ContainerRuntime) HardeningSupportError(hardenedRootless bool) error {
	if rt.Bin == runtimeApple && hardenedRootless {
		return fmt.Errorf("--runtime apple does not support --hardened-rootless-runtime " +
			"(that is the rootless-podman non-network half); use --hardened, whose " +
			"--internal host-only network Apple's container runtime supports")
	}
	return nil
}

// runArgs starts a runtime `run` command, adding runtime-specific flags that
// must precede the common options. Apple's container CLI writes lifecycle
// progress to stdout by default; suppress it so probe parsers and Claude's
// stream-json reader only see the container payload.
func (rt ContainerRuntime) runArgs(args ...string) []string {
	out := []string{"run"}
	if rt.Bin == runtimeApple {
		out = append(out, "--progress", "none")
	}
	return append(out, args...)
}

// runtimeProber runs a runtime command and returns its stdout. The production
// prober shells out; tests inject a stub so DetectRuntime's selection logic is
// exercised without a live daemon.
type runtimeProber func(name string, args ...string) ([]byte, error)

func execProber(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// DetectRuntime resolves the operator's --runtime choice into a
// ContainerRuntime, verifying the engine is actually reachable. prefer is
// "docker" (or "" defaulting to docker), "podman", or "apple". There is no
// auto-detection or fallback: a podman-only host left at the docker default
// still reports unavailable, by design (explicit opt-in). For podman it also
// probes rootless-ness so the run path can decide on --userns=keep-id.
//
// Returns (zero, false) when the chosen engine is not installed or its daemon
// is unreachable, so the caller emits the same hard error it emits for a
// missing docker.
func DetectRuntime(prefer string) (ContainerRuntime, bool) {
	return detectRuntime(prefer, execProber)
}

func detectRuntime(prefer string, probe runtimeProber) (ContainerRuntime, bool) {
	switch prefer {
	case "", "docker":
		// {{.ServerVersion}} exists in docker's info schema; this matches the
		// availability semantics of the former DockerAvailable (nil err +
		// non-empty output == reachable).
		out, err := probe("docker", "info", "--format", "{{.ServerVersion}}")
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			return ContainerRuntime{}, false
		}
		return ContainerRuntime{Bin: "docker", Version: string(bytes.TrimSpace(out))}, true
	case "podman":
		// podman's info has no .ServerVersion (a docker-only field that would
		// error the Go template); .Version.Version is the engine version and
		// .Host.Security.Rootless is the rootless flag. One call confirms
		// reachability AND rootless-ness without ever feeding podman the
		// docker template.
		out, err := probe("podman", "info", "--format", "{{.Version.Version}}|{{.Host.Security.Rootless}}")
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			return ContainerRuntime{}, false
		}
		version, rootless, ok := parsePodmanInfo(out)
		if !ok {
			return ContainerRuntime{}, false
		}
		return ContainerRuntime{Bin: "podman", Rootless: rootless, Version: version}, true
	case runtimeApple:
		// Apple's container CLI has no docker/podman-compatible `info`
		// template. `system status` verifies the background service is running;
		// parse the apiserver version best-effort for logs/settings.
		out, err := probe("container", "system", "status")
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			return ContainerRuntime{}, false
		}
		return ContainerRuntime{Bin: runtimeApple, Version: parseAppleStatus(out)}, true
	default:
		return ContainerRuntime{}, false
	}
}

// parsePodmanInfo splits the "<version>|<rootless>" line emitted by the podman
// info probe. ok is false when the line is malformed or the rootless field is
// not a bool, so DetectRuntime treats an unparseable probe as unavailable
// rather than guessing the uid-remap behaviour (which would silently break
// bind-mount ownership).
func parsePodmanInfo(out []byte) (version string, rootless bool, ok bool) {
	v, r, found := strings.Cut(strings.TrimSpace(string(out)), "|")
	if !found {
		return "", false, false
	}
	b, err := strconv.ParseBool(strings.TrimSpace(r))
	if err != nil {
		return "", false, false
	}
	return strings.TrimSpace(v), b, true
}

// parseAppleStatus extracts the apiserver version from `container system status`
// output. The runtime identity is "apple"; this parses the Apple CLI output.
func parseAppleStatus(out []byte) string {
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "apiserver.version" {
			continue
		}
		if v := firstDottedVersion(strings.Join(fields[1:], " ")); v != "" {
			return v
		}
	}
	return firstDottedVersion(string(out))
}

func firstDottedVersion(s string) string {
	for _, field := range strings.Fields(s) {
		field = strings.Trim(field, "(),")
		if _, _, ok := parseMajorMinor(field); ok {
			return field
		}
	}
	return ""
}

// podman gained `--add-host name:host-gateway` in 4.7; below that the egress
// path cannot resolve the host alias.
const (
	podmanHostGatewayMajor = 4
	podmanHostGatewayMinor = 7
)

// podmanHostGatewaySupported reports whether the podman version is recent enough
// to honour `--add-host host.docker.internal:host-gateway`, which the egress
// path depends on. An unparseable version returns true so a probe quirk never
// produces a spurious startup warning.
func podmanHostGatewaySupported(version string) bool {
	major, minor, ok := parseMajorMinor(version)
	if !ok {
		return true
	}
	return major > podmanHostGatewayMajor || (major == podmanHostGatewayMajor && minor >= podmanHostGatewayMinor)
}

// parseMajorMinor pulls the leading major and minor integers out of a dotted
// version string ("4.9.4" -> 4, 9). ok is false when either is absent or
// non-numeric.
func parseMajorMinor(version string) (major, minor int, ok bool) {
	majStr, rest, found := strings.Cut(strings.TrimSpace(version), ".")
	if !found {
		return 0, 0, false
	}
	minStr, _, _ := strings.Cut(rest, ".")
	maj, err1 := strconv.Atoi(majStr)
	min, err2 := strconv.Atoi(minStr)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}

// HostGatewaySupported reports whether the detected runtime is known to honour
// `--add-host host.docker.internal:host-gateway`, which the egress path needs.
// Always true for docker; for podman it checks the detected version against 4.7.
// Used for a soft startup warning, not a hard gate (an unparseable version
// returns true so a probe quirk never blocks startup).
func (rt ContainerRuntime) HostGatewaySupported() bool {
	if rt.Bin != "podman" {
		return true
	}
	return podmanHostGatewaySupported(rt.Version)
}

// VerifyKeepID smoke-tests `--userns=keep-id` for rootless podman so a missing
// or too-small /etc/subuid range fails once at startup with an actionable
// message instead of silently breaking every scan's bind-mount ownership. It is
// a no-op for docker and rootful podman. It is also skipped (returns nil) when
// the runner image is not yet present locally: the check needs an image to run,
// and the first scan will pull it -- and surface any sub-id problem -- then, so
// startup never eagerly pulls.
func VerifyKeepID(ctx context.Context, rt ContainerRuntime, image string) error {
	if !rt.needsKeepID() {
		return nil
	}
	if image == "" || !imageExistsLocally(ctx, rt, image) {
		return nil
	}
	out, err := exec.CommandContext(ctx, rt.bin(), "run", "--rm", "--pull", "never",
		"--userns=keep-id", "--entrypoint", "sh", "--", image, "-c", "exit 0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rootless podman --userns=keep-id smoke test failed "+
			"(ensure /etc/subuid and /etc/subgid grant your user a sub-id range; "+
			"see `podman system migrate`): %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
