package worker

// Container runtime selection. scrutineer shells out to an OCI engine (docker
// or podman) to run each scan in an ephemeral container. This file owns the
// engine choice and the one trait that changes the generated `run` flags --
// rootless podman's uid remapping -- so the rest of the package stays
// runtime-neutral.

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// ContainerRuntime identifies the OCI engine scrutineer shells out to and the
// one trait that changes the generated `run` flags: rootless podman maps
// --user uid:gid through /etc/subuid, so files written to bind mounts land as
// the wrong host uid unless --userns=keep-id is set. docker and rootful podman
// both run the container process as the host uid directly, so they need no
// remap. The zero value is the docker runtime, so a bare ContainerRunner{}
// (tests, RunnerImageName) keeps shelling out to "docker".
type ContainerRuntime struct {
	Bin      string // "docker" or "podman"; "" means docker
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
	if rt.Bin != "" {
		return rt.Bin
	}
	return "docker"
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
// --internal network fail-closed before running. True only for rootless podman:
// its pasta/slirp4netns host path is what varies across backends and what
// --internal can sever, so the isolation must be proven, not assumed. docker and
// rootful podman both run a bridge in the host netns (gateway on the host), so
// they keep the trusted path and pay no probe cost. Same condition as
// needsKeepID today, but a deliberately separate concern (network trust vs uid
// remap) so the two can diverge without surprising each other.
func (rt ContainerRuntime) needsHardenedNetVerify() bool {
	return rt.Bin == "podman" && rt.Rootless
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
// "docker" (or "" defaulting to docker) or "podman". There is no
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
