//go:build podman

// Integration tests that drive a real rootless podman. They are excluded from
// the default build so CI (which has no podman) stays green; run them with:
//
//	go test -tags podman ./internal/worker/
//
// Each test skips when podman is absent or the environment can't support the
// specific check, so the suite degrades cleanly on partial setups.
package worker

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	alpineImage = "docker.io/library/alpine:3.20"
	curlImage   = "docker.io/curlimages/curl:latest"
)

func podmanOrSkip(t *testing.T) ContainerRuntime {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman not installed")
	}
	rt, ok := DetectRuntime("podman")
	if !ok {
		t.Skip("podman not reachable")
	}
	return rt
}

func pullOrSkip(t *testing.T, rt ContainerRuntime, image string) string {
	t.Helper()
	if imageExistsLocally(context.Background(), rt, image) {
		return image
	}
	if out, err := exec.Command(rt.bin(), "pull", image).CombinedOutput(); err != nil {
		t.Skipf("cannot pull %s: %v: %s", image, err, strings.TrimSpace(string(out)))
	}
	return image
}

func runProbeOutput(t *testing.T, rt ContainerRuntime, args []string) string {
	t.Helper()
	out, _ := exec.Command(rt.bin(), args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// TestIntegration_KeepIDOwnership is the core rootless fix: a container running
// under --userns=keep-id must write bind-mounted files as the invoking host
// user, not a remapped sub-uid. Without keep-id this assertion fails.
func TestIntegration_KeepIDOwnership(t *testing.T) {
	rt := podmanOrSkip(t)
	if !rt.Rootless {
		t.Skip("podman is not rootless; keep-id only applies to rootless")
	}
	image := pullOrSkip(t, rt, alpineImage)
	work := t.TempDir()

	// Mirror the --user + --userns=keep-id flags the real runner adds, plus the
	// SELinux relabel (":z") it adds on an SELinux host -- without it this would
	// fail for a MAC reason on enforcing hosts rather than testing keep-id.
	args := []string{
		"run", "--rm", "--userns=keep-id",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", bindMount(work, "/work", HostSELinuxEnabled()), "-w", "/work",
		"--entrypoint", "sh", "--", image, "-c", "touch /work/out",
	}
	if out, err := exec.Command(rt.bin(), args...).CombinedOutput(); err != nil {
		t.Fatalf("container run failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	info, err := os.Stat(filepath.Join(work, "out"))
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	if int(st.Uid) != os.Getuid() {
		t.Errorf("bind-mount output owned by uid %d, want host uid %d (keep-id not applied?)", st.Uid, os.Getuid())
	}
}

// TestIntegration_SELinuxBindMount exercises the relabeled-mount smoke test on a
// real podman. On an SELinux-enabled host it proves the ":z" relabel actually
// lets the container read a host-seeded file and write output the host reads
// back; on a non-SELinux host VerifySELinuxMount is a no-op, so the test skips.
func TestIntegration_SELinuxBindMount(t *testing.T) {
	rt := podmanOrSkip(t)
	if !HostSELinuxEnabled() {
		t.Skip("SELinux not enabled on host; nothing to verify")
	}
	image := pullOrSkip(t, rt, alpineImage)
	if err := VerifySELinuxMount(context.Background(), rt, image, true); err != nil {
		t.Fatalf("VerifySELinuxMount on a relabeled mount: %v", err)
	}
}

// TestIntegration_ResolveHostGatewayIPv4 checks the egress path's gateway probe
// returns a usable IPv4 on podman (gated by podman >= 4.7 host-gateway support).
func TestIntegration_ResolveHostGatewayIPv4(t *testing.T) {
	rt := podmanOrSkip(t)
	image := pullOrSkip(t, rt, alpineImage)
	ip := ResolveHostGatewayIPv4(rt, image, "")
	if ip == "" {
		t.Skip("host-gateway did not resolve (podman < 4.7 or unusual networking)")
	}
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		t.Errorf("ResolveHostGatewayIPv4 = %q, want an IPv4 address", ip)
	}
}

// TestIntegration_HardenedEgressBlocked proves the --internal network actually
// blocks egress -- and that the probe is not a tautology, by first confirming
// the host can reach the internet on a normal network.
func TestIntegration_HardenedEgressBlocked(t *testing.T) {
	rt := podmanOrSkip(t)
	image := pullOrSkip(t, rt, curlImage)

	// Baseline on the default network: if the host itself has no egress we
	// cannot prove the --internal network is what blocks it, so skip.
	if base := runProbeOutput(t, rt, hardenedEgressBlockArgs("podman", image)); !strings.Contains(base, "REACHED") {
		t.Skipf("host has no baseline egress (probe: %q); cannot prove --internal blocks it", base)
	}

	const netName = "scrutineer-itest-internal"
	if err := EnsureHardenedNetwork(rt, netName); err != nil {
		t.Fatalf("create internal network: %v", err)
	}
	defer func() { _ = exec.Command(rt.bin(), "network", "rm", "--", netName).Run() }()

	if got := runProbeOutput(t, rt, hardenedEgressBlockArgs(netName, image)); !strings.Contains(got, "BLOCKED") {
		t.Errorf("egress on --internal network = %q, want BLOCKED", got)
	}
}

// TestIntegration_VerifyHardenedNetwork exercises the full fail-closed check
// against a real egress proxy: the --internal network must block external
// egress yet still reach the host proxy.
func TestIntegration_VerifyHardenedNetwork(t *testing.T) {
	rt := podmanOrSkip(t)
	image := pullOrSkip(t, rt, curlImage)

	token := NewProxyToken()
	port, err := StartEgressProxy(&EgressProxy{Allow: []string{HostGatewayAlias}, Token: token, Log: slog.Default()})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	const netName = "scrutineer-itest-verify"
	if err := EnsureHardenedNetwork(rt, netName); err != nil {
		t.Fatalf("create internal network: %v", err)
	}
	defer func() { _ = exec.Command(rt.bin(), "network", "rm", "--", netName).Run() }()

	gwIP := ResolveHostGatewayIPv4(rt, image, netName)
	if gwIP == "" {
		t.Skip("host-gateway unresolved on this network; cannot test proxy reachability")
	}

	d := ContainerRunner{Runtime: rt, Hardened: true, ProxyURL: ProxyURL(token, port)}
	if err := d.verifyHardenedNetwork(hardenedNet{name: netName, gatewayIP: gwIP}, image); err != nil {
		t.Fatalf("verifyHardenedNetwork on a correct internal network: %v", err)
	}
}
