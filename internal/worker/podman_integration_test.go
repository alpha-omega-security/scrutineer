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
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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
	if base := runProbeOutput(t, rt, rt.hardenedEgressBlockArgs("podman", image)); !strings.Contains(base, "REACHED") {
		t.Skipf("host has no baseline egress (probe: %q); cannot prove --internal blocks it", base)
	}

	const netName = "scrutineer-itest-internal"
	if err := EnsureHardenedNetwork(rt, netName); err != nil {
		t.Fatalf("create internal network: %v", err)
	}
	defer func() { _ = exec.Command(rt.bin(), "network", "rm", "--", netName).Run() }()

	if got := runProbeOutput(t, rt, rt.hardenedEgressBlockArgs(netName, image)); !strings.Contains(got, "BLOCKED") {
		t.Errorf("egress on --internal network = %q, want BLOCKED", got)
	}
}

// TestIntegration_VerifyHardenedNetwork exercises the full fail-closed check
// against a real egress proxy: the --internal network must block external
// egress yet still reach the host proxy.
func TestIntegration_VerifyHardenedNetwork(t *testing.T) {
	rt := podmanOrSkip(t)
	if rt.Rootless {
		// Host-proxy reachability across an --internal network is rootful-only:
		// on rootless podman the host proxy sits in the host netns, unreachable
		// from the isolated network, which is why hardened mode runs the egress
		// proxy as a sidecar there instead. The rootless path is covered by
		// TestIntegration_ProxySidecarEnforcedEgress.
		t.Skip("host-proxy across --internal is rootful-only; rootless uses the egress sidecar")
	}
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

	d := ContainerRunner{Runtime: rt, Hardened: true, ProxyURL: ProxyURLForHost(token, HostGatewayAlias, port)}
	if err := d.verifyHardenedNetwork(hardenedNet{name: netName, gatewayIP: gwIP}, image); err != nil {
		t.Fatalf("verifyHardenedNetwork on a correct internal network: %v", err)
	}
}

// runnerImageOrSkip returns a locally-present scrutineer-runner image (which
// carries the scrutineer binary the egress sidecar runs) or skips. Set
// SCRUTINEER_TEST_RUNNER_IMAGE to a locally-built tag; it defaults to the
// published runner image. It never pulls -- the runner image is large and may
// need registry auth.
func runnerImageOrSkip(t *testing.T, rt ContainerRuntime) string {
	t.Helper()
	image := os.Getenv("SCRUTINEER_TEST_RUNNER_IMAGE")
	if image == "" {
		image = DefaultRunnerImage
	}
	if !imageExistsLocally(context.Background(), rt, image) {
		t.Skipf("runner image %q not present locally; build it (Dockerfile.runner) or set SCRUTINEER_TEST_RUNNER_IMAGE", image)
	}
	return image
}

// containerScriptOutput runs `sh -c script` in a throwaway container with the
// given extra run args and returns trimmed combined output.
func containerScriptOutput(t *testing.T, rt ContainerRuntime, extra []string, image, script string) string {
	t.Helper()
	args := append([]string{"run", "--rm"}, extra...)
	args = append(args, "--entrypoint", "sh", "--", image, "-c", script)
	out, _ := exec.Command(rt.bin(), args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

// TestIntegration_ProxySidecarEnforcedEgress is the end-to-end check for the
// rootless hardened egress sidecar: under rootless podman --hardened, the egress
// proxy runs as a sidecar on the per-scan --internal network, and a scan reaches
// the host skill API only through it while the allowlist is enforced. It
// exercises the real
// setupHardenedNetwork path (start sidecar, connect both legs, fail-closed
// verification) and then the scan's own egress.
//
// It skips when the network backend does not forward host-gateway to the host
// loopback -- the precondition the whole feature rests on, which this box cannot
// assume -- so a backend that lacks it reads as "skipped: needs host-loopback
// forwarding", not a spurious failure.
func TestIntegration_ProxySidecarEnforcedEgress(t *testing.T) {
	rt := podmanOrSkip(t)
	if !rt.Rootless {
		t.Skip("egress proxy sidecar is rootless-podman only")
	}
	image := runnerImageOrSkip(t, rt)

	// A stand-in for the host skill API: httptest binds 127.0.0.1, exactly the
	// loopback-bound web server the real sidecar must reach across the namespace
	// boundary.
	const apiBody = "scrutineer-host-api-ok"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, apiBody)
	}))
	defer api.Close()
	_, apiPort, _ := net.SplitHostPort(api.Listener.Addr().String())

	gwIP := ResolveHostGatewayIPv4(rt, image, "")
	if gwIP == "" {
		t.Skip("host-gateway did not resolve (podman >= 4.7 and a working rootless backend needed)")
	}

	// Precondition: the backend must forward host-gateway to the host loopback,
	// or the sidecar can never reach the loopback-bound skill API. Prove it with
	// a plain container on the default network before relying on it.
	probe := containerScriptOutput(t, rt,
		[]string{"--network", "podman", "--add-host", HostGatewayAlias + ":" + gwIP},
		image, "curl -s -m 8 -o /dev/null -w '%{http_code}' http://"+HostGatewayAlias+":"+apiPort+"/ || true")
	if probe != "200" {
		t.Skipf("this rootless backend does not forward host-gateway to the host loopback (probe got %q); the egress sidecar requires it -- see docs/podman.md", probe)
	}

	d := ContainerRunner{
		Runtime:  rt,
		Hardened: true,
		Image:    image,
		Egress: EgressSidecarConfig{
			Token:     NewProxyToken(),
			Allow:     []string{HostGatewayAlias},
			APIPort:   apiPort,
			GatewayIP: gwIP,
		},
	}
	sj := SkillJob{ScanID: 990001} // high id, unlikely to collide with a real scan

	hn, cleanup, err := d.setupHardenedNetwork(sj, image)
	if err != nil {
		t.Fatalf("setupHardenedNetwork (sidecar): %v", err)
	}
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			cleanup()
		}
	}()
	if hn.proxyEndpoint == "" {
		t.Fatal("expected a sidecar endpoint from setupHardenedNetwork")
	}

	proxyURL := ProxyURLForEndpoint(d.Egress.Token, hn.proxyEndpoint)

	// (1) A scan on the --internal network reaches the host skill API THROUGH the
	// sidecar: this is the whole chain (scan -> sidecar -> host loopback).
	got := containerScriptOutput(t, rt, []string{"--network", hn.name}, image,
		"curl -s -m 8 -x "+proxyURL+" http://"+HostGatewayAlias+":"+apiPort+"/ || true")
	if got != apiBody {
		t.Errorf("scan -> sidecar -> host API: got %q, want %q", got, apiBody)
	}

	// (2) The allowlist is enforced at the sidecar: a host not on it is refused
	// (the proxy answers 403), proving the sidecar is a real enforcement point.
	denied := containerScriptOutput(t, rt, []string{"--network", hn.name}, image,
		"curl -s -m 8 -o /dev/null -w '%{http_code}' -x "+proxyURL+" http://example.org/ || true")
	if denied != "403" {
		t.Errorf("non-allowlisted egress via sidecar: got status %q, want 403", denied)
	}

	// (3) Teardown removes the sidecar and then its network.
	cleanup()
	cleanedUp = true
	name := proxySidecarName(sj.ScanID)
	if err := exec.Command(rt.bin(), "inspect", "--", name).Run(); err == nil {
		t.Errorf("sidecar %q still present after cleanup", name)
	}
	if err := exec.Command(rt.bin(), "network", "inspect", "--", hn.name).Run(); err == nil {
		t.Errorf("network %q still present after cleanup", hn.name)
	}
}
