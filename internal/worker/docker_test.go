package worker

import (
	"net"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestDockerArgs_InternalNetwork(t *testing.T) {
	d := DockerRunner{
		Image:         "img:latest",
		ProxyURL:      "http://u:p@host.docker.internal:9",
		Network:       "scrutineer-egress",
		HostGatewayIP: "172.18.0.1",
	}
	args := d.dockerArgs("/abs/work", []string{"claude", "-p", "go"})

	if got := flagValue(args, "--network"); got != "scrutineer-egress" {
		t.Errorf("--network = %q, want scrutineer-egress", got)
	}
	if got := flagValue(args, "--add-host"); got != HostGatewayAlias+":172.18.0.1" {
		t.Errorf("--add-host = %q, want gateway alias mapped to internal bridge IP", got)
	}
	if got := flagValue(args, "-v"); got != "/abs/work:/work" {
		t.Errorf("-v = %q", got)
	}
	wantTail := []string{"img:latest", "claude", "-p", "go"}
	if !slices.Equal(args[len(args)-len(wantTail):], wantTail) {
		t.Errorf("tail = %v, want %v", args[len(args)-len(wantTail):], wantTail)
	}
}

func TestDockerArgs_NoProxyMeansNoNetwork(t *testing.T) {
	d := DockerRunner{Image: "img"}
	args := d.dockerArgs("/w", []string{"claude"})
	if got := flagValue(args, "--network"); got != "none" {
		t.Errorf("--network = %q, want none", got)
	}
	if slices.Contains(args, "HTTPS_PROXY=") {
		t.Errorf("did not expect proxy env when ProxyURL is empty")
	}
}

func TestDockerArgs_ProxyWithoutNetworkOmitsFlag(t *testing.T) {
	d := DockerRunner{Image: "img", ProxyURL: "http://x"}
	args := d.dockerArgs("/w", []string{"claude"})
	if slices.Contains(args, "--network") {
		t.Errorf("did not expect --network without DockerRunner.Network: %v", args)
	}
}

// TestEnsureEgressNetwork_BlocksDirectEgress is the regression test for
// GHSA-qwg8-7975-9jwh: a container on the egress network must be able to
// reach the host's bridge gateway (where the proxy listens) but must NOT be
// able to reach the public internet by ignoring HTTPS_PROXY.
func TestEnsureEgressNetwork_BlocksDirectEgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker integration test in -short")
	}
	if runtime.GOOS != "linux" {
		t.Skip("internal-network egress enforcement is linux-only; on Docker Desktop the bridge gateway is the VM, not the host")
	}
	if !DockerAvailable() {
		t.Skip("docker not available")
	}
	const name = "scrutineer-egress-test"
	_ = exec.Command("docker", "network", "rm", name).Run()
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })

	gw, err := EnsureEgressNetwork(name)
	if err != nil {
		t.Fatalf("EnsureEgressNetwork: %v", err)
	}
	if net.ParseIP(gw) == nil || net.ParseIP(gw).To4() == nil {
		t.Fatalf("gateway %q is not an IPv4 address", gw)
	}

	gw2, err := EnsureEgressNetwork(name)
	if err != nil || gw2 != gw {
		t.Fatalf("second call not idempotent: gw=%q gw2=%q err=%v", gw, gw2, err)
	}

	// Host gateway must be reachable: connection refused (nothing on :1) is
	// fine, "network unreachable" or a timeout is not.
	out, _ := exec.Command("docker", "run", "--rm", "--network", name, "alpine:3",
		"wget", "-T", "3", "-qO-", "http://"+gw+":1/").CombinedOutput()
	if !containsAny(string(out), "Connection refused", "connection refused") {
		t.Errorf("expected host gateway reachable (connection refused on closed port), got: %s", out)
	}

	// Public internet must be unreachable when the proxy env vars are
	// ignored. This is the property the advisory PoC relied on breaking.
	out, _ = exec.Command("docker", "run", "--rm", "--network", name, "alpine:3",
		"wget", "-T", "3", "-qO-", "http://1.1.1.1/").CombinedOutput()
	if !containsAny(string(out), "unreachable", "timed out", "No route") {
		t.Errorf("expected direct egress to be blocked, got: %s", out)
	}
}

func TestEnsureEgressNetwork_RejectsNonInternal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker integration test in -short")
	}
	if !DockerAvailable() {
		t.Skip("docker not available")
	}
	const name = "scrutineer-egress-notinternal"
	_ = exec.Command("docker", "network", "rm", name).Run()
	if out, err := exec.Command("docker", "network", "create", name).CombinedOutput(); err != nil {
		t.Fatalf("create non-internal network: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })

	if _, err := EnsureEgressNetwork(name); err == nil {
		t.Fatalf("expected error when network exists but is not --internal")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
