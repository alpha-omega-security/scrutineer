package worker

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestDockerArgs_InternalNetwork(t *testing.T) {
	d := DockerRunner{
		Image:    "img:latest",
		ProxyURL: "http://u:p@scrutineer-egress-proxy:3128",
		Network:  "scrutineer-egress",
	}
	args := d.dockerArgs("/abs/work", []string{"claude", "-p", "go"})

	if got := flagValue(args, "--network"); got != "scrutineer-egress" {
		t.Errorf("--network = %q, want scrutineer-egress", got)
	}
	if slices.Contains(args, "--add-host") {
		t.Errorf("scan containers no longer need --add-host: %v", args)
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
// GHSA-qwg8-7975-9jwh: a container on the egress network must NOT be able
// to reach the public internet by ignoring HTTPS_PROXY.
func TestEnsureEgressNetwork_BlocksDirectEgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker integration test in -short")
	}
	if !DockerAvailable() {
		t.Skip("docker not available")
	}
	const name = "scrutineer-egress-test"
	_ = exec.Command("docker", "network", "rm", name).Run()
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })

	if err := EnsureEgressNetwork(name); err != nil {
		t.Fatalf("EnsureEgressNetwork: %v", err)
	}
	if err := EnsureEgressNetwork(name); err != nil {
		t.Fatalf("second call not idempotent: %v", err)
	}

	out, _ := exec.Command("docker", "run", "--rm", "--network", name, "alpine:3",
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

	if err := EnsureEgressNetwork(name); err == nil {
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
