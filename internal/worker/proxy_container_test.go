package worker

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

func TestProxyContainerConfig_RoundTrip(t *testing.T) {
	in := ProxyContainerConfig{
		Allow:       []string{"a", "*.b"},
		Deny:        []string{"c"},
		Token:       "tok",
		APIPort:     "9000",
		GatewayDial: "host.docker.internal",
		Listen:      ":3128",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out ProxyContainerConfig
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestStartProxyContainer_WritesConfig(t *testing.T) {
	if testing.Short() || !DockerAvailable() {
		t.Skip("needs docker")
	}
	dir := t.TempDir()
	// Use an image that definitely lacks scrutineer-proxy so the run fails
	// fast; we're only checking the config file gets written first.
	_, err := StartProxyContainer("alpine:3", "no-such-net", dir, ProxyContainerConfig{
		Allow: []string{"x"}, Token: "t", APIPort: "1",
	}, quietLog())
	if err == nil {
		t.Fatalf("expected error with bogus network")
	}
	b, rerr := os.ReadFile(filepath.Join(dir, "proxy.json"))
	if rerr != nil {
		t.Fatalf("proxy.json not written: %v", rerr)
	}
	var got ProxyContainerConfig
	if json.Unmarshal(b, &got) != nil || got.Token != "t" || got.Allow[0] != "x" {
		t.Errorf("proxy.json contents = %s", b)
	}
	info, _ := os.Stat(filepath.Join(dir, "proxy.json"))
	if info.Mode().Perm() != proxyConfigPerm {
		t.Errorf("proxy.json perms = %v, want %v", info.Mode().Perm(), os.FileMode(proxyConfigPerm))
	}
}

// TestProxyContainer_EndToEnd builds the full chain on whatever docker is
// available: internal network, proxy container, scan container reaching a
// host listener through the proxy and being blocked from direct egress.
// Gated on SCRUTINEER_TEST_IMAGE pointing at an image that contains the
// scrutineer-proxy binary (e.g. one built from Dockerfile.runner on this
// branch).
func TestProxyContainer_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short")
	}
	image := os.Getenv("SCRUTINEER_TEST_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_IMAGE to a runner image containing scrutineer-proxy")
	}
	if !DockerAvailable() {
		t.Skip("docker not available")
	}

	const network = "scrutineer-egress-e2e"
	_ = exec.Command("docker", "rm", "-f", network+"-proxy").Run()
	_ = exec.Command("docker", "network", "rm", network).Run()
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", network+"-proxy").Run()
		_ = exec.Command("docker", "network", "rm", network).Run()
	})
	if err := EnsureEgressNetwork(network); err != nil {
		t.Fatalf("ensure network: %v", err)
	}

	// Host-side stand-in for the scrutineer skill API.
	apiLn, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = apiLn.Close() })
	apiPort := strconv.Itoa(apiLn.Addr().(*net.TCPAddr).Port)
	go func() {
		_ = http.Serve(apiLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "skill-api-ok")
		}))
	}()

	pc, err := StartProxyContainer(image, network, t.TempDir(), ProxyContainerConfig{
		Allow:       []string{HostGatewayAlias, "example.com"},
		Token:       "e2etok",
		APIPort:     apiPort,
		GatewayDial: HostGatewayAlias,
	}, quietLog())
	if err != nil {
		t.Fatalf("start proxy container: %v", err)
	}
	t.Cleanup(pc.Stop)

	run := func(extra ...string) string {
		args := append([]string{"run", "--rm", "--network", network,
			"-e", "http_proxy=" + pc.URL(),
			"-e", "https_proxy=" + pc.URL(),
			"alpine:3"}, extra...)
		out, _ := exec.Command("docker", args...).CombinedOutput()
		return string(out)
	}

	if got := run("wget", "-T", "5", "-qO-", "http://"+HostGatewayAlias+":"+apiPort+"/api/ping"); got != "skill-api-ok" {
		t.Errorf("skill API via proxy: got %q, want skill-api-ok", got)
	}
	if got := run("wget", "-T", "5", "-qO-", "http://denied.test/"); !containsAny(got, "403", "Forbidden") {
		t.Errorf("non-allowlisted host via proxy should be 403, got: %s", got)
	}
	if got := run("sh", "-c", "unset http_proxy https_proxy; wget -T 3 -qO- http://1.1.1.1/ 2>&1"); !containsAny(got, "unreachable", "No route", "timed out") {
		t.Errorf("direct egress without proxy should be blocked, got: %s", got)
	}
}
