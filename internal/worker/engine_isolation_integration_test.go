package worker

// Real-container check of why HardeningSupportError refuses --hardened on
// Docker Engine: a per-scan --internal network keeps a host address on its
// bridge, so a scan reaches host services through that gateway without going
// through the egress proxy. The scan enters through the production runner with
// the in-process host proxy, as Docker Engine scans would. Load the probe image
// described in network_isolation_integration_test.go into the Engine daemon,
// then run on its host:
//
//	SCRUTINEER_TEST_NETWORK_ISOLATION_IMAGE=scrutineer-netprobe-test go test -race -run EngineIsolation -v ./internal/worker/

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness/container"
)

func engineIsolationSetup(t *testing.T) isolationEnv {
	t.Helper()
	image := os.Getenv(isolationImageEnv)
	if image == "" {
		t.Skipf("set %s to run the network isolation integration", isolationImageEnv)
	}
	rt, ok := container.DetectRuntime("docker")
	if !ok {
		t.Skip("docker is unavailable")
	}
	if rt.NeedsEgressSidecar() {
		t.Skip("docker uses the egress sidecar here; that path is covered by network_isolation_integration_test.go")
	}
	if !imageExistsLocally(t.Context(), rt, image) {
		t.Skipf("probe image %q is unavailable locally", image)
	}
	recorder := &apiRecorder{}
	api := httptest.NewServer(recorder)
	t.Cleanup(api.Close)
	_, apiPort, err := net.SplitHostPort(api.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	token := NewProxyToken()
	port, closeProxy, err := StartScopedEgressProxy(&EgressProxy{
		Allow:    []string{HostGatewayAlias},
		Token:    token,
		APIPort:  apiPort,
		APIHosts: []string{HostGatewayAlias},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeProxy)
	gatewayIP := ResolveHostGatewayIPv4(rt, image, "")
	if gatewayIP == "" {
		t.Fatal("host-gateway did not resolve on Docker Engine")
	}
	return isolationEnv{
		rt:        rt,
		image:     image,
		apiPort:   apiPort,
		gatewayIP: gatewayIP,
		api:       recorder,
		proxyURL:  ProxyURLForHost(token, HostGatewayAlias, port),
	}
}

const engineGatewayScript = `cd /work
NP="env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy"
echo @tcp@ | $NP nc -w 3 @GW@ @PORT@ >/work/tcp.out 2>&1
echo $? >/work/tcp.exit
$NP dig +tries=1 +time=2 @@GW@ -p @PORT@ @udp@.probe.test >/work/udp.out 2>&1
echo $? >/work/udp.exit
`

// A direct connection to the scan network's own gateway reaches a host service.
// Once it no longer does, the Docker Engine refusal can be revisited.
func TestIntegration_EngineIsolationGatewayDirect(t *testing.T) {
	env := engineIsolationSetup(t)
	l := newControlledListener(t)
	ctl := runControls(t, env, l)
	key := isolationKey("gateway")
	network := hardenedNetworkName(key)
	// RunSkill reuses an existing network, which is how the probe learns its gateway.
	if err := EnsureHardenedNetwork(env.rt, network); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", "--", network).Run() })
	out, err := exec.Command("docker", "network", "inspect", "--format", "{{(index .IPAM.Config 0).Gateway}}", "--", network).Output()
	if err != nil {
		t.Fatal(err)
	}
	gw := strings.TrimSpace(string(out))
	tcpMarker, udpMarker := newMarker(t, "gwtcp"), newMarker(t, "gwudp")
	script := strings.NewReplacer("@GW@", gw, "@PORT@", l.port, "@tcp@", tcpMarker, "@udp@", udpMarker).Replace(engineGatewayScript)
	work := newScanWorkspace(t)
	ctx, cancel := context.WithTimeout(t.Context(), scanTimeout)
	defer cancel()
	if err := env.runScan(ctx, key, work, script); err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	time.Sleep(grace)
	files := readWorkspaceFiles(work)
	t.Logf("gateway %s: tcp exit=%q out=%q, udp exit=%q out=%q", gw, files["tcp.exit"], files["tcp.out"], files["udp.exit"], files["udp.out"])

	for _, p := range []struct{ name, control, marker string }{
		{"tcp", "tcp", tcpMarker},
		{"udp", "dns_udp", udpMarker},
	} {
		t.Run(p.name, func(t *testing.T) {
			ctl.require(t, p.control)
			if !l.waitSaw(p.marker) {
				t.Errorf("a direct %s packet to the scan network's gateway %s no longer reaches a host service, so the --hardened refusal on Docker Engine may be lifted", p.name, gw)
			}
		})
	}
}
