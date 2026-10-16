package worker

// Real-container checks of what a hardened scan can reach across its lifecycle
// on Docker Desktop: once cancelled, once its egress sidecar fails, and while a
// concurrent scan holds a wider egress permission. Each refusal is paired with
// a request that does arrive, so a broken path cannot pass for isolation. Run
// with the probe image described in network_isolation_integration_test.go:
//
//	SCRUTINEER_TEST_NETWORK_ISOLATION_IMAGE=scrutineer-netprobe-test go test -race -run ScanLifecycle -v ./internal/worker/

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	heartbeatWait   = 60 * time.Second
	cancelReturnMax = 30 * time.Second
	stageWait       = 120 * time.Second
)

// heartbeatScript appends to /work/beat every half second until it is killed.
const heartbeatScript = `cd /work
i=0
while [ "$i" -lt 600 ]; do echo "$i" >> /work/beat; sleep 0.5; i=$((i+1)); done
`

func TestIntegration_ScanLifecycleCancelStopsScan(t *testing.T) {
	env := isolationSetup(t)
	work := newScanWorkspace(t)
	key := isolationKey("cancel")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- env.runScan(ctx, key, work, heartbeatScript) }()

	// Two beats are the control: the scan was observably running when cancelled.
	if !waitForFile(work, "beat", heartbeatWait, errc) || !waitBeats(work, 2) {
		t.Fatal("the scan never started beating, so cancellation cannot be judged")
	}
	cancel()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("RunSkill succeeded after cancellation")
		}
	case <-time.After(cancelReturnMax):
		t.Fatal("RunSkill did not return after cancellation")
	}
	before := beatCount(work)
	time.Sleep(3 * grace)
	if after := beatCount(work); after != before {
		t.Errorf("the scan kept running after RunSkill returned: %d beats, then %d", before, after)
	}
	assertScanRemoved(t, key)
}

const proxyFailureScript = `cd /work
code() { curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$@"; }
code http://host.docker.internal:@API@/@before@ >/work/before.out 2>/work/before.err
touch /work/ready
i=0
while [ ! -f /work/killed ] && [ "$i" -lt 240 ]; do sleep 0.5; i=$((i+1)); done
code http://host.docker.internal:@API@/@after@ >/work/after.out 2>/work/after.err
echo $? >/work/after.exit
`

func TestIntegration_ScanLifecycleProxyFailureFailsClosed(t *testing.T) {
	env := isolationSetup(t)
	work := newScanWorkspace(t)
	key := isolationKey("proxyfail")
	beforeMarker, afterMarker := newMarker(t, "before"), newMarker(t, "after")
	script := strings.NewReplacer("@API@", env.apiPort, "@before@", beforeMarker, "@after@", afterMarker).Replace(proxyFailureScript)
	ctx, cancel := context.WithTimeout(t.Context(), scanTimeout)
	defer cancel()
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(work, "killed"), nil, 0o600) })
	errc := make(chan error, 1)
	go func() { errc <- env.runScan(ctx, key, work, script) }()

	if !waitForFile(work, "ready", stageWait, errc) {
		t.Fatal("the scan never reached the sidecar failure")
	}
	if out, err := exec.Command("docker", "kill", "--", proxySidecarName(key)).CombinedOutput(); err != nil {
		t.Fatalf("kill sidecar: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(work, "killed"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	time.Sleep(grace)
	files := readWorkspaceFiles(work)
	t.Logf("before: code=%q; after: exit=%q code=%q err=%q", files["before.out"], files["after.exit"], files["after.out"], files["after.err"])

	if len(env.api.hostsFor(beforeMarker)) == 0 {
		t.Skipf("%s: the request before the failure never reached the API stand-in", controlFailedMessage)
	}
	if exit := files["after.exit"]; exit == "" || exit == "0" {
		t.Errorf("a request after the sidecar died did not fail: exit=%q code=%q", exit, files["after.out"])
	}
	if hosts := env.api.hostsFor(afterMarker); len(hosts) > 0 {
		t.Errorf("a request after the sidecar died reached the API with Host %q", hosts)
	}
	assertScanRemoved(t, key)
}

func TestIntegration_ScanLifecycleUnreachableAPIRefusesScan(t *testing.T) {
	env := isolationSetup(t)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_, closedPort, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()
	r := env.runner("touch /work/ran")
	r.Egress.APIPort = closedPort
	work := newScanWorkspace(t)
	key := isolationKey("noapi")
	ctx, cancel := context.WithTimeout(t.Context(), scanTimeout)
	defer cancel()

	err = runIsolatedScan(ctx, r, key, work)
	if err == nil || !strings.Contains(err.Error(), "egress proxy sidecar") {
		t.Errorf("RunSkill error = %v, want the egress proxy sidecar refusing to become ready", err)
	}
	if _, err := os.Stat(filepath.Join(work, "ran")); err == nil {
		t.Error("the scan ran although its egress sidecar never became ready")
	}
	assertScanRemoved(t, key)
}

const permissionHolderScript = `cd /work
curl -sS --max-time 10 -o /dev/null -w '%{http_code}' http://host.docker.internal:@PORT@/@granted@ >/work/granted.out 2>/work/granted.err
touch /work/ready
i=0
while [ ! -f /work/done ] && [ "$i" -lt 240 ]; do sleep 0.5; i=$((i+1)); done
`

const permissionProbeScript = `cd /work
rec() {
  name=$1; shift
  "$@" >"/work/$name.out" 2>"/work/$name.err"
  echo $? >"/work/$name.exit"
}
code() { curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$@"; }
rec own code http://host.docker.internal:@PORT@/@own@
rec peer code --proxy "${HTTPS_PROXY%@*}@@PEER@" http://host.docker.internal:@PORT@/@peer@
`

// Scan A may reach a host port that scan B may not, and both run at once with
// the same proxy token, as production scans do.
func TestIntegration_ScanLifecycleConcurrentPermissions(t *testing.T) {
	env := isolationSetup(t)
	l := newControlledListener(t)
	ctx, cancel := context.WithTimeout(t.Context(), scanTimeout)
	defer cancel()
	markers := map[string]string{}
	for _, n := range []string{"granted", "own", "peer", "ctlpeer"} {
		markers[n] = newMarker(t, n)
	}

	workA, keyA := newScanWorkspace(t), isolationKey("permita")
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(workA, "done"), nil, 0o600) })
	rA := env.runner(strings.NewReplacer("@PORT@", l.port, "@granted@", markers["granted"]).Replace(permissionHolderScript))
	rA.Egress.HostPorts = []string{l.port}
	errA := make(chan error, 1)
	go func() { errA <- runIsolatedScan(ctx, rA, keyA, workA) }()
	if !waitForFile(workA, "ready", stageWait, errA) {
		t.Fatal("scan A never started")
	}
	peerIP, err := rA.sidecarNetworkIP(proxySidecarName(keyA), hardenedNetworkName(keyA))
	if err != nil {
		t.Fatal(err)
	}
	peer := net.JoinHostPort(peerIP, proxySidecarPort)
	peerProxy := ProxyURLForEndpoint(rA.Egress.Token, peer)
	// A container on scan A's own network using A's proxy is the control that
	// the peer endpoint is live and would forward to the granted port.
	_ = env.defaultNetworkRun(t, "curl -sS --max-time 10 -o /dev/null --proxy "+peerProxy+" http://"+HostGatewayAlias+":"+l.port+"/"+markers["ctlpeer"], "--network", hardenedNetworkName(keyA))

	workB := newScanWorkspace(t)
	rB := env.runner(strings.NewReplacer("@PORT@", l.port, "@PEER@", peer, "@own@", markers["own"], "@peer@", markers["peer"]).Replace(permissionProbeScript))
	rB.Egress.Token = rA.Egress.Token
	if err := runIsolatedScan(ctx, rB, isolationKey("permitb"), workB); err != nil {
		t.Fatalf("scan B RunSkill: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workA, "done"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-errA; err != nil {
		t.Fatalf("scan A RunSkill: %v", err)
	}
	time.Sleep(grace)
	files := readWorkspaceFiles(workB)
	t.Logf("scan A granted code=%q; scan B own exit=%q code=%q, peer exit=%q code=%q err=%q",
		readWorkspaceFiles(workA)["granted.out"], files["own.exit"], files["own.out"], files["peer.exit"], files["peer.out"], files["peer.err"])

	t.Run("own_proxy", func(t *testing.T) {
		if !l.waitSaw(markers["granted"]) {
			t.Skipf("%s: scan A's granted request never arrived", controlFailedMessage)
		}
		// 403 is scan B's proxy refusing the port; 000 would only mean the
		// proxy was unreachable.
		if got := files["own.out"]; got != "403" {
			t.Errorf("scan B reached a port only scan A may use: code=%q exit=%q, want 403", got, files["own.exit"])
		}
		if l.saw(markers["own"]) {
			t.Error("scan B's request arrived on scan A's granted port")
		}
	})
	t.Run("peer_proxy", func(t *testing.T) {
		if !l.waitSaw(markers["ctlpeer"]) {
			t.Skipf("%s: scan A's proxy did not forward from its own network", controlFailedMessage)
		}
		if exit := files["peer.exit"]; exit == "" || exit == "0" {
			t.Errorf("scan B used scan A's proxy: exit=%q code=%q", exit, files["peer.out"])
		}
		if l.saw(markers["peer"]) {
			t.Error("scan B's request through scan A's proxy arrived")
		}
	})
}

// assertScanRemoved checks that no container, sidecar or network of the scan
// outlives RunSkill.
func assertScanRemoved(t *testing.T, key string) {
	t.Helper()
	network := hardenedNetworkName(key)
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "network="+network).Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("containers remain on %q: %s", network, out)
	}
	if exec.Command("docker", "inspect", "--", proxySidecarName(key)).Run() == nil {
		t.Errorf("sidecar %q remains", proxySidecarName(key))
	}
	if exec.Command("docker", "network", "inspect", "--", network).Run() == nil {
		t.Errorf("network %q remains", network)
	}
}

func beatCount(work string) int {
	b, _ := os.ReadFile(filepath.Join(work, "beat"))
	return strings.Count(string(b), "\n")
}

func waitBeats(work string, n int) bool {
	deadline := time.Now().Add(controlWait)
	for time.Now().Before(deadline) {
		if beatCount(work) >= n {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}

// waitForFile reports whether the scan created name in its workspace before d
// elapsed. A scan that ends first puts its error back for the caller.
func waitForFile(work, name string, d time.Duration, errc chan error) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		select {
		case err := <-errc:
			errc <- err
			return false
		default:
		}
		if _, err := os.Stat(filepath.Join(work, name)); err == nil {
			return true
		}
		time.Sleep(pollInterval)
	}
	return false
}
