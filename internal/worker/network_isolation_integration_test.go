package worker

// Real-container checks of hardened scan network isolation on Docker Desktop.
// Each check pairs an isolated probe with a positive control run on the default
// network against the same controlled destination, so an unreachable
// destination can never be mistaken for working isolation. Build the probe
// image (curl, dig, nc and nslookup plus this branch's scrutineer binary) with:
//
//	GOOS=linux GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -o "$TMP/scrutineer" ./cmd/scrutineer
//	printf 'FROM alpine:3.22\nRUN apk add --no-cache curl bind-tools busybox-extras\nCOPY scrutineer /usr/local/bin/scrutineer\n' > "$TMP/Dockerfile"
//	docker build -t scrutineer-netprobe-test "$TMP"
//
// then run it with SCRUTINEER_TEST_NETWORK_ISOLATION_IMAGE=scrutineer-netprobe-test
// go test -race -run NetworkIsolation -v ./internal/worker/
//
// engine_isolation_integration_test.go runs the direct egress, operator route
// and cancellation checks on Docker Engine (host-proxy path), and podman
// isolation is covered by podman_integration_test.go. Cloud metadata has no
// positive control on Docker Desktop because there is no metadata service, so
// only the egress proxy refusing non-public addresses is checked.
// Gateway-addressed probes are likewise omitted here: on Docker Desktop a
// packet sent to a network's gateway never reaches a host service even without
// isolation, so such a probe could not fail. The Engine file carries them.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

const (
	isolationImageEnv    = "SCRUTINEER_TEST_NETWORK_ISOLATION_IMAGE"
	controlFailedMessage = "control failed: the destination is unreachable even without isolation, so isolation cannot be judged"
	listenerBindAttempts = 20
	listenerConnDeadline = 2 * time.Second
	listenerReadBuf      = 4096
	markerRandomBytes    = 6
	controlWait          = 5 * time.Second
	controlRunTimeout    = 90 * time.Second
	pollInterval         = 100 * time.Millisecond
	grace                = 2 * time.Second
	scanTimeout          = 5 * time.Minute
	siblingPort          = "9000"
	siblingIPWait        = 60 * time.Second
	siblingControlTries  = 3
)

type isolationHarness struct {
	stubHarness
	script string
}

func (isolationHarness) Binary() string              { return "sh" }
func (h isolationHarness) Args(harness.Job) []string { return []string{"-c", h.script} }

// controlledListener records every TCP payload and UDP datagram that reaches
// the host so tests can verify whether a probe arrived.
type controlledListener struct {
	tcp  net.Listener
	udp  net.PacketConn
	port string
	mu   sync.Mutex
	data []byte
}

func newControlledListener(t *testing.T) *controlledListener {
	t.Helper()
	for range listenerBindAttempts {
		tcp, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		_, port, err := net.SplitHostPort(tcp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp", "0.0.0.0:"+port)
		if err != nil {
			_ = tcp.Close()
			continue
		}
		l := &controlledListener{tcp: tcp, udp: udp, port: port}
		t.Cleanup(l.close)
		go l.serveTCP()
		go l.serveUDP()
		return l
	}
	t.Fatal("no port with both TCP and UDP free")
	return nil
}

func (l *controlledListener) close() {
	_ = l.tcp.Close()
	_ = l.udp.Close()
}

func (l *controlledListener) record(b []byte) {
	l.mu.Lock()
	l.data = append(l.data, b...)
	l.mu.Unlock()
}

func (l *controlledListener) serveTCP() {
	for {
		c, err := l.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			buf := make([]byte, listenerReadBuf)
			_ = c.SetReadDeadline(time.Now().Add(listenerConnDeadline))
			for {
				n, err := c.Read(buf)
				l.record(buf[:n])
				if err != nil {
					return
				}
			}
		}()
	}
}

func (l *controlledListener) serveUDP() {
	buf := make([]byte, listenerReadBuf)
	for {
		n, _, err := l.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		l.record(buf[:n])
	}
}

func (l *controlledListener) saw(marker string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Contains(l.data, []byte(marker))
}

func (l *controlledListener) waitSaw(marker string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if l.saw(marker) {
			return true
		}
		time.Sleep(pollInterval)
	}
	return l.saw(marker)
}

// newMarker returns a unique alphanumeric token usable in a payload or as a DNS label.
func newMarker(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, markerRandomBytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(prefix, "_", "") + hex.EncodeToString(b)
}

type isolationEnv struct {
	rt        ContainerRuntime
	image     string
	apiPort   string
	gatewayIP string
	api       *apiRecorder
	// proxyURL is the in-process host proxy scans use on runtimes without an
	// egress sidecar. Empty means the sidecar path.
	proxyURL string
}

// apiRecorder stands in for the host skill API and records the path and Host
// of every request that reaches it.
type apiRecorder struct {
	mu   sync.Mutex
	seen []apiRequest
}

type apiRequest struct{ path, host string }

func (a *apiRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.seen = append(a.seen, apiRequest{path: r.URL.Path, host: r.Host})
	a.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// hostsFor returns the Host of every recorded request whose path holds marker.
func (a *apiRecorder) hostsFor(marker string) []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var hosts []string
	for _, req := range a.seen {
		if strings.Contains(req.path, marker) {
			hosts = append(hosts, req.host)
		}
	}
	return hosts
}

func (a *apiRecorder) waitFor(marker string, d time.Duration) []string {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if hosts := a.hostsFor(marker); len(hosts) > 0 {
			return hosts
		}
		time.Sleep(pollInterval)
	}
	return a.hostsFor(marker)
}

func isolationSetup(t *testing.T) isolationEnv {
	t.Helper()
	image := os.Getenv(isolationImageEnv)
	if image == "" {
		t.Skipf("set %s to run the network isolation integration", isolationImageEnv)
	}
	rt, ok := container.DetectRuntime("docker")
	if !ok {
		t.Skip("docker is unavailable; podman isolation is covered by podman_integration_test.go")
	}
	if !rt.DockerDesktop {
		t.Skip("docker daemon is not Docker Desktop; Docker Engine is covered by engine_isolation_integration_test.go and podman by podman_integration_test.go")
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
	gatewayIP := ResolveHostGatewayIPv4(rt, image, "")
	if gatewayIP == "" {
		t.Fatal("host-gateway did not resolve on Docker Desktop")
	}
	return isolationEnv{rt: rt, image: image, apiPort: apiPort, gatewayIP: gatewayIP, api: recorder}
}

func (e isolationEnv) runner(script string) ContainerRunner {
	r := ContainerRunner{
		Image:    e.image,
		Harness:  isolationHarness{script: script},
		Hardened: true,
		Runtime:  e.rt,
	}
	if e.proxyURL != "" {
		r.ProxyURL = e.proxyURL
		return r
	}
	r.Egress = EgressSidecarConfig{
		Token:     NewProxyToken(),
		Allow:     []string{HostGatewayAlias},
		APIPort:   e.apiPort,
		GatewayIP: e.gatewayIP,
	}
	return r
}

func isolationKey(label string) string {
	return fmt.Sprintf("iso-%s-%d-%d", label, os.Getpid(), time.Now().UnixNano())
}

func (e isolationEnv) runScan(ctx context.Context, key, work, script string) error {
	return runIsolatedScan(ctx, e.runner(script), key, work)
}

func runIsolatedScan(ctx context.Context, r ContainerRunner, key, work string) error {
	_, err := r.RunSkill(ctx, SkillJob{
		IsolationKey: key,
		WorkRoot:     work,
		SrcReady:     true,
		Name:         "netprobe",
	}, func(Event) {})
	return err
}

// defaultNetworkRun runs a script in a container on the default network.
func (e isolationEnv) defaultNetworkRun(t *testing.T, script string, extra ...string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), controlRunTimeout)
	defer cancel()
	args := append([]string{"run", "--rm"}, extra...)
	if !e.rt.DockerDesktop {
		// Only Docker Desktop resolves the host alias without --add-host.
		args = append(args, "--add-host", HostGatewayAlias+":host-gateway")
	}
	args = append(args, "--entrypoint", "sh", e.image, "-c", script)
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Logf("docker %v: %v\n%s", args, err, out)
	}
	return err
}

const directProbeScript = `cd /work
NP="env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy"
rec() {
  name=$1; shift
  "$@" >"/work/$name.out" 2>"/work/$name.err"
  echo $? >"/work/$name.exit"
}
tcp() { echo "$2" | $NP nc -w 3 "$1" @PORT@; }
dnsq() { $NP dig +tries=1 +time=2 $3 @"$1" -p @PORT@ "$2.probe.test"; }
rec tcp_alias tcp host.docker.internal @tcp_alias@
rec udp_alias dnsq host.docker.internal @udp_alias@
rec dtcp_alias dnsq host.docker.internal @dtcp_alias@ +tcp
rec resolver $NP nslookup -timeout=3 -retry=1 example.com
ip -6 addr show scope global | grep -c inet6 > v6count
if [ "$(cat v6count)" != 0 ]; then
  rec v6 $NP curl -6 -sS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' https://[2606:4700:4700::1111]/
fi
rec meta_proxied curl -sS --max-time 10 -o /dev/null -w '%{http_code}' http://169.254.169.254/latest/meta-data/
rec host_proxied curl -sS --max-time 10 -o /dev/null -w '%{http_code}' http://host.docker.internal:@PORT@/@host_proxied@
rec connect_proxied curl -sS -p --max-time 10 -o /dev/null -w '%{http_connect}' https://host.docker.internal:@PORT@/@connect_proxied@
`

// markerProbeNames are the probes whose markers must never reach the listener.
var markerProbeNames = []string{"tcp_alias", "udp_alias", "dtcp_alias", "host_proxied", "connect_proxied"}

func directScript(port string, markers map[string]string) string {
	pairs := []string{"@PORT@", port}
	for name, m := range markers {
		pairs = append(pairs, "@"+name+"@", m)
	}
	return strings.NewReplacer(pairs...).Replace(directProbeScript)
}

// controls records which positive controls succeeded on the default network.
type controls map[string]bool

func runControls(t *testing.T, e isolationEnv, l *controlledListener) controls {
	t.Helper()
	ok := controls{}
	target := HostGatewayAlias
	for _, c := range []struct{ name, script, marker string }{
		{"tcp", "echo %s | nc -w 3 " + target + " " + l.port, "ctltcp"},
		{"dns_udp", "dig +tries=1 +time=2 @" + target + " -p " + l.port + " %s.probe.test", "ctludp"},
		{"dns_tcp", "dig +tcp +tries=1 +time=2 @" + target + " -p " + l.port + " %s.probe.test", "ctldtcp"},
	} {
		m := newMarker(t, c.marker)
		// dig exits non-zero without a reply, so only arrival at the listener counts.
		_ = e.defaultNetworkRun(t, fmt.Sprintf(c.script, m))
		ok[c.name] = l.waitSaw(m, controlWait)
	}
	ok["resolver"] = e.defaultNetworkRun(t, "nslookup -timeout=3 -retry=1 example.com") == nil
	return ok
}

func (c controls) require(t *testing.T, name string) {
	t.Helper()
	if !c[name] {
		t.Skip(controlFailedMessage)
	}
}

func TestIntegration_NetworkIsolationDirectEgress(t *testing.T) {
	assertDirectEgressIsolated(t, isolationSetup(t))
}

func assertDirectEgressIsolated(t *testing.T, env isolationEnv) {
	t.Helper()
	l := newControlledListener(t)
	ctl := runControls(t, env, l)

	markers := map[string]string{}
	for _, n := range markerProbeNames {
		markers[n] = newMarker(t, n)
	}
	work := newScanWorkspace(t)
	key := isolationKey("direct")
	ctx, cancel := context.WithTimeout(t.Context(), scanTimeout)
	defer cancel()
	if err := env.runScan(ctx, key, work, directScript(l.port, markers)); err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	time.Sleep(grace)
	files := readWorkspaceFiles(work)
	t.Logf("v6count=%s", files["v6count"])
	for _, n := range []string{"tcp_alias", "udp_alias", "dtcp_alias", "resolver", "v6", "meta_proxied", "host_proxied", "connect_proxied"} {
		t.Logf("%s: exit=%q out=%q err=%q", n, files[n+".exit"], files[n+".out"], files[n+".err"])
	}

	assertDirectBlocked(t, ctl, l, files, markers)
	assertProxyRefusals(t, l, files, markers)
	t.Run("ipv6", func(t *testing.T) { assertIPv6(t, env, files) })
	t.Run("cleanup", func(t *testing.T) { assertScanRemoved(t, key) })
}

func assertDirectBlocked(t *testing.T, ctl controls, l *controlledListener, files, markers map[string]string) {
	t.Helper()
	for _, p := range []struct{ name, control string }{
		{"tcp_alias", "tcp"},
		{"udp_alias", "dns_udp"},
		{"dtcp_alias", "dns_tcp"},
		{"resolver", "resolver"},
	} {
		t.Run("direct_"+p.name, func(t *testing.T) {
			ctl.require(t, p.control)
			exit := files[p.name+".exit"]
			if exit == "" || exit == "0" {
				t.Errorf("direct probe did not fail: exit=%q out=%q", exit, files[p.name+".out"])
			}
			if m, ok := markers[p.name]; ok && l.saw(m) {
				t.Errorf("marker %s reached the host listener", m)
			}
		})
	}
}

func assertProxyRefusals(t *testing.T, l *controlledListener, files, markers map[string]string) {
	t.Helper()
	t.Run("proxied_metadata", func(t *testing.T) {
		if got := files["meta_proxied.out"]; got != "403" {
			t.Errorf("metadata via proxy: code=%q exit=%q, want 403", got, files["meta_proxied.exit"])
		}
	})
	t.Run("proxied_host_service", func(t *testing.T) {
		if got := files["host_proxied.out"]; got != "403" {
			t.Errorf("host service via proxy: code=%q exit=%q, want 403", got, files["host_proxied.exit"])
		}
		if l.saw(markers["host_proxied"]) {
			t.Error("host service marker reached the listener through the proxy")
		}
	})
	t.Run("proxied_connect", func(t *testing.T) {
		// 403 is the proxy refusing the tunnel. 000 would mean the proxy was
		// unreachable, which proves nothing about isolation.
		if got := files["connect_proxied.out"]; got != "403" {
			t.Errorf("CONNECT to a host service via proxy: code=%q exit=%q, want 403", got, files["connect_proxied.exit"])
		}
		if l.saw(markers["connect_proxied"]) {
			t.Error("CONNECT marker reached the listener")
		}
	})
}

const ipv6ControlScript = "curl -6 -sS --max-time 5 -o /dev/null https://[2606:4700:4700::1111]/"

func assertIPv6(t *testing.T, env isolationEnv, files map[string]string) {
	t.Helper()
	if files["v6count"] == "" {
		t.Fatal("IPv6 address count was not recorded")
	}
	if files["v6count"] == "0" {
		t.Log("hardened scan network has no global IPv6 address")
		t.Skip("IPv6 unsupported on this runtime: the scan network has no global IPv6 address, so there is nothing to block")
	}
	if env.defaultNetworkRun(t, ipv6ControlScript) != nil {
		t.Skip(controlFailedMessage)
	}
	if exit := files["v6.exit"]; exit == "" || exit == "0" {
		t.Errorf("direct IPv6 connection succeeded: exit=%q code=%q", exit, files["v6.out"])
	}
}

const siblingAScript = `cd /work
(while true; do nc -l -p ` + siblingPort + ` >> /work/conns; done) &
sleep 1
ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n 1 > /work/ip.tmp
mv /work/ip.tmp /work/ip
i=0
while [ ! -f /work/done ] && [ "$i" -lt 120 ]; do sleep 1; i=$((i+1)); done
`

const siblingBScript = `cd /work
NP="env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy"
echo @DIRECT@ | $NP nc -w 3 @IP@ ` + siblingPort + ` >/work/direct.out 2>&1
echo $? >/work/direct.exit
curl -sS --max-time 10 -o /dev/null -w '%{http_code}' http://@IP@:` + siblingPort + `/@PROXIED@ >/work/proxied.out 2>/work/proxied.err
echo $? >/work/proxied.exit
`

func TestIntegration_NetworkIsolationSiblingScans(t *testing.T) {
	env := isolationSetup(t)
	ctx, cancel := context.WithTimeout(t.Context(), scanTimeout)
	defer cancel()

	workA := newScanWorkspace(t)
	keyA := isolationKey("siblinga")
	// Always release scan A so a failure cannot hang the test.
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(workA, "done"), nil, 0o600) })
	errA := make(chan error, 1)
	go func() { errA <- env.runScan(ctx, keyA, workA, siblingAScript) }()

	ipA := waitForSiblingIP(t, workA, errA)
	t.Logf("scan A address on its scan network: %s", ipA)

	control := newMarker(t, "ctlsibling")
	delivered := deliverSiblingControl(t, env, keyA, ipA, control)

	directMarker := newMarker(t, "bdirect")
	proxiedMarker := newMarker(t, "bproxied")
	workB := newScanWorkspace(t)
	script := strings.NewReplacer("@IP@", ipA, "@DIRECT@", directMarker, "@PROXIED@", proxiedMarker).Replace(siblingBScript)
	if err := env.runScan(ctx, isolationKey("siblingb"), workB, script); err != nil {
		t.Fatalf("scan B RunSkill: %v", err)
	}
	time.Sleep(grace)

	if err := os.WriteFile(filepath.Join(workA, "done"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-errA; err != nil {
		t.Fatalf("scan A RunSkill: %v", err)
	}
	conns := readWorkspaceFiles(workA)["conns"]
	filesB := readWorkspaceFiles(workB)
	t.Logf("scan B: direct exit=%q out=%q proxied exit=%q code=%q", filesB["direct.exit"], filesB["direct.out"], filesB["proxied.exit"], filesB["proxied.out"])

	if !delivered || !strings.Contains(conns, control) {
		t.Skip(controlFailedMessage)
	}
	if strings.Contains(conns, directMarker) || strings.Contains(conns, proxiedMarker) {
		t.Errorf("scan A received traffic from scan B: %q", conns)
	}
	if exit := filesB["direct.exit"]; exit == "" || exit == "0" {
		t.Errorf("scan B direct connection to scan A did not fail: exit=%q", exit)
	}
	if got := filesB["proxied.out"]; got != "403" {
		t.Errorf("scan B proxied request to scan A: code=%q, want 403", got)
	}
}

func waitForSiblingIP(t *testing.T, work string, errA chan error) string {
	t.Helper()
	deadline := time.Now().Add(siblingIPWait)
	for time.Now().Before(deadline) {
		select {
		case err := <-errA:
			t.Fatalf("scan A ended before publishing its address: %v", err)
		default:
		}
		if b, err := os.ReadFile(filepath.Join(work, "ip")); err == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimSpace(string(b))
		}
		time.Sleep(pollInterval)
	}
	t.Fatal("scan A did not publish its address")
	return ""
}

// deliverSiblingControl connects from a container on scan A's own network; the
// listener restarts between connections so a few attempts are made.
func deliverSiblingControl(t *testing.T, env isolationEnv, keyA, ipA, marker string) bool {
	t.Helper()
	script := "echo " + marker + " | nc -w 3 " + ipA + " " + siblingPort
	for range siblingControlTries {
		if env.defaultNetworkRun(t, script, "--network", hardenedNetworkName(keyA)) == nil {
			return true
		}
		time.Sleep(time.Second)
	}
	return false
}
