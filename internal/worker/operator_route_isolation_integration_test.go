package worker

// Real-container checks that a hardened scan cannot reach the host-only
// operator routes (/api/v1/*) that share a listener with the skill API. Scan
// code reaches the skill API through the egress sidecar as inspected HTTP, so
// these probes try to make the API server see a loopback Host: a forged Host
// header, an absolute target naming loopback or the gateway, a CONNECT tunnel
// carrying its own Host and a raw request that skips the proxy.
//
// The positive control is a proxied request from the same scan that does reach
// the API stand-in, so a broken proxy path can never pass for isolation. The
// raw request has its own control from a container on the default network. Run
// with the probe image described in network_isolation_integration_test.go:
//
//	SCRUTINEER_TEST_NETWORK_ISOLATION_IMAGE=scrutineer-netprobe-test go test -race -run OperatorRoute -v ./internal/worker/

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

const operatorRouteScript = `cd /work
NP="env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy"
rec() {
  name=$1; shift
  "$@" >"/work/$name.out" 2>"/work/$name.err"
  echo $? >"/work/$name.exit"
}
code() { curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$@"; }
tunnel() { curl -sS -p --max-time 10 -o /dev/null -w '%{http_connect}' "$@"; }
raw() { printf 'GET /api/v1/%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' "$1" | $NP nc -w 3 host.docker.internal @API@; }
rec forged_loopback code -H 'Host: 127.0.0.1' http://host.docker.internal:@API@/api/v1/@forged_loopback@
rec forged_localhost code -H 'Host: localhost:@API@' http://host.docker.internal:@API@/api/v1/@forged_localhost@
rec target_loopback code http://127.0.0.1:@API@/api/v1/@target_loopback@
rec target_localhost code http://localhost:@API@/api/v1/@target_localhost@
rec target_gateway code http://@GATEWAY@:@API@/api/v1/@target_gateway@
rec connect_api tunnel -H 'Host: 127.0.0.1' http://host.docker.internal:@API@/api/v1/@connect_api@
rec connect_api_case tunnel -H 'Host: 127.0.0.1' http://HOST.DOCKER.INTERNAL:@API@/api/v1/@connect_api_case@
rec connect_gateway tunnel -H 'Host: 127.0.0.1' http://@GATEWAY@:@API@/api/v1/@connect_gateway@
rec raw_api raw @raw_api@
`

// forgedHostProbes reach the API through the proxy with a forged Host header.
// The request must arrive, but never with the forged Host.
var forgedHostProbes = []string{"forged_loopback", "forged_localhost"}

// refusedProbes must be refused by the proxy with the code written to .out and
// never reach the API.
var refusedProbes = []string{"target_loopback", "target_localhost", "target_gateway", "connect_api", "connect_api_case", "connect_gateway"}

func operatorRouteMarkers(t *testing.T) map[string]string {
	t.Helper()
	markers := map[string]string{}
	for _, n := range append(append(append([]string{}, forgedHostProbes...), refusedProbes...), "raw_api") {
		markers[n] = newMarker(t, n)
	}
	return markers
}

func operatorRouteProbeScript(apiPort, gatewayIP string, markers map[string]string) string {
	pairs := []string{"@API@", apiPort, "@GATEWAY@", gatewayIP}
	for name, m := range markers {
		pairs = append(pairs, "@"+name+"@", m)
	}
	return strings.NewReplacer(pairs...).Replace(operatorRouteScript)
}

// isLoopbackHost reports whether a Host value names the loopback interface,
// which is what the operator routes' Host check accepts.
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func TestIntegration_OperatorRouteIsolation(t *testing.T) {
	env := isolationSetup(t)
	markers := operatorRouteMarkers(t)
	work := newScanWorkspace(t)
	key := isolationKey("operator")
	ctx, cancel := context.WithTimeout(t.Context(), scanTimeout)
	defer cancel()
	if err := env.runScan(ctx, key, work, operatorRouteProbeScript(env.apiPort, env.gatewayIP, markers)); err != nil {
		t.Fatalf("RunSkill: %v", err)
	}
	time.Sleep(grace)
	files := readWorkspaceFiles(work)
	for name := range markers {
		t.Logf("%s: exit=%q out=%q err=%q hosts=%q", name, files[name+".exit"], files[name+".out"], files[name+".err"], env.api.hostsFor(markers[name]))
	}

	reached := assertForgedHostsRewritten(t, env, files, markers)
	assertOperatorRefusals(t, env, files, markers, reached)
	t.Run("raw_api", func(t *testing.T) { assertRawAPIBlocked(t, env, files, markers) })
}

// assertForgedHostsRewritten reports whether any forged-Host request reached
// the API, which is the positive control for the refusals.
func assertForgedHostsRewritten(t *testing.T, env isolationEnv, files, markers map[string]string) bool {
	t.Helper()
	reached := false
	for _, name := range forgedHostProbes {
		t.Run(name, func(t *testing.T) {
			hosts := env.api.waitFor(markers[name], controlWait)
			if len(hosts) == 0 {
				t.Skipf("%s: the proxied request never reached the API stand-in (code=%q)", controlFailedMessage, files[name+".out"])
			}
			reached = true
			for _, host := range hosts {
				if isLoopbackHost(host) {
					t.Errorf("the API saw the forged loopback Host %q", host)
				}
			}
		})
	}
	return reached
}

func assertOperatorRefusals(t *testing.T, env isolationEnv, files, markers map[string]string, reached bool) {
	t.Helper()
	for _, name := range refusedProbes {
		t.Run(name, func(t *testing.T) {
			if !reached {
				t.Skip(controlFailedMessage)
			}
			// 403 is the proxy refusing the request. 000 would mean the proxy
			// was unreachable, which proves nothing about isolation.
			if got := files[name+".out"]; got != "403" {
				t.Errorf("code=%q exit=%q err=%q, want 403", got, files[name+".exit"], files[name+".err"])
			}
			if hosts := env.api.hostsFor(markers[name]); len(hosts) > 0 {
				t.Errorf("marker reached the API with Host %q", hosts)
			}
		})
	}
}

func assertRawAPIBlocked(t *testing.T, env isolationEnv, files, markers map[string]string) {
	t.Helper()
	control := newMarker(t, "ctlraw")
	script := "printf 'GET /api/v1/" + control + " HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 3 " + HostGatewayAlias + " " + env.apiPort
	_ = env.defaultNetworkRun(t, script)
	controlHosts := env.api.waitFor(control, controlWait)
	if len(controlHosts) == 0 {
		t.Skip(controlFailedMessage)
	}
	// The control sends Host: 127.0.0.1 straight to the API, so the stand-in
	// must record it as loopback. Otherwise the forged Host checks could never
	// fail.
	if !isLoopbackHost(controlHosts[0]) {
		t.Fatalf("control Host %q was not recorded as loopback", controlHosts[0])
	}
	if exit := files["raw_api.exit"]; exit == "" || exit == "0" {
		t.Errorf("raw request without the proxy did not fail: exit=%q out=%q", exit, files["raw_api.out"])
	}
	if hosts := env.api.hostsFor(markers["raw_api"]); len(hosts) > 0 {
		t.Errorf("raw request reached the API with Host %q", hosts)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1":                 true,
		"127.0.0.1:8080":            true,
		"127.1.2.3":                 true,
		"localhost":                 true,
		"LOCALHOST:8080":            true,
		"[::1]:8080":                true,
		"::1":                       true,
		"host.docker.internal:8080": false,
		"192.168.65.254:8080":       false,
		"":                          false,
	} {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}
