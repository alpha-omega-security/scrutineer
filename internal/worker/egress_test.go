package worker

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHardenedEgressAllow_minimalSurface(t *testing.T) {
	// HardenedEgressAllow is harness-neutral: it must allow only the
	// host skill API. The harness's own model-API hosts (e.g.
	// *.anthropic.com for claude) are layered on at startup, so they
	// must NOT appear in the static list -- a non-claude harness would
	// otherwise inherit anthropic by accident. Adding a new entry here
	// is a deliberate widening of the hardened surface and should not
	// happen accidentally.
	allow := HardenedEgressAllow
	if !HostAllowed(allow, HostGatewayAlias) {
		t.Errorf("hardened blocked %s", HostGatewayAlias)
	}
	if HostAllowed(allow, "api.anthropic.com") {
		t.Errorf("hardened static list still contains anthropic; that belongs in ClaudeHarness.EgressHosts")
	}
	for _, host := range []string{
		"packages.ecosyste.ms",
		"github.com",
		"registry.npmjs.org",
		"pypi.org",
		"osv.dev",
	} {
		if HostAllowed(allow, host) {
			t.Errorf("hardened allowed %s, must not", host)
		}
	}
}

func TestHostAllowed(t *testing.T) {
	allow := []string{
		"api.anthropic.com",
		"*.ecosyste.ms",
		"GitHub.com",
		HostGatewayAlias,
	}
	cases := []struct {
		host string
		want bool
	}{
		{"api.anthropic.com", true},
		{"API.Anthropic.com", true},
		{"anthropic.com", false},
		{"packages.ecosyste.ms", true},
		{"repos.ecosyste.ms", true},
		{"ecosyste.ms", false},
		{"evil.ecosyste.ms.attacker.net", false},
		{"github.com", true},
		{"gist.github.com", false},
		{"host.docker.internal", true},
		{"example.org", false},
	}
	for _, tc := range cases {
		if got := HostAllowed(allow, tc.host); got != tc.want {
			t.Errorf("HostAllowed(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestSplitTargetDefaultsPort(t *testing.T) {
	h, p := splitTarget("example.com")
	if h != "example.com" || p != "443" {
		t.Errorf("got %q %q", h, p)
	}
	h, p = splitTarget("example.com:8443")
	if h != "example.com" || p != "8443" {
		t.Errorf("got %q %q", h, p)
	}
}

func TestDialTargetRewritesGatewayAlias(t *testing.T) {
	// The in-process host proxy (GatewayDialHost unset) rewrites the alias to
	// 127.0.0.1, which is the host's own loopback where the web server listens.
	host := &EgressProxy{}
	if got := host.dialTarget(HostGatewayAlias, "8080"); got != "127.0.0.1:8080" {
		t.Errorf("got %q", got)
	}
	if got := host.dialTarget("Host.Docker.Internal", "9090"); got != "127.0.0.1:9090" {
		t.Errorf("case-insensitive rewrite failed: %q", got)
	}
	if got := host.dialTarget("api.anthropic.com", "443"); got != "api.anthropic.com:443" {
		t.Errorf("got %q", got)
	}
}

func TestEgressProxyDialTargetRewritesAPIHosts(t *testing.T) {
	p := &EgressProxy{}
	if got := p.dialTarget(HostGatewayAlias, "8080"); got != "127.0.0.1:8080" {
		t.Errorf("got %q", got)
	}
	if got := p.dialTarget("Host.Docker.Internal", "9090"); got != "127.0.0.1:9090" {
		t.Errorf("case-insensitive rewrite failed: %q", got)
	}

	p = &EgressProxy{APIHosts: []string{"192.168.64.1"}}
	if got := p.dialTarget("192.168.64.1", "8080"); got != "127.0.0.1:8080" {
		t.Errorf("custom API host rewrite failed: %q", got)
	}
	if got := p.dialTarget("api.anthropic.com", "443"); got != "api.anthropic.com:443" {
		t.Errorf("got %q", got)
	}
}

func TestDialTargetSidecarUsesGatewayDialHost(t *testing.T) {
	// The sidecar cannot use 127.0.0.1 -- that is its own loopback, not the
	// host's -- so it sets GatewayDialHost to the egress-network host-gateway
	// IPv4 and the alias resolves there instead.
	side := &EgressProxy{GatewayDialHost: "192.0.2.7"}
	if got := side.dialTarget(HostGatewayAlias, "8080"); got != "192.0.2.7:8080" {
		t.Errorf("sidecar alias rewrite: got %q, want 192.0.2.7:8080", got)
	}
	// Non-alias hosts are unaffected by GatewayDialHost.
	if got := side.dialTarget("api.anthropic.com", "443"); got != "api.anthropic.com:443" {
		t.Errorf("non-alias host must dial as-is: got %q", got)
	}
}

func TestEgressProxy_RequiresAuth(t *testing.T) {
	p := &EgressProxy{Allow: []string{"example.com"}, Token: "sekrit", Log: quietLog()}
	r := httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("no auth: got %d, want 407", w.Code)
	}

	r = httptest.NewRequest(http.MethodConnect, "example.com:443", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("x:wrong")))
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("wrong token: got %d, want 407", w.Code)
	}
}

func TestEgressProxy_ForwardDenied(t *testing.T) {
	p := &EgressProxy{Allow: []string{"allowed.test"}, Log: quietLog()}
	r := httptest.NewRequest("GET", "http://denied.test/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
}

func TestEgressProxy_ForwardAllowedRewritesGateway(t *testing.T) {
	// Upstream stands in for the local scrutineer API on 127.0.0.1.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	}))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	p := &EgressProxy{Allow: []string{HostGatewayAlias}, Log: quietLog()}
	target := "http://" + net.JoinHostPort(HostGatewayAlias, port) + "/api/ping"
	r := httptest.NewRequest("GET", target, nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if w.Header().Get("X-Upstream") != "yes" {
		t.Errorf("upstream header not copied through")
	}
	if !strings.Contains(w.Body.String(), "/api/ping") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestEgressProxy_SidecarForwardDialsGatewayHost(t *testing.T) {
	// In sidecar mode the proxy reaches the host skill API not on its own
	// loopback but at GatewayDialHost (the egress-network host-gateway IPv4).
	// Stand the upstream up on 127.0.0.1 and point GatewayDialHost at it to
	// prove the alias is rewritten to GatewayDialHost rather than hard-coded.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "sidecar "+r.URL.Path)
	}))
	defer upstream.Close()
	host, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	p := &EgressProxy{Allow: []string{HostGatewayAlias}, GatewayDialHost: host, Log: quietLog()}
	target := "http://" + net.JoinHostPort(HostGatewayAlias, port) + "/api/ping"
	r := httptest.NewRequest("GET", target, nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "/api/ping") {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestEgressProxy_ForwardAllowedRewritesCustomAPIHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "yes")
		_, _ = io.WriteString(w, "hello "+r.URL.Path)
	}))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	const apiHost = "192.168.64.1"
	p := &EgressProxy{Allow: []string{apiHost}, APIHosts: []string{apiHost}, Log: quietLog()}
	target := "http://" + net.JoinHostPort(apiHost, port) + "/api/ping"
	r := httptest.NewRequest("GET", target, nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if w.Header().Get("X-Upstream") != "yes" {
		t.Errorf("upstream header not copied through")
	}
}

func TestWaitHostAPIReachable_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Any status proves a server answered -- pick a non-200 to make the
		// point that the status is irrelevant to reachability.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := WaitHostAPIReachable(ctx, host, port); err != nil {
		t.Fatalf("reachable server reported unreachable: %v", err)
	}
}

func TestServeEgressProxy(t *testing.T) {
	// Grab a free port, then hand it to ServeEgressProxy and confirm it actually
	// listens and serves the EgressProxy handler: a bare request gets 407 because
	// the proxy requires Proxy-Authorization.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	p := &EgressProxy{Allow: []string{"example.com"}, Token: "tok", Log: quietLog()}
	go func() { _ = ServeEgressProxy(p, addr) }() // no graceful stop; dies with the test binary

	client := &http.Client{Timeout: time.Second}
	var resp *http.Response
	for range 100 {
		if resp, err = client.Get("http://" + addr + "/"); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("ServeEgressProxy never came up on %s: %v", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("ServeEgressProxy handler not wired: got %d, want 407", resp.StatusCode)
	}
}

func TestDNSCandidates(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{HostGatewayAlias}, nil},                        // only the host alias: nothing upstream
		{[]string{"Host.Docker.Internal"}, nil},                  // case-insensitive drop
		{[]string{"*.anthropic.com"}, []string{"anthropic.com"}}, // wildcard -> parent
		{[]string{"github.com"}, []string{"github.com"}},         // apex as-is
		{[]string{"*.anthropic.com", HostGatewayAlias, "OSV.dev"}, // mix; lowercased
			[]string{"anthropic.com", "osv.dev"}},
	}
	for _, c := range cases {
		if got := dnsCandidates(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("dnsCandidates(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestVerifyUpstreamDNS(t *testing.T) {
	resolves := func(context.Context, string) ([]string, error) { return []string{"1.2.3.4"}, nil }
	nxdomain := func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	unreachable := func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "connection refused", IsTemporary: true}
	}
	mustNotCall := func(context.Context, string) ([]string, error) {
		t.Helper()
		t.Fatal("lookup should not be called when there are no candidates")
		return nil, nil
	}
	ctx := context.Background()

	// No upstreams to prove (only the host alias) -> pass without looking up.
	if err := verifyUpstreamDNS(ctx, []string{HostGatewayAlias}, mustNotCall); err != nil {
		t.Errorf("no-candidate case: %v", err)
	}
	// A name that resolves -> the resolver works.
	if err := verifyUpstreamDNS(ctx, []string{"*.anthropic.com"}, resolves); err != nil {
		t.Errorf("resolves case: %v", err)
	}
	// Every candidate NXDOMAINs -> a resolver that answers but can't forward
	// externally (e.g. an --internal aardvark); fail closed (it would 502 mid-scan).
	if err := verifyUpstreamDNS(ctx, []string{"*.anthropic.com"}, nxdomain); err == nil {
		t.Error("all-NXDOMAIN must fail closed (non-forwarding resolver)")
	}
	// NXDOMAIN on one candidate but a real resolution on another -> pass.
	nxCalls := 0
	nxThenResolve := func(c context.Context, h string) ([]string, error) {
		nxCalls++
		if nxCalls == 1 {
			return nxdomain(c, h)
		}
		return resolves(c, h)
	}
	if err := verifyUpstreamDNS(ctx, []string{"*.anthropic.com", "osv.dev"}, nxThenResolve); err != nil {
		t.Errorf("a real resolution after an NXDOMAIN should pass: %v", err)
	}
	// Every candidate hits an unreachable resolver -> fail closed.
	if err := verifyUpstreamDNS(ctx, []string{"*.anthropic.com", "osv.dev"}, unreachable); err == nil {
		t.Error("expected a fail-closed error when the resolver is unreachable")
	}
	// First unreachable, second resolves -> pass (tries them all).
	calls := 0
	firstFailsThenResolves := func(c context.Context, h string) ([]string, error) {
		calls++
		if calls == 1 {
			return unreachable(c, h)
		}
		return resolves(c, h)
	}
	if err := verifyUpstreamDNS(ctx, []string{"*.anthropic.com", "osv.dev"}, firstFailsThenResolves); err != nil {
		t.Errorf("should pass when a later candidate resolves: %v", err)
	}
}

func TestWaitHostAPIReachable_FailsClosed(t *testing.T) {
	// Bind then immediately release a port so the address is guaranteed to
	// refuse: the probe must fail closed within the context deadline rather
	// than hang or report success.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := WaitHostAPIReachable(ctx, host, port); err == nil {
		t.Fatal("expected an unreachable error, got nil")
	}
}

// TestEgressProxy_ConnectEndToEnd exercises the full path the container
// runner uses: a real listener, Proxy-Authorization in the proxy URL,
// CONNECT tunnel, then a TLS request over it. The upstream is a local
// httptest TLS server allowlisted as 127.0.0.1.
func TestEgressProxy_ConnectEndToEnd(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "tunnelled")
	}))
	defer upstream.Close()

	token := "tok"
	p := &EgressProxy{Allow: []string{"127.0.0.1"}, Token: token, Log: quietLog()}
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	pu, _ := url.Parse(proxySrv.URL)
	pu.User = url.UserPassword("scrutineer", token)
	tr := &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("get via proxy: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "tunnelled" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}

	// And a host not on the allowlist must be refused at CONNECT time.
	// Drop the pooled tunnel from the allowed request first so the
	// transport actually re-CONNECTs.
	tr.CloseIdleConnections()
	p.Allow = []string{"somewhere.else"}
	_, err = client.Get(upstream.URL)
	if err == nil {
		t.Fatalf("expected CONNECT to be refused for non-allowlisted host")
	}
}

func TestEgressProxy_DeniesGatewayOnWrongPort(t *testing.T) {
	p := &EgressProxy{
		Allow:   []string{HostGatewayAlias},
		APIPort: "8080",
		Log:     quietLog(),
	}

	// CONNECT to allowed port should work (as far as allowlist goes)
	r := httptest.NewRequest(http.MethodConnect, HostGatewayAlias+":8080", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	// Will fail with 502 (no upstream listener) but NOT 403
	if w.Code == http.StatusForbidden {
		t.Fatalf("CONNECT to API port should not be forbidden: %s", w.Body)
	}

	// CONNECT to a different port should be denied
	r = httptest.NewRequest(http.MethodConnect, HostGatewayAlias+":9090", nil)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("CONNECT to non-API port: got %d, want 403", w.Code)
	}

	// Forward (non-CONNECT) to a different port should also be denied
	r = httptest.NewRequest("GET", "http://"+HostGatewayAlias+":9090/secrets", nil)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("forward to non-API port: got %d, want 403", w.Code)
	}
}

func TestEgressProxy_NoPortRestrictionForOtherHosts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	p := &EgressProxy{
		Allow:   []string{"127.0.0.1"},
		APIPort: "8080",
		Log:     quietLog(),
	}
	r := httptest.NewRequest("GET", "http://127.0.0.1:"+port+"/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("non-gateway host on any port should be allowed: got %d", w.Code)
	}
}

func TestProxyURLForHostShape(t *testing.T) {
	got := ProxyURLForHost("abc", HostGatewayAlias, 1234)
	want := "http://scrutineer:abc@host.docker.internal:1234"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}

	got = ProxyURLForHost("abc", "192.168.64.1", 1234)
	want = "http://scrutineer:abc@192.168.64.1:1234"
	if got != want {
		t.Errorf("custom host got %q want %q", got, want)
	}
}

func TestProxyURLForEndpointShape(t *testing.T) {
	// The sidecar is addressed by container name on the --internal network.
	got := ProxyURLForEndpoint("abc", "scrutineer-proxy-7:3128")
	want := "http://scrutineer:abc@scrutineer-proxy-7:3128"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestDefaultEgressAllowCoversSkillHosts(t *testing.T) {
	// DefaultEgressAllow is harness-neutral; the model-API hosts come
	// from Harness.EgressHosts and are layered on at startup. This test
	// covers the static list only -- api.anthropic.com belonging in the
	// claude harness is asserted by TestClaudeHarness_binaryGuideEgress.
	for _, h := range []string{
		"packages.ecosyste.ms",
		"repos.ecosyste.ms",
		"advisories.ecosyste.ms",
		"commits.ecosyste.ms",
		"issues.ecosyste.ms",
		"github.com",
		"gitlab.com",
		"registry.npmjs.org",
		"api.npmjs.org",
		"www.npmjs.com",
		"pypi.org",
		"pypistats.org",
		"rubygems.org",
		"crates.io",
		"pkg.go.dev",
		"packagist.org",
		"hex.pm",
		"api.nuget.org",
		"www.nuget.org",
		"repo.maven.apache.org",
		"central.sonatype.com",
		"anaconda.org",
		"trunk.cocoapods.org",
		"metacpan.org",
		"cpan.metacpan.org",
		"www.cpan.org",
		"cran.r-project.org",
		"formulae.brew.sh",
		"pub.dev",
		"center.conan.io",
		"semgrep.dev",
		HostGatewayAlias,
	} {
		if !HostAllowed(DefaultEgressAllow, h) {
			t.Errorf("default allowlist missing %q", h)
		}
	}
	if HostAllowed(DefaultEgressAllow, "evil.example.net") {
		t.Errorf("default allowlist should not match arbitrary hosts")
	}
}

func TestFirstIfaceIPv4(t *testing.T) {
	ipv4 := func(s string) net.Addr { return &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(24, 32)} }
	ipv6 := func(s string) net.Addr { return &net.IPNet{IP: net.ParseIP(s), Mask: net.CIDRMask(64, 128)} }
	lo := ifaceAddrs{flags: net.FlagUp | net.FlagLoopback, addrs: []net.Addr{ipv4("127.0.0.1")}}

	cases := []struct {
		name    string
		ifaces  []ifaceAddrs
		want    string
		wantErr bool
	}{
		{"internal leg only", []ifaceAddrs{lo,
			{flags: net.FlagUp, addrs: []net.Addr{ipv4("10.89.1.2")}},
		}, "10.89.1.2", false},
		// The egress leg may already be connected by the time the sidecar
		// enumerates; the run-time leg has the lower index and must still win.
		{"egress leg already connected", []ifaceAddrs{lo,
			{flags: net.FlagUp, addrs: []net.Addr{ipv4("10.89.1.2")}},
			{flags: net.FlagUp, addrs: []net.Addr{ipv4("10.88.0.7")}},
		}, "10.89.1.2", false},
		{"down interface skipped", []ifaceAddrs{lo,
			{flags: 0, addrs: []net.Addr{ipv4("10.89.1.2")}},
			{flags: net.FlagUp, addrs: []net.Addr{ipv4("10.88.0.7")}},
		}, "10.88.0.7", false},
		{"ipv6 listed before ipv4 on the same interface", []ifaceAddrs{lo,
			{flags: net.FlagUp, addrs: []net.Addr{ipv6("fd00::2"), ipv4("10.89.1.2")}},
		}, "10.89.1.2", false},
		{"loopback only", []ifaceAddrs{lo}, "", true},
		{"no interfaces", nil, "", true},
		// Falling through to a later interface would bind the egress leg and
		// re-open the listener to the default bridge: fail closed instead.
		{"first candidate ipv6-only fails closed", []ifaceAddrs{lo,
			{flags: net.FlagUp, addrs: []net.Addr{ipv6("fd00::2")}},
			{flags: net.FlagUp, addrs: []net.Addr{ipv4("10.88.0.7")}},
		}, "", true},
	}
	for _, c := range cases {
		got, err := firstIfaceIPv4(c.ifaces)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected an error, got %q", c.name, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: firstIfaceIPv4 = %q, %v, want %q", c.name, got, err, c.want)
		}
	}
}
