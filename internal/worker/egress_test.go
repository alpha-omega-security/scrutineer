package worker

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
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
	if got := dialTarget(HostGatewayAlias, "8080"); got != "127.0.0.1:8080" {
		t.Errorf("got %q", got)
	}
	if got := dialTarget("Host.Docker.Internal", "9090"); got != "127.0.0.1:9090" {
		t.Errorf("case-insensitive rewrite failed: %q", got)
	}
	if got := dialTarget("api.anthropic.com", "443"); got != "api.anthropic.com:443" {
		t.Errorf("got %q", got)
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

// TestEgressProxy_ConnectEndToEnd exercises the full path the docker
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

func TestProxyURLShape(t *testing.T) {
	got := ProxyURL("abc", 1234)
	want := "http://scrutineer:abc@host.docker.internal:1234"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestDefaultEgressAllowCoversSkillHosts(t *testing.T) {
	for _, h := range []string{
		"api.anthropic.com",
		"packages.ecosyste.ms",
		"repos.ecosyste.ms",
		"advisories.ecosyste.ms",
		"commits.ecosyste.ms",
		"issues.ecosyste.ms",
		"github.com",
		"gitlab.com",
		"registry.npmjs.org",
		"pypi.org",
		"rubygems.org",
		"crates.io",
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
