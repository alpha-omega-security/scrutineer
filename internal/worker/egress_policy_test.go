package worker

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"scrutineer/internal/egressgrant"
)

func proxyAuth(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("scrutineer:"+token))
}

func TestEgressPortGuard(t *testing.T) {
	const token = "tok"
	grants, err := egressgrant.Parse([]string{"api.ecosyste.ms:443", "*.example.com:443", "*.example.com:8443", "plain.test:80"})
	if err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	reached := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; w.WriteHeader(http.StatusTeapot) })
	guard := egressPortGuard(token, []string{"*.anthropic.com"}, grants, log, next)

	connect := func(target string, auth bool) *http.Request {
		r := httptest.NewRequest(http.MethodConnect, "http://"+target, nil)
		r.Host = target
		if auth {
			r.Header.Set("Proxy-Authorization", proxyAuth(token))
		}
		return r
	}
	forward := func(rawURL string, auth bool) *http.Request {
		r := httptest.NewRequest(http.MethodGet, rawURL, nil)
		if auth {
			r.Header.Set("Proxy-Authorization", proxyAuth(token))
		}
		return r
	}
	relative := httptest.NewRequest(http.MethodGet, "/x", nil)
	relative.URL.Host = ""

	for _, tc := range []struct {
		name      string
		req       *http.Request
		wantCode  int
		wantReach bool
	}{
		{"base host any port", connect("api.anthropic.com:9999", true), http.StatusTeapot, true},
		{"granted host granted port", connect("api.ecosyste.ms:443", true), http.StatusTeapot, true},
		{"granted host default port", connect("api.ecosyste.ms", true), http.StatusTeapot, true},
		{"wildcard second port", connect("x.example.com:8443", true), http.StatusTeapot, true},
		{"granted host other port", connect("api.ecosyste.ms:8443", true), http.StatusForbidden, false},
		{"wildcard other port", connect("x.example.com:22", true), http.StatusForbidden, false},
		{"missing auth on denied port", connect("api.ecosyste.ms:22", false), http.StatusProxyAuthRequired, false},
		{"wrong auth on denied port", func() *http.Request {
			r := connect("api.ecosyste.ms:22", false)
			r.Header.Set("Proxy-Authorization", proxyAuth("wrong"))
			return r
		}(), http.StatusProxyAuthRequired, false},
		{"ungranted host falls through", connect("evil.test:22", true), http.StatusTeapot, true},
		{"forward without port is checked as 443", forward("http://api.ecosyste.ms/x", true), http.StatusTeapot, true},
		{"forward without port on an 80-only grant denied", forward("http://plain.test/x", true), http.StatusForbidden, false},
		{"forward explicit 80 on an 80-only grant allowed", forward("http://plain.test:80/x", true), http.StatusTeapot, true},
		{"forward explicit granted port", forward("http://x.example.com:8443/x", true), http.StatusTeapot, true},
		{"relative request falls through", relative, http.StatusTeapot, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := reached
			rec := httptest.NewRecorder()
			guard.ServeHTTP(rec, tc.req)
			if rec.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			if got := reached > before; got != tc.wantReach {
				t.Errorf("reached next = %v, want %v", got, tc.wantReach)
			}
			if tc.wantCode == http.StatusProxyAuthRequired && rec.Header().Get("Proxy-Authenticate") == "" {
				t.Error("407 lacks Proxy-Authenticate")
			}
		})
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "port not granted by egress policy") || !strings.Contains(logged, "port=8443") {
		t.Errorf("denial not logged as expected: %q", logged)
	}
}

// connectStatus sends an authenticated CONNECT to a proxy and returns the
// status code it answers with.
func connectStatus(t *testing.T, proxyAddr, target, token string) int {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: " + proxyAuth(token) + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestStartScopedEgressProxy_grants_listener(t *testing.T) {
	grants, err := egressgrant.Parse([]string{"granted.example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	p := &EgressProxy{Allow: []string{"base.example.com"}, Token: "tok", APIPort: "1", Log: slog.New(slog.DiscardHandler)}
	port, closeProxy, err := StartScopedEgressProxy(p, grants...)
	if err != nil {
		t.Fatal(err)
	}
	defer closeProxy()
	if len(p.Allow) != 1 {
		t.Errorf("caller's proxy Allow was mutated: %v", p.Allow)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if got := connectStatus(t, addr, "granted.example.com:8443", "tok"); got != http.StatusForbidden {
		t.Errorf("CONNECT to granted host on an undeclared port = %d, want 403", got)
	}
	if got := connectStatus(t, addr, "other.example.com:443", "tok"); got != http.StatusForbidden {
		t.Errorf("CONNECT to an unlisted host = %d, want 403", got)
	}
}

func TestStartScopedEgressProxy_grants_refusesAPIHosts(t *testing.T) {
	for _, tc := range []struct {
		grant    string
		apiHosts []string
	}{
		{"*.example.com:443", []string{"gw.example.com"}},
		{"gw.example.com:443", []string{"gw.example.com"}},
	} {
		grants, err := egressgrant.Parse([]string{tc.grant})
		if err != nil {
			t.Fatalf("%s: %v", tc.grant, err)
		}
		_, closeProxy, err := StartScopedEgressProxy(&EgressProxy{Token: "tok", APIHosts: tc.apiHosts, Allow: []string{"x.test"}}, grants...)
		if err == nil {
			closeProxy()
			t.Errorf("grant %s covering an API host was accepted", tc.grant)
		}
	}
	// The parser refuses the alias and any wildcard covering it, so config cannot know only the runtime API hosts.
	if _, err := egressgrant.Parse([]string{HostGatewayAlias + ":8080"}); err == nil {
		t.Error("parser accepted the host gateway alias")
	}
}

func TestGrantedProxy_noGrantsReturnsSameProxy(t *testing.T) {
	p := &EgressProxy{Allow: []string{"a.test"}, Token: "tok"}
	inner, err := grantedProxy(p, nil)
	if err != nil || inner != p {
		t.Errorf("grantedProxy with no grants = %p, %v, want the same proxy", inner, err)
	}
}

func policyTestRunner(hardened bool, policies map[string][]EgressGrant) ContainerRunner {
	return ContainerRunner{
		Hardened:       hardened,
		Runtime:        ContainerRuntime{Bin: "docker", Version: "24.0.7"},
		EgressPolicies: policies,
		ProviderProxy:  ScopedEgressProxyConfig{Allow: []string{"*.anthropic.com"}, APIPort: "8080", ContainerHost: "host.docker.internal"},
	}
}

func collectEvents() (func(Event), func() []Event) {
	var mu sync.Mutex
	var events []Event
	return func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() },
		func() []Event { mu.Lock(); defer mu.Unlock(); return slices.Clone(events) }
}

func TestApplyEgressPolicy_noPolicyIsUntouched(t *testing.T) {
	d := policyTestRunner(true, map[string][]EgressGrant{"other": {{Host: "a.example.com", Ports: []string{"443"}}}})
	d.ProxyURL = "http://x"
	emit, events := collectEvents()
	got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: "plain"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if !reflect.DeepEqual(got, d) || len(events()) != 0 {
		t.Errorf("skill without a policy changed the runner or emitted events: %+v %v", got, events())
	}
}

func TestApplyEgressPolicy_refusesWithoutHardened(t *testing.T) {
	d := policyTestRunner(false, map[string][]EgressGrant{"meta": {{Host: "a.example.com", Ports: []string{"443"}}}})
	emit, _ := collectEvents()
	_, _, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit)
	if err == nil || !strings.Contains(err.Error(), "requires --hardened") {
		t.Fatalf("err = %v, want a --hardened refusal", err)
	}
}

func TestApplyEgressPolicy_sidecarPath(t *testing.T) {
	grants := []EgressGrant{{Host: "a.example.com", Ports: []string{"443"}}}
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": grants})
	d.Runtime = ContainerRuntime{Bin: "docker", DockerDesktop: true, Version: "24.0.7"}
	emit, events := collectEvents()
	got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if !reflect.DeepEqual(got.Egress.Grants, grants) {
		t.Errorf("sidecar grants = %+v, want %+v", got.Egress.Grants, grants)
	}
	if len(d.Egress.Grants) != 0 {
		t.Error("shared runner config was mutated")
	}
	ev := events()
	if len(ev) != 1 || ev[0].Kind != KindEgress || ev[0].Text != "egress-policy: skill=meta grants=a.example.com:443" {
		t.Errorf("events = %+v", ev)
	}
}

func TestApplyEgressPolicy_hostProxyPath(t *testing.T) {
	grants, _ := egressgrant.Parse([]string{"a.example.com:443"})
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": grants})
	d.ProxyURL = "http://stable"
	emit, events := collectEvents()
	got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyURL == "" || got.ProxyURL == d.ProxyURL || !strings.Contains(got.ProxyURL, "host.docker.internal:") {
		t.Fatalf("ProxyURL = %q, want a new scoped proxy URL", got.ProxyURL)
	}
	// Drive a denial through the scoped proxy so the cleanup has one to emit.
	userinfo, hostport, _ := strings.Cut(strings.TrimPrefix(got.ProxyURL, "http://"), "@")
	_, pw, _ := strings.Cut(userinfo, ":")
	_, port, _ := strings.Cut(hostport, ":")
	if code := connectStatus(t, "127.0.0.1:"+port, "a.example.com:22", pw); code != http.StatusForbidden {
		t.Fatalf("proxy answered %d, want 403", code)
	}
	cleanup()
	var denial bool
	for _, e := range events() {
		if e.Kind == KindEgress && strings.HasPrefix(e.Text, "egress-proxy: ") && strings.Contains(e.Text, "port not granted") {
			denial = true
		}
	}
	if !denial {
		t.Errorf("cleanup did not emit the recorded denial: %+v", events())
	}
}

func TestApplyEgressPolicy_hostProxyNeedsContainerHost(t *testing.T) {
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": {{Host: "a.example.com", Ports: []string{"443"}}}})
	d.ProviderProxy.ContainerHost = ""
	emit, _ := collectEvents()
	if _, _, err := d.applyEgressPolicy(SkillJob{Name: "meta"}, emit); err == nil {
		t.Fatal("expected an error without a container host endpoint")
	}
}

func TestApplyEgressPolicy_concurrentSkillsStayIsolated(t *testing.T) {
	ga, _ := egressgrant.Parse([]string{"a.example.com:443"})
	gb, _ := egressgrant.Parse([]string{"b.example.com:8443"})
	d := policyTestRunner(true, map[string][]EgressGrant{"alpha": ga, "beta": gb})
	emit, _ := collectEvents()
	var wg sync.WaitGroup
	urls := make([]string, 2)
	for i, name := range []string{"alpha", "beta"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, cleanup, err := d.applyEgressPolicy(SkillJob{Name: name}, emit)
			if err != nil {
				t.Error(err)
				return
			}
			defer cleanup()
			urls[i] = got.ProxyURL
			time.Sleep(50 * time.Millisecond)
		}()
	}
	wg.Wait()
	if urls[0] == "" || urls[0] == urls[1] {
		t.Errorf("concurrent scans share a proxy: %v", urls)
	}
	if d.ProxyURL != "" {
		t.Error("shared runner ProxyURL was mutated")
	}
}

func TestPrepareExecution_providerAndPolicyShareOneProxy(t *testing.T) {
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": {{Host: "granted.example.com", Ports: []string{"443"}}}})
	d.Harness = OpencodeHarness{}
	d.Egress = EgressSidecarConfig{Allow: []string{"models.dev"}}
	d.OpencodeProviders = map[string]OpencodeProviderConfig{"groq": {EgressHosts: []string{"provider.invalid"}}}
	d.ProviderProxy.Allow = []string{"models.dev"}
	d.ProviderProxy.APIHosts = []string{HostGatewayAlias}
	d.ProxyURL = "http://original"

	provider, err := d.resolveOpencodeProvider("groq/model")
	if err != nil {
		t.Fatal(err)
	}
	mid, cleanupProvider, err := d.configureOpencodeProviderEgress(provider, true)
	if err != nil {
		t.Fatal(err)
	}
	cleanupProvider()
	if mid.ProxyURL != d.ProxyURL {
		t.Errorf("provider configuration started its own proxy: %q", mid.ProxyURL)
	}
	for _, allow := range [][]string{mid.Egress.Allow, mid.ProviderProxy.Allow} {
		if !slices.Contains(allow, "provider.invalid") {
			t.Errorf("provider host missing from %v", allow)
		}
	}

	emit, _ := collectEvents()
	got, _, _, cleanup, err := d.prepareExecution(t.Context(), SkillJob{Name: "meta", Model: "groq/model"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	pu, err := url.Parse(got.ProxyURL)
	if err != nil || got.ProxyURL == d.ProxyURL {
		t.Fatalf("scan proxy URL = %q, %v, want a new scoped proxy", got.ProxyURL, err)
	}
	token, _ := pu.User.Password()
	addr := "127.0.0.1:" + pu.Port()
	if code := connectStatus(t, addr, "provider.invalid:443", token); code == http.StatusForbidden {
		t.Errorf("provider host refused by the single scoped proxy: %d", code)
	}
	if code := connectStatus(t, addr, "granted.example.com:22", token); code != http.StatusForbidden {
		t.Errorf("granted host on an undeclared port = %d, want 403", code)
	}
	if code := connectStatus(t, addr, "other.invalid:443", token); code != http.StatusForbidden {
		t.Errorf("unlisted host = %d, want 403", code)
	}
}

// A scan can carry both an egress policy and a model proxy token. The single
// setup step must provide both. Its one cleanup must revoke the token then
// close the policy's scoped proxy.
func TestPrepareExecution_modelProxyAndPolicyTogether(t *testing.T) {
	grants, _ := egressgrant.Parse([]string{"a.example.com:443"})
	d := policyTestRunner(true, map[string][]EgressGrant{"meta": grants})
	d.ProxyURL = "http://stable"
	mp, err := NewModelProxy("", "real-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	d.ModelProxy = mp
	d.ModelProxyURL = "http://" + HostGatewayAlias + ":8080" + ModelProxyPathPrefix
	emit, _ := collectEvents()

	got, _, _, cleanup, err := d.prepareExecution(t.Context(), SkillJob{Name: "meta"}, emit)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyURL == d.ProxyURL || !strings.Contains(got.ProxyURL, HostGatewayAlias+":") {
		t.Fatalf("ProxyURL = %q, want the policy's scoped proxy", got.ProxyURL)
	}
	if got.modelProxyToken == "" {
		t.Fatal("no model proxy token issued alongside the egress policy")
	}
	req := httptest.NewRequest(http.MethodPost, ModelProxyPathPrefix+"/v1/messages", nil)
	req.Header.Set("X-Api-Key", got.modelProxyToken)
	if !mp.authorized(req) {
		t.Fatal("issued token is not accepted by the model proxy")
	}
	_, hostport, _ := strings.Cut(strings.TrimPrefix(got.ProxyURL, "http://"), "@")
	_, port, _ := strings.Cut(hostport, ":")

	cleanup()
	if mp.authorized(req) {
		t.Error("model proxy token still valid after cleanup")
	}
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second); err == nil {
		_ = conn.Close()
		t.Error("policy's scoped proxy still listening after cleanup")
	}
}
