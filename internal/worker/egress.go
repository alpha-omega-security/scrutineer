package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HostGatewayAlias is the hostname Docker/Podman containers use to reach the
// host. The proxy rewrites configured API hosts to 127.0.0.1 when dialing so
// skills can call the scrutineer API even though the web server only listens on
// loopback. Apple's container runtime uses a gateway IP instead of this alias;
// callers pass that host through EgressProxy.APIHosts.
const HostGatewayAlias = "host.docker.internal"

// HardenedEgressAllow is the strict harness-neutral allowlist used when
// --hardened is set. Only the host skill API (reached through
// host.docker.internal) is permitted; the harness's model-API hosts
// (Harness.EgressHosts) are appended at startup so the agent can talk to
// its provider, and anything else returns 403 at the proxy. Skills that
// need ecosyste.ms or a package registry must route through the host
// API, or the operator must drop hardened mode.
var HardenedEgressAllow = []string{
	HostGatewayAlias,
}

// DefaultEgressAllow is the built-in harness-neutral host allowlist for
// the container runner's egress proxy. It covers what the bundled skills
// actually reach: ecosyste.ms services, the major code forges, the
// package registries those forges publish to, and the advisory sources
// the security skills consult. The harness's model-API hosts
// (Harness.EgressHosts) are appended at startup. Entries are matched
// case-insensitively against the CONNECT/request host with the port
// stripped; a leading "*." matches any subdomain.
var DefaultEgressAllow = []string{
	// scrutineer skill API on the host
	HostGatewayAlias,

	// ecosyste.ms (packages, repos, advisories, commits, issues, ...)
	"*.ecosyste.ms",

	// forges
	"github.com",
	"api.github.com",
	"raw.githubusercontent.com",
	"objects.githubusercontent.com",
	"codeload.github.com",
	"gitlab.com",
	"codeberg.org",
	"bitbucket.org",

	// package registries — API, content, web, and stats endpoints for the
	// ecosystems packages.ecosyste.ms covers. Grouped so adding a new
	// registry stays a focused diff.
	// npm
	"registry.npmjs.org",
	"api.npmjs.org",
	"www.npmjs.com",
	// PyPI
	"pypi.org",
	"files.pythonhosted.org",
	"pypistats.org",
	// RubyGems
	"rubygems.org",
	"index.rubygems.org",
	// crates.io
	"crates.io",
	"static.crates.io",
	"index.crates.io",
	// Go
	"proxy.golang.org",
	"sum.golang.org",
	"pkg.go.dev",
	// Packagist (PHP)
	"packagist.org",
	"repo.packagist.org",
	// Hex (Elixir/Erlang)
	"hex.pm",
	"repo.hex.pm",
	// NuGet (.NET)
	"api.nuget.org",
	"www.nuget.org",
	// Maven Central (Java)
	"repo.maven.apache.org",
	"repo1.maven.org",
	"search.maven.org",
	"central.sonatype.com",
	// Conda
	"anaconda.org",
	"conda.anaconda.org",
	// CocoaPods (Swift / Objective-C)
	"cocoapods.org",
	"trunk.cocoapods.org",
	// CPAN (Perl) -- metacpan/fastapi for the index and API, www.cpan.org
	// and cpan.metacpan.org for the tarballs cpanm actually fetches.
	"metacpan.org",
	"fastapi.metacpan.org",
	"cpan.metacpan.org",
	"www.cpan.org",
	// CRAN (R)
	"cran.r-project.org",
	// Homebrew
	"formulae.brew.sh",
	// Pub (Dart / Flutter)
	"pub.dev",
	// Conan (C / C++)
	"conan.io",
	"center.conan.io",

	// advisory / rule sources
	"semgrep.dev",
	"osv.dev",
	"api.osv.dev",
	"nvd.nist.gov",
	"services.nvd.nist.gov",
	"cwe.mitre.org",
}

// EgressProxy is a small forward proxy the container runner points
// HTTPS_PROXY/HTTP_PROXY at. It only tunnels to hosts on Allow. Clients
// must present Token via Proxy-Authorization basic auth (any username);
// the proxy listens on all interfaces so the container can reach it on its
// gateway, and the token stops it being an open relay on the LAN.
type EgressProxy struct {
	Allow   []string
	Token   string
	APIPort string // only this port is allowed for APIHosts
	// APIHosts are hostnames/IPs that mean "the scrutineer host API" from
	// inside a scan container. They are restricted to APIPort and rewritten to
	// 127.0.0.1 when the proxy dials upstream. Empty keeps the Docker/Podman
	// default of HostGatewayAlias.
	APIHosts []string
	Log      *slog.Logger
	// GatewayDialHost overrides the address the proxy dials for the host skill
	// API (requests whose host is HostGatewayAlias). The in-process host proxy
	// leaves it "" and dials 127.0.0.1: it shares the host's loopback, so the
	// loopback-bound web server is reachable directly. The egress-proxy SIDECAR
	// runs in its own container, where 127.0.0.1 is the sidecar's own loopback,
	// not the host's; it sets this to the host-gateway IPv4 of its
	// egress network so the host API is reached across the namespace boundary.
	GatewayDialHost string

	transport *http.Transport
	once      sync.Once
}

const (
	egressDialTimeout      = 10 * time.Second
	egressCopyBuf          = 32 << 10
	egressIdlePerHost      = 4
	egressHostProbeBackoff = 500 * time.Millisecond
)

func (p *EgressProxy) init() {
	p.once.Do(func() {
		p.transport = &http.Transport{
			DialContext:         (&net.Dialer{Timeout: egressDialTimeout}).DialContext,
			ForceAttemptHTTP2:   false,
			MaxIdleConnsPerHost: egressIdlePerHost,
		}
	})
}

func (p *EgressProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.init()
	if !p.checkAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="scrutineer"`)
		http.Error(w, "proxy authorization required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveForward(w, r)
}

func (p *EgressProxy) checkAuth(r *http.Request) bool {
	if p.Token == "" {
		return true
	}
	const prefix = "Basic "
	h := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	_, pass, ok := decodeBasic(h[len(prefix):])
	return ok && pass == p.Token
}

func (p *EgressProxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitTarget(r.Host)
	if !HostAllowed(p.Allow, host) {
		p.Log.Warn("egress denied", "method", "CONNECT", "host", host)
		http.Error(w, "egress to "+host+" is not on the allowlist", http.StatusForbidden)
		return
	}
	if p.isAPIHost(host) && p.APIPort != "" && port != p.APIPort {
		p.Log.Warn("egress denied", "method", "CONNECT", "host", host, "port", port, "allowed_port", p.APIPort)
		http.Error(w, "egress to "+host+" is only allowed on port "+p.APIPort, http.StatusForbidden)
		return
	}
	upstream, err := net.DialTimeout("tcp", p.dialTarget(host, port), egressDialTimeout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	pipe(client, upstream)
}

func (p *EgressProxy) serveForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "absolute URI required", http.StatusBadRequest)
		return
	}
	host, port := splitTarget(r.URL.Host)
	if !HostAllowed(p.Allow, host) {
		p.Log.Warn("egress denied", "method", r.Method, "host", host)
		http.Error(w, "egress to "+host+" is not on the allowlist", http.StatusForbidden)
		return
	}
	if p.isAPIHost(host) && p.APIPort != "" && port != p.APIPort {
		p.Log.Warn("egress denied", "method", r.Method, "host", host, "port", port, "allowed_port", p.APIPort)
		http.Error(w, "egress to "+host+" is only allowed on port "+p.APIPort, http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Host = p.dialTarget(host, port)
	out.Header.Del("Proxy-Authorization")
	out.Header.Del("Proxy-Connection")
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	maps.Copy(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// HostAllowed reports whether host matches any entry in allow. Matching is
// case-insensitive on the bare hostname (port already stripped). An entry
// "*.example.com" matches any subdomain of example.com but not the apex;
// list the apex separately if needed.
func HostAllowed(allow []string, host string) bool {
	host = strings.ToLower(host)
	for _, a := range allow {
		a = strings.ToLower(a)
		if rest, ok := strings.CutPrefix(a, "*."); ok {
			if strings.HasSuffix(host, "."+rest) {
				return true
			}
			continue
		}
		if host == a {
			return true
		}
	}
	return false
}

// StartEgressProxy listens on all interfaces on an ephemeral port and
// serves p in a goroutine. It returns the chosen port. The caller embeds
// the port and p.Token into the proxy URL handed to containers.
func StartEgressProxy(p *EgressProxy) (int, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	srv := &http.Server{Handler: p, ReadHeaderTimeout: egressDialTimeout}
	// The proxy lives for the process lifetime: it is started once from
	// main.setupRunner (skipped under rootless --hardened, where the per-scan
	// sidecar replaces it) and every container talks through it. There is no
	// per-scan teardown, so no Shutdown wiring is needed; process exit
	// closes the listener.
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// NewProxyToken returns 32 hex chars of crypto/rand for Proxy-Authorization.
func NewProxyToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ProxyURLForHost builds the http_proxy-style URL for containers reaching the
// in-process host proxy. Docker/Podman pass HostGatewayAlias; Apple's
// container runtime passes the resolved gateway IP.
func ProxyURLForHost(token, host string, port int) string {
	return fmt.Sprintf("http://scrutineer:%s@%s:%d", token, host, port)
}

// ProxyURLForEndpoint builds the http_proxy-style URL for a proxy reachable at
// an arbitrary host:port. The egress proxy sidecar is addressed by its
// container name on the per-scan --internal network, so the scan points
// HTTPS_PROXY at the sidecar's name:port rather than the host-gateway alias.
func ProxyURLForEndpoint(token, endpoint string) string {
	return fmt.Sprintf("http://scrutineer:%s@%s", token, endpoint)
}

func splitTarget(hostport string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return hostport, "443"
}

func (p *EgressProxy) isAPIHost(host string) bool {
	for _, apiHost := range p.apiHosts() {
		if strings.EqualFold(host, apiHost) {
			return true
		}
	}
	return false
}

func (p *EgressProxy) apiHosts() []string {
	if len(p.APIHosts) > 0 {
		return p.APIHosts
	}
	return []string{HostGatewayAlias}
}

// dialTarget resolves a request's host:port to the address the proxy actually
// dials. A request to an API host (HostGatewayAlias by default) is rewritten to
// gatewayDialHost (127.0.0.1 for the in-process host proxy, the egress-network
// host-gateway IPv4 for the sidecar); every other host is dialed as given.
func (p *EgressProxy) dialTarget(host, port string) string {
	if p.isAPIHost(host) {
		host = p.gatewayDialHost()
	}
	return net.JoinHostPort(host, port)
}

// gatewayDialHost is the address HostGatewayAlias resolves to when dialing.
// "" (the host-proxy default) means 127.0.0.1, preserving the loopback rewrite
// that lets the in-process proxy reach the loopback-bound web server.
func (p *EgressProxy) gatewayDialHost() string {
	if p.GatewayDialHost != "" {
		return p.GatewayDialHost
	}
	return "127.0.0.1"
}

// ServeEgressProxy runs p on addr and blocks until the server stops. The egress
// proxy sidecar uses it to listen on a fixed port inside its container; the
// in-process host proxy uses StartEgressProxy instead (ephemeral port, returns
// immediately). Both share the handler and timeouts.
func ServeEgressProxy(p *EgressProxy, addr string) error {
	p.init()
	srv := &http.Server{Addr: addr, Handler: p, ReadHeaderTimeout: egressDialTimeout}
	return srv.ListenAndServe()
}

// SidecarListenFirstIface is the listen-host keyword that makes `scrutineer
// proxy` bind to the IPv4 of its first non-loopback interface instead of all
// interfaces. The container runner creates the sidecar attached only to the
// per-scan --internal network and connects the default (egress) bridge
// afterwards, so the first interface IS the internal leg -- binding there keeps
// the listener off the shared default bridge, where other containers of the
// same rootless user could otherwise probe it.
const SidecarListenFirstIface = "first-iface"

// ifaceAddrs is the slice of one interface's state firstIfaceIPv4 needs,
// decoupled from net.Interface so tests can fabricate interface layouts.
type ifaceAddrs struct {
	flags net.Flags
	addrs []net.Addr
}

// FirstIfaceIPv4 returns the IPv4 of the sidecar's first up, non-loopback
// interface. The sidecar always runs in a Linux container (rootless podman is
// the only sidecar runtime), where interface indexes grow with attachment
// order and net.Interfaces returns the netlink dump in index order -- so this
// is the leg the container was created with, the per-scan --internal network,
// even when the egress leg has already been connected by the time it runs.
func FirstIfaceIPv4() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	all := make([]ifaceAddrs, 0, len(ifs))
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			return "", fmt.Errorf("addresses of %s: %w", i.Name, err)
		}
		all = append(all, ifaceAddrs{flags: i.Flags, addrs: addrs})
	}
	return firstIfaceIPv4(all)
}

// firstIfaceIPv4 picks the IPv4 of the first up, non-loopback interface. It
// fails when that interface has no IPv4 rather than falling through to a later
// one: a later interface is the egress leg, and silently binding there would
// re-open the listener to the shared default bridge.
func firstIfaceIPv4(ifaces []ifaceAddrs) (string, error) {
	for _, i := range ifaces {
		if i.flags&net.FlagLoopback != 0 || i.flags&net.FlagUp == 0 {
			continue
		}
		for _, a := range i.addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					return ip4.String(), nil
				}
			}
		}
		return "", errors.New("first non-loopback interface has no IPv4 address")
	}
	return "", errors.New("no non-loopback interface is up")
}

// dnsCandidates reduces an egress allowlist to resolvable hostnames for the
// sidecar's DNS readiness check: it drops the host-gateway alias (which resolves
// via /etc/hosts, not real DNS, so it proves nothing about upstream resolution)
// and reduces each "*.example.com" wildcard to its parent "example.com".
func dnsCandidates(allow []string) []string {
	var out []string
	for _, a := range allow {
		if strings.EqualFold(a, HostGatewayAlias) {
			continue
		}
		host := strings.TrimPrefix(strings.ToLower(a), "*.")
		if host != "" {
			out = append(out, host)
		}
	}
	return out
}

// VerifyUpstreamDNS fails closed when the sidecar cannot resolve its allowlisted
// upstreams. Under rootless --hardened, upstream names (e.g. api.anthropic.com)
// are resolved by the sidecar CONTAINER, not the host, so a rootless netns whose
// resolver the host has but the container doesn't would let a scan start and then
// fail mid-run on the first model call. This turns that into a clear fail-closed
// startup refusal. It passes as soon as any candidate actually resolves; it fails
// closed when every candidate returns NXDOMAIN (a resolver that answers but cannot
// forward external lookups, e.g. an --internal network's aardvark) or the resolver
// is unreachable. A pure host-gateway allowlist has no upstreams to prove and passes.
func VerifyUpstreamDNS(ctx context.Context, allow []string) error {
	return verifyUpstreamDNS(ctx, allow, (&net.Resolver{}).LookupHost)
}

func verifyUpstreamDNS(ctx context.Context, allow []string, lookup func(context.Context, string) ([]string, error)) error {
	candidates := dnsCandidates(allow)
	if len(candidates) == 0 {
		return nil
	}
	var lastErr error
	nxdomain := 0
	for _, h := range candidates {
		_, err := lookup(ctx, h)
		if err == nil {
			return nil // actually resolved: the resolver forwards external lookups
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			nxdomain++ // NXDOMAIN: keep looking for a real resolution
		}
		lastErr = err
	}
	// Nothing resolved. NXDOMAIN for every candidate means the resolver answers
	// but cannot forward external lookups (e.g. an --internal network's aardvark),
	// which would let a scan start and then 502 on its first model call -- so fail
	// closed rather than treat "the resolver answered" as working DNS.
	if nxdomain == len(candidates) {
		return fmt.Errorf("sidecar resolver returned NXDOMAIN for every allowlisted upstream (%v); it cannot forward external DNS -- check the rootless network backend's DNS", candidates)
	}
	return fmt.Errorf("sidecar cannot reach a DNS resolver for any allowlisted upstream (tried %v): %w; check the rootless network backend's DNS", candidates, lastErr)
}

// WaitHostAPIReachable blocks until an HTTP request to host:port returns any
// response, or ctx is done (fail closed). The egress-proxy sidecar calls it
// before it starts listening: under rootless podman the sidecar reaches the
// host's loopback-bound skill API only if the network backend forwards
// host-gateway to the host loopback (pasta --map-host-loopback / slirp4netns
// host-loopback). Gating readiness on this probe makes an unsupported backend
// fail the scan closed -- the sidecar never accepts proxy traffic it could not
// forward to the host API -- rather than silently breaking every skill API call.
// Any HTTP status counts as reachable (even 401/404): the point is that a real
// server answered at all, not which status it chose. Redirects are not followed
// so an unreachable redirect target cannot mask a reachable server.
func WaitHostAPIReachable(ctx context.Context, host, port string) error {
	target := "http://" + net.JoinHostPort(host, port) + "/"
	client := &http.Client{
		Timeout:       egressDialTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("host skill API at %s unreachable: %w", net.JoinHostPort(host, port), lastErr)
		case <-time.After(egressHostProbeBackoff):
		}
	}
}

func pipe(a, b net.Conn) {
	done := make(chan struct{})
	cp := func(dst, src net.Conn) {
		buf := make([]byte, egressCopyBuf)
		_, _ = io.CopyBuffer(dst, src, buf)
		_ = dst.Close()
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

func decodeBasic(enc string) (user, pass string, ok bool) {
	r := &http.Request{Header: http.Header{"Authorization": {"Basic " + enc}}}
	return r.BasicAuth()
}
