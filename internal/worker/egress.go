package worker

import (
	"crypto/rand"
	"encoding/hex"
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

// HostGatewayAlias is the hostname containers use to reach the host. The
// proxy rewrites it to 127.0.0.1 when dialing so skills can call the
// scrutineer API even though the web server only listens on loopback.
const HostGatewayAlias = "host.docker.internal"

// DefaultEgressAllow is the built-in host allowlist for the docker
// runner's egress proxy. It covers what the bundled skills actually
// reach: the Anthropic API, ecosyste.ms services, the major code forges,
// the package registries those forges publish to, and the advisory
// sources the security skills consult. Entries are matched
// case-insensitively against the CONNECT/request host with the port
// stripped; a leading "*." matches any subdomain.
var DefaultEgressAllow = []string{
	// model
	"*.anthropic.com",

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

	// package registries
	"registry.npmjs.org",
	"pypi.org",
	"files.pythonhosted.org",
	"rubygems.org",
	"index.rubygems.org",
	"crates.io",
	"static.crates.io",
	"index.crates.io",
	"proxy.golang.org",
	"sum.golang.org",
	"pkg.go.dev",
	"packagist.org",
	"repo.packagist.org",
	"hex.pm",
	"repo.hex.pm",
	"api.nuget.org",

	// advisory / rule sources
	"semgrep.dev",
	"osv.dev",
	"api.osv.dev",
	"nvd.nist.gov",
	"services.nvd.nist.gov",
	"cwe.mitre.org",
}

// EgressProxy is a small forward proxy the docker runner points
// HTTPS_PROXY/HTTP_PROXY at. It only tunnels to hosts on Allow. Clients
// must present Token via Proxy-Authorization basic auth (any username);
// the proxy listens on all interfaces so the docker bridge can reach it,
// and the token stops it being an open relay on the LAN.
type EgressProxy struct {
	Allow []string
	Token string
	Log   *slog.Logger

	transport *http.Transport
	once      sync.Once
}

const (
	egressDialTimeout = 10 * time.Second
	egressCopyBuf     = 32 << 10
	egressIdlePerHost = 4
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
	upstream, err := net.DialTimeout("tcp", dialTarget(host, port), egressDialTimeout)
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
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Host = dialTarget(host, port)
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
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// NewProxyToken returns 32 hex chars of crypto/rand for Proxy-Authorization.
func NewProxyToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ProxyURL builds the http_proxy-style URL for containers.
func ProxyURL(token string, port int) string {
	return fmt.Sprintf("http://scrutineer:%s@%s:%d", token, HostGatewayAlias, port)
}

func splitTarget(hostport string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return hostport, "443"
}

func dialTarget(host, port string) string {
	if strings.EqualFold(host, HostGatewayAlias) {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
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
