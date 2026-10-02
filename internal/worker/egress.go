// This file re-exports github.com/alpha-omega-security/harness/egress under
// the names the rest of scrutineer already uses, so the swap is one file
// rather than forty call sites. The package-name prefix that would be
// redundant with the egress package (EgressProxy vs egress.Proxy) is kept
// here for now; a follow-up rename can drop it once the harness core PR has
// landed and the churn settles.
package worker

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/alpha-omega-security/harness/egress"
)

const (
	HostGatewayAlias        = egress.HostGatewayAlias
	SidecarListenFirstIface = egress.ListenFirstIface
	// ProxyCapabilityDenyAPIConnect is required by the host when a runner
	// image supplies the hardened egress sidecar binary. Older binaries do not
	// recognise the corresponding flag and therefore fail closed.
	ProxyCapabilityDenyAPIConnect = "deny-api-connect-v1"
	// ProxyCapabilityEgressPortGrants is required in addition when a scan
	// carries per-skill egress grants. A sidecar binary that predates the
	// grant gate rejects the unknown value and exits, which fails the scan
	// closed instead of running without the port restriction.
	ProxyCapabilityEgressPortGrants = "egress-port-grants-v1"
)

var (
	DefaultEgressAllow  = egress.DefaultAllow
	HardenedEgressAllow = egress.HardenedAllow
)

type EgressProxy = egress.Proxy

const egressProxyReadHeaderTimeout = 10 * time.Second

func NewProxyToken() string                               { return egress.NewToken() }
func ProxyURLForHost(token, host string, port int) string { return egress.ProxyURL(token, host, port) }
func ProxyURLForEndpoint(token, endpoint string) string   { return egress.EndpointURL(token, endpoint) }
func FirstIfaceIPv4() (string, error)                     { return egress.FirstIfaceIPv4() }

// StartEgressProxy starts the process-wide proxy used by ordinary container
// scans. Scrutineer owns the listener so every proxy shape shares the API
// CONNECT guard, including versions of harness that still allow that tunnel.
func StartEgressProxy(p *EgressProxy) (int, error) {
	if err := validateEgressProxy(p); err != nil {
		return 0, err
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	srv := newEgressProxyServer(p, "", p.Allow, nil)
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// ServeEgressProxy runs the fixed-address proxy used by hardened sidecars. The
// granted hosts, if any, are reachable only on their declared ports.
func ServeEgressProxy(p *EgressProxy, addr string, grants ...EgressGrant) error {
	if err := validateEgressProxy(p); err != nil {
		return err
	}
	inner, err := grantedProxy(p, grants)
	if err != nil {
		return err
	}
	srv := newEgressProxyServer(inner, addr, p.Allow, grants)
	return srv.ListenAndServe()
}

func WaitHostAPIReachable(ctx context.Context, host, port string) error {
	return egress.WaitHostAPIReachable(ctx, host, port)
}

func VerifyUpstreamDNS(ctx context.Context, allow []string) error {
	return egress.VerifyUpstreamDNS(ctx, allow)
}

func validateEgressProxy(p *EgressProxy) error {
	if p == nil {
		return errors.New("egress: proxy is required")
	}
	if p.Token == "" {
		return errors.New("egress: Token is required")
	}
	return nil
}

// newEgressProxyServer fronts the proxy with the port gate when there
// are grants. base is the allowlist that keeps its any-port behaviour; the
// proxy's own Allow already includes the granted hosts.
func newEgressProxyServer(p *EgressProxy, addr string, base []string, grants []EgressGrant) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           egressProxyHandler(p, base, grants),
		ReadHeaderTimeout: egressProxyReadHeaderTimeout,
	}
}

func egressProxyHandler(p *EgressProxy, base []string, grants []EgressGrant) http.Handler {
	guarded := apiConnectGuard(p)
	if len(grants) == 0 {
		return guarded
	}
	return egressPortGuard(p.Token, base, grants, p.Log, guarded)
}

// apiConnectGuard keeps the host skill API on the proxy's parsed HTTP path.
// A raw tunnel would let scan code choose a second Host header after the proxy
// has authorized and rewritten the outer destination, turning the proxy into a
// deputy for the host-only operator routes. HostPorts remain tunnelable because
// they are separate, explicit grants for host-local model services.
func apiConnectGuard(p *EgressProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			host, port := splitProxyTarget(r.Host)
			if port == p.APIPort && proxyAPIHost(p, host) {
				// Own authentication for this forbidden target instead of delegating
				// invalid credentials to harness. That keeps the denial fail-closed
				// if a future harness release changes what credentials it accepts.
				if !validProxyAuthorization(p.Token, r.Header.Get("Proxy-Authorization")) {
					w.Header().Set("Proxy-Authenticate", `Basic realm="harness"`)
					http.Error(w, "proxy authorization required", http.StatusProxyAuthRequired)
					return
				}
				if p.Log != nil {
					p.Log.Warn("egress denied", "method", http.MethodConnect, "host", host, "port", port,
						"reason", "host skill API requires inspected HTTP")
				}
				http.Error(w, "CONNECT to the host skill API is denied; use an HTTP proxy request", http.StatusForbidden)
				return
			}
		}
		if r.Method != http.MethodConnect && r.URL.IsAbs() {
			if host, _ := splitProxyTarget(r.URL.Host); proxyAPIHost(p, host) {
				w = newFlushingResponseWriter(w)
			}
		}
		p.ServeHTTP(w, r)
	})
}

// flushingResponseWriter flushes after every write. The harness proxy's
// forward path copies the upstream body with io.Copy and never flushes, so an
// SSE response from the host API (the -model-proxy route) would otherwise sit
// in the server's output buffer instead of streaming to the scan. It
// deliberately does not implement io.ReaderFrom: that would let io.Copy take
// the response's buffered ReadFrom path and skip the flushes.
type flushingResponseWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func newFlushingResponseWriter(w http.ResponseWriter) *flushingResponseWriter {
	return &flushingResponseWriter{w: w, rc: http.NewResponseController(w)}
}

func (f *flushingResponseWriter) Header() http.Header { return f.w.Header() }

func (f *flushingResponseWriter) WriteHeader(code int) {
	f.w.WriteHeader(code)
	_ = f.rc.Flush()
}

func (f *flushingResponseWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if err == nil {
		_ = f.rc.Flush()
	}
	return n, err
}

func validProxyAuthorization(token, header string) bool {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return false
	}
	_, password, ok := strings.Cut(string(decoded), ":")
	return ok && subtle.ConstantTimeCompare([]byte(password), []byte(token)) == 1
}

func splitProxyTarget(hostport string) (host, port string) {
	if host, port, err := net.SplitHostPort(hostport); err == nil {
		return host, port
	}
	return hostport, "443"
}

func proxyAPIHost(p *EgressProxy, host string) bool {
	hosts := p.APIHosts
	if len(hosts) == 0 {
		hosts = []string{HostGatewayAlias}
	}
	for _, apiHost := range hosts {
		if strings.EqualFold(host, apiHost) {
			return true
		}
	}
	return false
}

// StartScopedEgressProxy starts a host proxy whose lifetime is one scan. The
// harness package's process-wide starter intentionally has no close hook, so
// provider-specific allowlists use this variant to avoid leaking listeners.
// p.Allow stays the any-port base. Each grant host is added to the inner
// proxy's allowlist behind a gate that admits it on declared ports only.
func StartScopedEgressProxy(p *EgressProxy, grants ...EgressGrant) (int, func(), error) {
	noop := func() {}
	if err := validateEgressProxy(p); err != nil {
		return 0, noop, err
	}
	inner, err := grantedProxy(p, grants)
	if err != nil {
		return 0, noop, err
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, noop, err
	}
	srv := newEgressProxyServer(inner, "", p.Allow, grants)
	go func() { _ = srv.Serve(ln) }()
	// srv.Close only closes listeners Serve has already tracked; if the Serve
	// goroutine has not been scheduled yet, srv.listeners is empty and ln stays
	// open until Serve eventually runs. Closing ln directly makes the returned
	// cleanup synchronous regardless of goroutine scheduling; the second close
	// on an already-closed listener is a discarded error.
	closeProxy := func() { _ = srv.Close(); _ = ln.Close() }
	return ln.Addr().(*net.TCPAddr).Port, closeProxy, nil
}
