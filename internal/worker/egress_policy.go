package worker

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/alpha-omega-security/harness/egress"

	"scrutineer/internal/egressgrant"
)

// EgressGrant is one operator-granted destination, see egressgrant.Grant.
type EgressGrant = egressgrant.Grant

// grantedProxy returns the proxy that should serve p with grants applied: a
// fresh Proxy whose allowlist is p.Allow plus the granted hosts. p itself is
// never mutated. With no grants it returns p. A grant naming an API host is
// refused so a policy can never reach host services.
func grantedProxy(p *EgressProxy, grants []EgressGrant) (*EgressProxy, error) {
	if len(grants) == 0 {
		return p, nil
	}
	for _, g := range grants {
		if err := checkGrantNotAPIHost(p, g); err != nil {
			return nil, err
		}
	}
	return &EgressProxy{
		Allow:           append(slices.Clone(p.Allow), egressgrant.Hosts(grants)...),
		Token:           p.Token,
		APIPort:         p.APIPort,
		APIHosts:        p.APIHosts,
		HostPorts:       p.HostPorts,
		Log:             p.Log,
		GatewayDialHost: p.GatewayDialHost,
	}, nil
}

func checkGrantNotAPIHost(p *EgressProxy, g EgressGrant) error {
	apiHosts := append([]string{HostGatewayAlias}, p.APIHosts...)
	for _, h := range apiHosts {
		if egress.HostAllowed([]string{g.Host}, h) {
			return fmt.Errorf("egress grant for %q covers host service %q, which policies cannot reach", g.Host, h)
		}
	}
	return nil
}

// egressPortGuard enforces declared ports for hosts that only an EgressGrant
// allows. Hosts on base keep their any-port behaviour and hosts that match no
// grant fall through so the inner proxy applies its own allowlist.
func egressPortGuard(token string, base []string, grants []EgressGrant, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, ok := proxyRequestTarget(r)
		if !ok || egress.HostAllowed(base, host) {
			next.ServeHTTP(w, r)
			return
		}
		matched := false
		for _, g := range grants {
			if !egress.HostAllowed([]string{g.Host}, host) {
				continue
			}
			matched = true
			if slices.Contains(g.Ports, port) {
				next.ServeHTTP(w, r)
				return
			}
		}
		if !matched {
			next.ServeHTTP(w, r)
			return
		}
		denyUngrantedPort(w, r, token, log, host, port)
	})
}

func denyUngrantedPort(w http.ResponseWriter, r *http.Request, token string, log *slog.Logger, host, port string) {
	if !validProxyAuthorization(token, r.Header.Get("Proxy-Authorization")) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="harness"`)
		http.Error(w, "proxy authorization required", http.StatusProxyAuthRequired)
		return
	}
	if log != nil {
		log.Warn("egress denied", "method", r.Method, "host", host, "port", port,
			"reason", "port not granted by egress policy")
	}
	http.Error(w, "egress to "+host+" port "+port+" is not granted", http.StatusForbidden)
}

// proxyRequestTarget extracts the destination host and port of a proxy request
// exactly as the inner proxy will dial it. A target without an explicit port is
// dialed on 443 for both CONNECT and forward requests (see splitProxyTarget),
// so the gate checks that port rather than a scheme default the proxy would
// not use. Relative forward requests report ok=false so the inner proxy
// rejects them.
func proxyRequestTarget(r *http.Request) (host, port string, ok bool) {
	if r.Method == http.MethodConnect {
		host, port = splitProxyTarget(r.Host)
		return host, port, true
	}
	if r.URL == nil || !r.URL.IsAbs() {
		return "", "", false
	}
	host, port = splitProxyTarget(r.URL.Host)
	return host, port, true
}
