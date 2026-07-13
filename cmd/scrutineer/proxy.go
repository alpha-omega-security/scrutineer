package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"scrutineer/internal/worker"
)

// proxyReadinessTimeout bounds how long the egress-proxy sidecar waits for the
// host skill API to become reachable before giving up and exiting non-zero. It
// is generous because the readiness path is local (sidecar -> host-gateway) but
// a cold runtime or a backend that needs a moment to wire host-loopback
// forwarding can take a few seconds. Exiting after this is the fail-closed
// signal: a backend that never forwards host-gateway to the host loopback makes
// the sidecar quit, which the host's hardened verification surfaces as the scan
// being refused rather than run with a broken skill API.
const proxyReadinessTimeout = 20 * time.Second

// proxyConfig is the resolved configuration for the egress-proxy sidecar.
type proxyConfig struct {
	listen  string   // listen address inside the sidecar container
	token   string   // Proxy-Authorization token clients must present
	apiHost string   // host-gateway IPv4 the sidecar dials for the host skill API
	apiPort string   // host skill API port; the only port allowed for the host alias
	allow   []string // egress allowlist
}

// parseProxyConfig resolves the sidecar configuration from flags layered over
// environment defaults. Env carries the per-scan values the container runner
// injects (-e SCRUTINEER_PROXY_*); the flags exist mainly for manual runs and
// tests. getenv is injected so tests exercise the env path without mutating the
// process environment.
func parseProxyConfig(args []string, getenv func(string) string) (proxyConfig, error) {
	fset := flag.NewFlagSet("proxy", flag.ContinueOnError)
	var listen, token, apiHost, apiPort, allow string
	fset.StringVar(&listen, "listen", envOr(getenv, "SCRUTINEER_PROXY_LISTEN", ":3128"), "listen address")
	fset.StringVar(&token, "token", getenv("SCRUTINEER_PROXY_TOKEN"), "Proxy-Authorization token clients must present")
	fset.StringVar(&apiHost, "api-host", getenv("SCRUTINEER_PROXY_API_HOST"), "host-gateway IPv4 to dial for the host skill API")
	fset.StringVar(&apiPort, "api-port", getenv("SCRUTINEER_PROXY_API_PORT"), "host skill API port (only port allowed for the host alias)")
	fset.StringVar(&allow, "allow", getenv("SCRUTINEER_PROXY_ALLOW"), "comma-separated egress allowlist")
	if err := fset.Parse(args); err != nil {
		return proxyConfig{}, err
	}
	cfg := proxyConfig{
		listen:  listen,
		token:   token,
		apiHost: apiHost,
		apiPort: apiPort,
		allow:   splitAllow(allow),
	}
	if cfg.token == "" {
		return proxyConfig{}, errors.New("proxy: empty token (set -token or SCRUTINEER_PROXY_TOKEN)")
	}
	if len(cfg.allow) == 0 {
		return proxyConfig{}, errors.New("proxy: empty allowlist (set -allow or SCRUTINEER_PROXY_ALLOW)")
	}
	return cfg, nil
}

// splitAllow turns a comma-separated allowlist into a trimmed, empty-free slice.
func splitAllow(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// envOr returns getenv(key) when non-empty, else def.
func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// resolveListen turns the SidecarListenFirstIface keyword in the listen host
// into the concrete IPv4 of the sidecar's first interface -- its per-scan
// --internal leg -- so the listener never faces the default bridge the egress
// leg is attached to. Any other listen value passes through untouched (manual
// runs; a malformed one fails at bind time). A resolution failure is fatal:
// falling back to all interfaces would silently re-open the probe surface the
// keyword exists to remove. firstIfaceIPv4 is injected for tests.
func resolveListen(listen string, firstIfaceIPv4 func() (string, error)) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || host != worker.SidecarListenFirstIface {
		return listen, nil
	}
	ip, err := firstIfaceIPv4()
	if err != nil {
		return "", fmt.Errorf("resolve %s listen address: %w", worker.SidecarListenFirstIface, err)
	}
	return net.JoinHostPort(ip, port), nil
}

// runProxy is the entrypoint for `scrutineer proxy`: the egress-proxy sidecar
// the container runner attaches to a hardened scan's --internal network under
// rootless podman. The scan container points HTTPS_PROXY at this
// process; it enforces the same allowlist as the in-process host proxy and
// forwards out its egress leg. It refuses to start serving until it has
// confirmed it can reach the host skill API, so a network backend that cannot
// forward host-gateway to the host loopback fails the scan closed instead of
// silently breaking every skill API call.
func runProxy(args []string) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg, err := parseProxyConfig(args, os.Getenv)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // usage already printed by Parse
		}
		return err
	}
	if cfg.listen, err = resolveListen(cfg.listen, worker.FirstIfaceIPv4); err != nil {
		return fmt.Errorf("egress proxy refusing to start: %w", err)
	}

	if cfg.apiHost != "" && cfg.apiPort != "" {
		ctx, cancel := context.WithTimeout(context.Background(), proxyReadinessTimeout)
		defer cancel()
		log.Info("egress proxy: waiting for host skill API", "host", cfg.apiHost, "port", cfg.apiPort)
		if err := worker.WaitHostAPIReachable(ctx, cfg.apiHost, cfg.apiPort); err != nil {
			return fmt.Errorf("egress proxy refusing to start: %w", err)
		}
		// Upstream names are resolved here in the sidecar, not on the host, so a
		// rootless netns without working DNS would fail every scan mid-run; prove
		// the resolver answers before serving (fail closed).
		if err := worker.VerifyUpstreamDNS(ctx, cfg.allow); err != nil {
			return fmt.Errorf("egress proxy refusing to start: %w", err)
		}
	}

	p := &worker.EgressProxy{
		Allow:           cfg.allow,
		Token:           cfg.token,
		APIPort:         cfg.apiPort,
		GatewayDialHost: cfg.apiHost,
		Log:             log,
	}
	log.Info("egress proxy listening", "addr", cfg.listen, "allow", len(cfg.allow))
	return worker.ServeEgressProxy(p, cfg.listen)
}
