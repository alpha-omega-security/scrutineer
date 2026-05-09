// scrutineer-proxy is the egress proxy as a standalone binary, run inside
// a container that is attached to both the --internal scan network and the
// default bridge. Scan containers reach it by container name on the
// internal network; it dials upstreams via the bridge. Configuration is a
// worker.ProxyContainerConfig JSON file written by the parent scrutineer
// process and mounted read-only.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"scrutineer/internal/worker"
)

const readHeaderTimeout = 10 * time.Second

func main() {
	cfgPath := flag.String("config", "/etc/scrutineer-proxy.json", "path to ProxyContainerConfig JSON")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(*cfgPath, log); err != nil {
		log.Error("proxy exited", "err", err)
		os.Exit(1)
	}
}

func run(cfgPath string, log *slog.Logger) error {
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg worker.ProxyContainerConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = fmt.Sprintf(":%d", worker.ProxyContainerPort)
	}

	p := &worker.EgressProxy{
		Allow:       cfg.Allow,
		Deny:        cfg.Deny,
		Token:       cfg.Token,
		APIPort:     cfg.APIPort,
		GatewayDial: cfg.GatewayDial,
		Log:         log,
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	log.Info("egress proxy listening",
		"addr", ln.Addr().String(),
		"allow", len(cfg.Allow), "deny", len(cfg.Deny),
		"gateway_dial", cfg.GatewayDial, "api_port", cfg.APIPort)

	srv := &http.Server{Handler: p, ReadHeaderTimeout: readHeaderTimeout}
	return srv.Serve(ln)
}
