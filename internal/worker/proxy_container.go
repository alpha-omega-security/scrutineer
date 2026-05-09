package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	proxyBinary       = "scrutineer-proxy"
	proxyConfigMount  = "/etc/scrutineer-proxy.json"
	proxyConfigPerm   = 0o600
	proxyStartTimeout = 30 * time.Second
	proxyReadyPoll    = 200 * time.Millisecond
)

// ProxyContainer manages the long-lived egress proxy container. It is
// attached to the --internal scan network (so scan containers can reach it
// by name) and to the default bridge (so it can dial upstreams and the
// host's API listener). One per scrutineer process.
type ProxyContainer struct {
	Name    string
	Network string
	Token   string

	cfgPath string
	log     *slog.Logger
	cancel  context.CancelFunc
}

// StartProxyContainer writes cfg to dataDir/proxy.json, removes any stale
// container of the same name, starts a fresh one on network, connects it to
// the default bridge, and tails its logs into log. The container name is
// derived from the network name so two scrutineer instances with distinct
// egress_network values can coexist on one host.
func StartProxyContainer(image, network, dataDir string, cfg ProxyContainerConfig, log *slog.Logger) (*ProxyContainer, error) {
	if err := os.MkdirAll(dataDir, dirPerm); err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(dataDir, "proxy.json")
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfgPath, b, proxyConfigPerm); err != nil {
		return nil, fmt.Errorf("write proxy config: %w", err)
	}
	absCfg, _ := filepath.Abs(cfgPath)

	name := network + "-proxy"
	_ = exec.Command("docker", "rm", "-f", name).Run()

	runArgs := []string{
		"run", "-d",
		"--name", name,
		"--cap-drop", "ALL",
		"--network", network,
		"--add-host", HostGatewayAlias + ":host-gateway",
		"-v", absCfg + ":" + proxyConfigMount + ":ro",
		"--entrypoint", proxyBinary,
		image,
		"-config", proxyConfigMount,
	}
	if out, err := exec.Command("docker", runArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("docker run %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("docker", "network", "connect", "bridge", name).CombinedOutput(); err != nil {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		return nil, fmt.Errorf("docker network connect bridge %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	if err := waitProxyReady(name); err != nil {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	pc := &ProxyContainer{
		Name:    name,
		Network: network,
		Token:   cfg.Token,
		cfgPath: cfgPath,
		log:     log,
		cancel:  cancel,
	}
	go pc.tailLogs(ctx)
	log.Info("egress proxy container running", "name", name, "network", network, "image", image)
	return pc, nil
}

// URL returns the HTTPS_PROXY value scan containers should use. Docker's
// embedded DNS on user-defined networks resolves the container name.
func (pc *ProxyContainer) URL() string {
	return fmt.Sprintf("http://scrutineer:%s@%s:%d", pc.Token, pc.Name, ProxyContainerPort)
}

// Stop removes the container and its config file. Safe to call more than
// once.
func (pc *ProxyContainer) Stop() {
	if pc.cancel != nil {
		pc.cancel()
	}
	_ = exec.Command("docker", "rm", "-f", pc.Name).Run()
	_ = os.Remove(pc.cfgPath)
}

// waitProxyReady polls `docker logs` until the proxy's "listening" line
// appears or the timeout fires. This catches the common failure mode of an
// image that lacks the scrutineer-proxy binary before any scan tries to
// use it.
func waitProxyReady(name string) error {
	deadline := time.Now().Add(proxyStartTimeout)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("docker", "logs", name).CombinedOutput()
		s := string(out)
		if strings.Contains(s, "egress proxy listening") {
			return nil
		}
		if strings.Contains(s, "executable file not found") || strings.Contains(s, "no such file") {
			return fmt.Errorf("runner image is missing the %s binary; rebuild Dockerfile.runner: %s", proxyBinary, strings.TrimSpace(s))
		}
		if strings.Contains(s, `"level":"ERROR"`) {
			return fmt.Errorf("proxy container failed to start: %s", strings.TrimSpace(s))
		}
		time.Sleep(proxyReadyPoll)
	}
	out, _ := exec.Command("docker", "logs", name).CombinedOutput()
	return fmt.Errorf("proxy container %s did not become ready within %s: %s", name, proxyStartTimeout, strings.TrimSpace(string(out)))
}

// tailLogs follows `docker logs -f` and re-emits each JSON line through
// the host slog so egress denials show up alongside scrutineer's own log.
func (pc *ProxyContainer) tailLogs(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "-f", "--since", "0s", pc.Name)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil {
			lvl := slog.LevelInfo
			if l, _ := rec["level"].(string); l == "WARN" {
				lvl = slog.LevelWarn
			} else if l == "ERROR" {
				lvl = slog.LevelError
			}
			msg, _ := rec["msg"].(string)
			delete(rec, "time")
			delete(rec, "level")
			delete(rec, "msg")
			attrs := []any{"container", pc.Name}
			for k, v := range rec {
				attrs = append(attrs, k, v)
			}
			pc.log.Log(ctx, lvl, msg, attrs...)
		} else {
			pc.log.Info(line, "container", pc.Name)
		}
	}
	_ = cmd.Wait()
}
