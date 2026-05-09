// Package worker provides a DockerRunner that executes claude in an ephemeral
// container. Used when docker is available on the host; falls back to
// LocalClaude otherwise. The scrutineer process runs on the host (not
// containerised) and calls docker directly -- no socket mounting needed (T12).
package worker

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const DefaultRunnerImage = "ghcr.io/alpha-omega-security/scrutineer-runner:latest"

// EgressNetworkName is the docker bridge network the runner attaches scan
// containers to. It is created with --internal so containers have no route
// to the outside world; the only reachable address is the host's interface
// on that bridge, where the EgressProxy listens. See GHSA-qwg8-7975-9jwh.
const EgressNetworkName = "scrutineer-egress"

// DockerRunner launches claude inside an ephemeral container with the scan
// workspace (clone + staged skill + output file) mounted at /work. It
// implements SkillRunner.
type DockerRunner struct {
	Image            string
	Effort           string
	ProxyURL         string // http://user:token@host.docker.internal:port; "" disables egress
	Network          string // docker network to attach to; should be an --internal bridge
	FullClone        bool
	MaxTurns         int
	AnthropicBaseURL string // passed as ANTHROPIC_BASE_URL env var to the container
	HostGatewayIP    string // IPv4 address for --add-host; falls back to "host-gateway"
}

func (d DockerRunner) image() string {
	if d.Image != "" {
		return d.Image
	}
	return DefaultRunnerImage
}

// RunSkill runs a skill inside an ephemeral container. The whole workspace
// (clone + staged .claude/skills + context.json + output) is mounted at
// /work read-write so claude can read the skill files and write its output.
// Egress is routed through scrutineer's allowlisting proxy on the host;
// see EgressProxy. tmpfs/cap-drop rules mirror the local runner's intent.
func (d DockerRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	src, err := ensureClone(ctx, sj.Repo, sj.WorkRoot, d.FullClone, sj.Ref, emit)
	if err != nil {
		return SkillResult{}, err
	}
	commit := gitHead(src)
	work := sj.WorkRoot
	absWork, _ := filepath.Abs(work)

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	claudeArgs := append([]string{"claude"}, buildClaudeArgs(sj, d.Effort, d.MaxTurns)...)
	dockerArgs := d.dockerArgs(absWork, claudeArgs)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return SkillResult{}, err
	}
	cmd.Stderr = cmd.Stdout

	logLine := "$ docker run --rm " + d.image() + " <skill:" + sj.Name + ">"
	if d.AnthropicBaseURL != "" {
		logLine += " [ANTHROPIC_BASE_URL=" + d.AnthropicBaseURL + "]"
	}
	emit(Event{Kind: KindText, Text: logLine})
	if err := cmd.Start(); err != nil {
		return SkillResult{}, fmt.Errorf("start docker: %w", err)
	}

	hitMaxTurns := false
	wrappedEmit := func(e Event) {
		if e.Kind == KindError && e.Text == "hit max turns" {
			hitMaxTurns = true
		}
		emit(e)
	}
	ParseStream(stdout, wrappedEmit)
	waitErr := cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	res := SkillResult{Commit: commit}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		if hitMaxTurns {
			return res, &MaxTurnsReachedError{}
		}
		return res, fmt.Errorf("docker exited: %w", waitErr)
	}
	return res, nil
}

// dockerArgs builds the `docker run` argv for a single skill scan. Pulled
// out of RunSkill so the network/proxy wiring can be unit-tested without a
// daemon.
func (d DockerRunner) dockerArgs(absWork string, claudeArgs []string) []string {
	gwTarget := "host-gateway"
	if d.HostGatewayIP != "" {
		gwTarget = d.HostGatewayIP
	}
	args := []string{
		"run", "--rm",
		"--cap-drop", "ALL",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp",
		"-e", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"-e", "SEMGREP_SEND_METRICS=off",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"-v", absWork + ":/work",
		"-w", "/work",
		"--add-host", HostGatewayAlias + ":" + gwTarget,
	}
	if d.ProxyURL != "" {
		if d.Network != "" {
			args = append(args, "--network", d.Network)
		}
		args = append(args,
			"-e", "HTTPS_PROXY="+d.ProxyURL,
			"-e", "HTTP_PROXY="+d.ProxyURL,
			"-e", "ALL_PROXY="+d.ProxyURL,
			"-e", "NO_PROXY=",
		)
	} else {
		args = append(args, "--network", "none")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		args = append(args, "-e", "ANTHROPIC_API_KEY")
	}
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" {
		args = append(args, "-e", "CLAUDE_CODE_OAUTH_TOKEN")
	}
	if d.AnthropicBaseURL != "" {
		args = append(args, "-e", "ANTHROPIC_BASE_URL="+d.AnthropicBaseURL)
	}
	args = append(args, d.image())
	return append(args, claudeArgs...)
}

// DockerAvailable checks if docker is in PATH and the daemon is reachable.
func DockerAvailable() bool {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	return err == nil && len(out) > 0
}

// EnsureEgressNetwork creates the --internal bridge network that scan
// containers attach to, if it doesn't already exist, and returns the host's
// gateway IPv4 on that bridge. Containers on this network have no route to
// the outside world; the gateway IP is the only reachable address, and the
// EgressProxy listening on 0.0.0.0 answers there. Inter-container traffic
// is also disabled so concurrent scans cannot probe each other.
//
// If a network with this name already exists but is not --internal (e.g. an
// operator created it manually), EnsureEgressNetwork fails rather than
// silently attaching containers to a routable bridge.
func EnsureEgressNetwork(name string) (string, error) {
	gw, internal, exists := inspectNetwork(name)
	if exists {
		if !internal {
			return "", fmt.Errorf("docker network %q exists but is not --internal; remove it and let scrutineer recreate it", name)
		}
		if gw == "" {
			return "", fmt.Errorf("docker network %q has no IPv4 gateway", name)
		}
		return gw, nil
	}
	out, err := exec.Command("docker", "network", "create",
		"--driver", "bridge",
		"--internal",
		"-o", "com.docker.network.bridge.enable_icc=false",
		name).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker network create %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	gw, _, _ = inspectNetwork(name)
	if gw == "" {
		return "", fmt.Errorf("network %s created but no IPv4 gateway reported", name)
	}
	return gw, nil
}

// ResolveHostGatewayIPv4 returns the IPv4 address that Docker's
// host-gateway maps to. Docker adds both IPv4 and IPv6 /etc/hosts
// entries for host-gateway; tools that prefer IPv6 (like Node's fetch)
// fail when the server only listens on 127.0.0.1. Using the explicit
// IPv4 address avoids the dual-stack ambiguity.
//
// This is only used on Docker Desktop (darwin/windows), where the
// --internal egress network cannot reach the host and the runner falls
// back to the cooperative proxy on the default bridge.
func ResolveHostGatewayIPv4(image string) string {
	out, err := exec.Command("docker", "run", "--rm",
		"--add-host", "hgw:host-gateway",
		"--entrypoint", "grep",
		image, "hgw", "/etc/hosts").Output()
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip != nil && ip.To4() != nil {
			return fields[0]
		}
	}
	return ""
}

func inspectNetwork(name string) (gw string, internal, exists bool) {
	out, err := exec.Command("docker", "network", "inspect", name,
		"--format", "{{.Internal}} {{range .IPAM.Config}}{{.Gateway}} {{end}}").Output()
	if err != nil {
		return "", false, false
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", false, true
	}
	internal = fields[0] == "true"
	for _, f := range fields[1:] {
		if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
			return f, internal, true
		}
	}
	return "", internal, true
}
