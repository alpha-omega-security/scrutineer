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
)

const DefaultRunnerImage = "ghcr.io/alpha-omega-security/scrutineer-runner:latest"

// DockerRunner launches a skill inside an ephemeral container with the scan
// workspace (clone + staged skill + output file) mounted at /work. It
// implements SkillRunner. The Harness field selects which CLI the container
// execs: "claude" (default), "codex", or "opencode".
type DockerRunner struct {
	Image            string
	Effort           string
	Harness          string // "claude" (default), "codex", or "opencode"
	ProxyURL         string // http://user:token@host.docker.internal:port; "" disables egress
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

func (d DockerRunner) harness() string {
	if d.Harness != "" {
		return d.Harness
	}
	return "claude"
}

// buildEntrypoint returns the command+args the container should exec based
// on the configured harness.
func (d DockerRunner) buildEntrypoint(sj SkillJob) []string {
	switch d.harness() {
	case "codex":
		args := []string{"codex", "exec"}
		if sj.Model != "" {
			args = append(args, "--model", sj.Model)
		}
		args = append(args, buildSkillPrompt(sj.Name, sj.OutputFile))
		return args
	case "opencode":
		args := []string{"opencode", "run"}
		if sj.Model != "" {
			args = append(args, "--model", sj.Model)
		}
		args = append(args, buildSkillPrompt(sj.Name, sj.OutputFile))
		return args
	default: // "claude"
		return append([]string{"claude"}, buildClaudeArgs(sj, d.Effort, d.MaxTurns)...)
	}
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

	entrypoint := d.buildEntrypoint(sj)

	gwTarget := "host-gateway"
	if d.HostGatewayIP != "" {
		gwTarget = d.HostGatewayIP
	}
	dockerArgs := []string{
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
		dockerArgs = append(dockerArgs,
			"-e", "HTTPS_PROXY="+d.ProxyURL,
			"-e", "HTTP_PROXY="+d.ProxyURL,
			"-e", "ALL_PROXY="+d.ProxyURL,
			"-e", "NO_PROXY=",
		)
	} else {
		dockerArgs = append(dockerArgs, "--network", "none")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		dockerArgs = append(dockerArgs, "-e", "ANTHROPIC_API_KEY")
	}
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "" {
		dockerArgs = append(dockerArgs, "-e", "CLAUDE_CODE_OAUTH_TOKEN")
	}
	if d.AnthropicBaseURL != "" {
		dockerArgs = append(dockerArgs, "-e", "ANTHROPIC_BASE_URL="+d.AnthropicBaseURL)
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		dockerArgs = append(dockerArgs, "-e", "OPENAI_API_KEY")
	}
	dockerArgs = append(dockerArgs, d.image())
	dockerArgs = append(dockerArgs, entrypoint...)

	logLine := "$ docker run --rm " + d.image() + " " + d.harness() + " <skill:" + sj.Name + ">"
	if d.AnthropicBaseURL != "" {
		logLine += " [ANTHROPIC_BASE_URL=" + d.AnthropicBaseURL + "]"
	}

	err = runCommand(ctx, runSpec{
		Name: "docker",
		Args: dockerArgs,
		Env:  os.Environ(),
		Log:  logLine,
	}, emit)

	res := SkillResult{Commit: commit}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if err != nil {
		return res, err
	}
	return res, nil
}

// DockerAvailable checks if docker is in PATH and the daemon is reachable.
func DockerAvailable() bool {
	out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").Output()
	return err == nil && len(out) > 0
}

// ResolveHostGatewayIPv4 returns the IPv4 address that Docker's
// host-gateway maps to. Docker adds both IPv4 and IPv6 /etc/hosts
// entries for host-gateway; tools that prefer IPv6 (like Node's fetch)
// fail when the server only listens on 127.0.0.1. Using the explicit
// IPv4 address avoids the dual-stack ambiguity.
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
