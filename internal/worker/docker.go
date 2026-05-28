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

// DockerRunner launches claude inside an ephemeral container with the scan
// workspace (clone + staged skill + output file) mounted at /work. It
// implements SkillRunner.
type DockerRunner struct {
	Image            string
	Effort           string
	ProxyURL         string // http://user:token@host.docker.internal:port; "" disables egress
	FullClone        bool
	MaxTurns         int
	AnthropicBaseURL string // passed as ANTHROPIC_BASE_URL env var to the container
	HostGatewayIP    string // IPv4 address for --add-host; falls back to "host-gateway"
	// ProfilesDir is the host directory containing docker/profiles/<name>/
	// Dockerfile entries. When empty, profile resolution is skipped and
	// every scan runs in the default Image.
	ProfilesDir string
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
	var src string
	if sj.SrcReady {
		src = filepath.Join(sj.WorkRoot, "src")
	} else {
		var err error
		src, err = ensureClone(ctx, sj.Repo, sj.WorkRoot, d.FullClone, sj.Ref, emit)
		if err != nil {
			return SkillResult{}, err
		}
	}
	commit := gitHead(src)
	work := sj.WorkRoot
	absWork, _ := filepath.Abs(work)

	profile, image := d.resolveProfile(ctx, sj.Profile, src, emit)

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	claudeArgs := append([]string{"claude"}, buildClaudeArgs(sj, d.Effort, d.MaxTurns)...)

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
		// Suppress telemetry traffic
		// Denied by the egress proxy anyway, but noisy in the log.
		"-e", "OTEL_SDK_DISABLED=true",
		"-e", "DISABLE_TELEMETRY=1",
		"-e", "DISABLE_ERROR_REPORTING=1",
		"-e", "DISABLE_BUG_COMMAND=1",
		"-e", "DISABLE_AUTOUPDATER=1",
		// Disable auxiliary calls not useful in headless mode
		"-e", "DISABLE_NON_ESSENTIAL_MODEL_CALLS=1",
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
	dockerArgs = append(dockerArgs, "--", image)
	dockerArgs = append(dockerArgs, claudeArgs...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return SkillResult{}, err
	}
	cmd.Stderr = cmd.Stdout

	logLine := "$ docker run --rm " + image + " <skill:" + sj.Name + ">"
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

	res := SkillResult{Commit: commit, Profile: profile}
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

// resolveProfile picks the runner image for this scan. When requested
// is non-empty, the operator's choice wins (and "default" forces the
// default image); when empty, scrutineer probes the clone with `brief`
// to auto-select. Any failure along the way falls back to the default
// image with a log line so a missing profile never blocks a scan.
func (d DockerRunner) resolveProfile(ctx context.Context, requested, src string, emit func(Event)) (string, string) {
	defaultImg := d.image()
	if d.ProfilesDir == "" {
		return "", defaultImg
	}
	var p Profile
	if requested != "" {
		if requested == "default" {
			return "", defaultImg
		}
		p = ProfileByName(requested)
		if p.IsDefault() {
			emit(Event{Kind: KindText, Text: "profile: unknown " + requested + ", using default"})
			return "", defaultImg
		}
	} else {
		p = DetectProfile(ctx, defaultImg, src)
		if p.IsDefault() {
			return "", defaultImg
		}
	}
	img, err := p.EnsureImage(ctx, d.ProfilesDir, defaultImg)
	if err != nil {
		emit(Event{Kind: KindText, Text: "profile: " + p.Name + " build failed, using default: " + err.Error()})
		return "", defaultImg
	}
	emit(Event{Kind: KindText, Text: "profile: " + p.Name + " (" + img + ")"})
	return p.Name, img
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
		"--", image, "hgw", "/etc/hosts").Output()
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
