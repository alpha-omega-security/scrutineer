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
	// Hardened toggles the strict sandbox: rootfs is mounted read-only,
	// no-new-privileges is set on the container, and the runner attaches
	// to HardenedNetwork (which must be --internal) so the only egress
	// path is the host proxy. Profile images must work with a read-only
	// rootfs when this is enabled (writable paths beyond /work and /tmp
	// will fail).
	Hardened        bool
	HardenedNetwork string
}

func (d DockerRunner) image() string {
	if d.Image != "" {
		return d.Image
	}
	return DefaultRunnerImage
}

// HardenedWorkspaceCapBytes caps the per-scan workspace footprint that
// hardened mode tolerates after clone completes. This is a post-clone
// check, not a clone-time bound: a clone that already exceeds disk
// capacity fails earlier on its own, so this cap is what hardened mode
// will agree to scan, not a guarantee against disk fill during clone
// (use OS-level disk quotas for that). 2 GiB leaves room for genuinely
// large legitimate repos.
const HardenedWorkspaceCapBytes int64 = 2 << 30

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
	if d.Hardened {
		size, err := dirSize(sj.WorkRoot)
		if err != nil {
			return SkillResult{}, fmt.Errorf("hardened workspace size check: %w", err)
		}
		if size > HardenedWorkspaceCapBytes {
			return SkillResult{}, fmt.Errorf("hardened workspace exceeds %d bytes after clone (got %d)", HardenedWorkspaceCapBytes, size)
		}
	}
	commit := gitHead(src)
	work := sj.WorkRoot
	absWork, _ := filepath.Abs(work)

	profile, image := d.resolveProfile(ctx, sj.Profile, src, emit)
	if sj.RequiresProfile != "" && profile != sj.RequiresProfile {
		got := profile
		if got == "" {
			got = "default"
		}
		return SkillResult{Commit: commit, Profile: profile}, fmt.Errorf("skill %q requires profile %q, resolved %q", sj.Name, sj.RequiresProfile, got)
	}

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	claudeArgs := append([]string{"claude"}, buildClaudeArgs(sj, d.Effort, d.MaxTurns)...)
	dockerArgs := append(d.buildDockerArgs(absWork, image), claudeArgs...)

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

// buildDockerArgs assembles the `docker run` flags for a skill invocation.
// Returns the args up to and including the image name; the caller appends
// the in-container command. Split out of RunSkill to keep its cognitive
// complexity manageable as new toggles (hardened mode, proxy, profiles)
// accumulate.
func (d DockerRunner) buildDockerArgs(absWork, image string) []string {
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
	if d.Hardened {
		// Read-only rootfs + no-new-privileges close the residual paths a
		// hostile skill could use to escalate inside the container. /work
		// stays writable (skill output) and /tmp is the tmpfs declared
		// above with HOME=/tmp redirecting claude session storage.
		args = append(args,
			"--read-only",
			"--security-opt", "no-new-privileges",
			"--network", d.HardenedNetwork,
		)
	}
	if d.ProxyURL != "" {
		args = append(args,
			"-e", "HTTPS_PROXY="+d.ProxyURL,
			"-e", "HTTP_PROXY="+d.ProxyURL,
			"-e", "ALL_PROXY="+d.ProxyURL,
			"-e", "NO_PROXY=",
		)
	} else if !d.Hardened {
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
	return append(args, "--", image)
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
// host-gateway maps to on the given network. An empty network probes
// the default bridge, which is what scrutineer uses outside hardened
// mode. The hardened path passes its --internal network name so the
// resolved gateway matches the network the runner actually attaches to.
// Docker adds both IPv4 and IPv6 /etc/hosts entries for host-gateway;
// tools that prefer IPv6 (like Node's fetch) fail when the server only
// listens on 127.0.0.1. Using the explicit IPv4 address avoids the
// dual-stack ambiguity.
func ResolveHostGatewayIPv4(image, network string) string {
	args := []string{"run", "--rm", "--add-host", "hgw:host-gateway"}
	if network != "" {
		args = append(args, "--network", network)
	}
	args = append(args, "--entrypoint", "grep", "--", image, "hgw", "/etc/hosts")
	out, err := exec.Command("docker", args...).Output()
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

// dirSize sums the on-disk size of every regular file under root. Used
// by hardened mode to refuse a scan whose workspace is large enough to
// fill the host disk. Errors during the walk are returned so the caller
// can decide whether to fail the scan or skip the cap.
func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// EnsureHardenedNetwork creates an internal docker network with the
// given name if it does not already exist. --internal blocks routes
// to external networks; the container can still reach the host via
// the bridge gateway, so the egress proxy on the host remains the only
// path out. The function is idempotent so scrutineer restarts after a
// crash (when the network may still exist with orphan endpoints) do
// not fail.
func EnsureHardenedNetwork(name string) error {
	if out, err := exec.Command("docker", "network", "inspect", name).Output(); err == nil && len(out) > 0 {
		return nil
	}
	cmd := exec.Command("docker", "network", "create", "--internal", "--", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker network create --internal %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
