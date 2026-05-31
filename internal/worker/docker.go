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
	// no-new-privileges is set on the container, and the runner creates
	// a per-scan --internal docker network so the only egress path is
	// the host proxy and concurrent scans cannot reach each other.
	// Profile images must work with a read-only rootfs when this is
	// enabled (writable paths beyond /work and /tmp will fail).
	Hardened bool
}

// hardenedNetworkPrefix is the common prefix used to name the per-scan
// --internal docker networks. SweepOrphanHardenedNetworks relies on it
// to identify residue from crashed scrutineer processes.
const hardenedNetworkPrefix = "scrutineer-hardened-"

// hardenedNetworkName returns the docker network name dedicated to a
// single hardened scan. Uniqueness per scan is the whole isolation
// property: two scans must never produce the same name.
func hardenedNetworkName(scanID uint) string {
	return fmt.Sprintf("%s%d", hardenedNetworkPrefix, scanID)
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
	if err := d.checkHardenedWorkspace(sj.WorkRoot); err != nil {
		return SkillResult{}, err
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
	d.injectProfileGuide(profile, absWork, emit)

	var perScanNetwork string
	if d.Hardened {
		if sj.ScanID == 0 {
			return SkillResult{Commit: commit, Profile: profile}, fmt.Errorf("hardened mode requires SkillJob.ScanID; refusing to share %s0 across scans", hardenedNetworkPrefix)
		}
		perScanNetwork = hardenedNetworkName(sj.ScanID)
		if err := EnsureHardenedNetwork(perScanNetwork); err != nil {
			return SkillResult{Commit: commit, Profile: profile}, fmt.Errorf("create hardened network: %w", err)
		}
		defer func() {
			_ = exec.Command("docker", "network", "rm", "--", perScanNetwork).Run()
		}()
	}

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	// docker treats a non-absolute -v source as a named volume (which
	// rejects '/'), so the config dir must be absolutised like absWork.
	var absConfig string
	if sj.ClaudeConfigDir != "" {
		absConfig, _ = filepath.Abs(sj.ClaudeConfigDir)
		if err := os.MkdirAll(absConfig, dirPerm); err != nil {
			return SkillResult{Commit: commit, Profile: profile}, fmt.Errorf("create claude config dir: %w", err)
		}
	}
	dockerBase := d.buildDockerArgs(absWork, image, perScanNetwork, absConfig)

	logLine := "$ docker run --rm " + image + " <skill:" + sj.Name + ">"
	if d.AnthropicBaseURL != "" {
		logLine += " [ANTHROPIC_BASE_URL=" + d.AnthropicBaseURL + "]"
	}
	emit(Event{Kind: KindText, Text: logLine})

	planLimitText := ""
	wrappedEmit := func(e Event) {
		if planLimitText == "" {
			planLimitText = claudePlanLimitText(e.Text)
		}
		emit(e)
	}
	hitMaxTurns, sessionID, waitErr := d.runDockerOnce(ctx, dockerBase, sj, wrappedEmit)

	if waitErr != nil && sj.ResumeSessionID != "" && sessionID == "" && planLimitText == "" {
		// The resume produced no session event, so claude could not load the
		// saved conversation (gone from the mounted store). Restart fresh in
		// the same /work + config mount so the retry lineage isn't wedged on
		// a dead session id.
		emit(Event{Kind: KindText, Text: "resume of session " + sj.ResumeSessionID + " failed; restarting fresh"})
		fresh := sj
		fresh.ResumeSessionID = ""
		hitMaxTurns, sessionID, waitErr = d.runDockerOnce(ctx, dockerBase, fresh, wrappedEmit)
	}

	res := SkillResult{Commit: commit, Profile: profile, SessionID: sessionID}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		if hitMaxTurns {
			return res, &MaxTurnsReachedError{}
		}
		if planLimitText != "" {
			return res, &ClaudePlanLimitError{Detail: planLimitText}
		}
		return res, fmt.Errorf("docker exited: %w", waitErr)
	}
	return res, nil
}

// runDockerOnce launches one container for the given skill job, appending
// the in-container `claude` command to dockerBase, streaming its output
// through emit, and reporting the wait error, whether the run hit the
// max-turns cap, and the session id from the init event (empty when no init
// event arrived, e.g. a --resume that could not find the conversation).
func (d DockerRunner) runDockerOnce(ctx context.Context, dockerBase []string, sj SkillJob, emit func(Event)) (hitMaxTurns bool, sessionID string, waitErr error) {
	claudeArgs := append([]string{"claude"}, buildClaudeArgs(sj, d.Effort, d.MaxTurns)...)
	dockerArgs := append(append([]string{}, dockerBase...), claudeArgs...)

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return false, "", fmt.Errorf("start docker: %w", err)
	}

	wrappedEmit := func(e Event) {
		switch {
		case e.Kind == KindError && e.Text == "hit max turns":
			hitMaxTurns = true
		case e.Kind == KindSession && e.SessionID != "":
			sessionID = e.SessionID
		}
		emit(e)
	}
	ParseStream(stdout, wrappedEmit)
	waitErr = cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	return hitMaxTurns, sessionID, waitErr
}

// buildDockerArgs assembles the `docker run` flags for a skill invocation.
// Returns the args up to and including the image name; the caller appends
// the in-container command. Split out of RunSkill to keep its cognitive
// complexity manageable as new toggles (hardened mode, proxy, profiles)
// accumulate.
func (d DockerRunner) buildDockerArgs(absWork, image, perScanNetwork, claudeConfigDir string) []string {
	gwTarget := "host-gateway"
	if d.Hardened {
		// Each --internal network has its own subnet and gateway, so the
		// IPv4 must be probed against the per-scan network the runner
		// will actually attach to. An empty probe result falls through
		// to docker's literal host-gateway alias.
		if ip := ResolveHostGatewayIPv4(image, perScanNetwork); ip != "" {
			gwTarget = ip
		}
	} else if d.HostGatewayIP != "" {
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
	if claudeConfigDir != "" {
		// Persist the resumable claude session store outside the container.
		// Without this it lands in the /tmp tmpfs and dies with the
		// container, so --resume on a retry would find nothing. The bind
		// mount stays writable even under hardened mode's --read-only
		// rootfs, so resume works there too.
		args = append(args,
			"-v", claudeConfigDir+":/claude-config",
			"-e", "CLAUDE_CONFIG_DIR=/claude-config",
		)
	}
	if d.Hardened {
		// Read-only rootfs + no-new-privileges close the residual paths a
		// hostile skill could use to escalate inside the container. /work
		// stays writable (skill output) and /tmp is the tmpfs declared
		// above with HOME=/tmp redirecting claude session storage.
		args = append(args,
			"--read-only",
			"--security-opt", "no-new-privileges",
			"--network", perScanNetwork,
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
	img, err := p.EnsureImage(ctx, d.ProfilesDir, defaultImg, emit)
	if err != nil {
		emit(Event{Kind: KindText, Text: "profile: " + p.Name + " build failed, using default: " + err.Error()})
		return "", defaultImg
	}
	emit(Event{Kind: KindText, Text: "profile: " + p.Name + " (" + img + ")"})
	return p.Name, img
}

// profileGuideFileMode is the mode used when copying a profile's
// PROFILE.md into the workspace as CLAUDE.md. The workspace already
// belongs to the host user (the docker runner mounts it as that uid),
// so a plain 0644 keeps it readable by the agent without surprises.
const profileGuideFileMode os.FileMode = 0o644

// checkHardenedWorkspace returns an error when hardened mode is on
// and the cloned workspace exceeds HardenedWorkspaceCapBytes. A no-op
// outside hardened mode so the cap doesn't apply to default scans.
func (d DockerRunner) checkHardenedWorkspace(workRoot string) error {
	if !d.Hardened {
		return nil
	}
	size, err := dirSize(workRoot)
	if err != nil {
		return fmt.Errorf("hardened workspace size check: %w", err)
	}
	if size > HardenedWorkspaceCapBytes {
		return fmt.Errorf("hardened workspace exceeds %d bytes after clone (got %d)", HardenedWorkspaceCapBytes, size)
	}
	return nil
}

// injectProfileGuide copies the resolved profile's PROFILE.md into the
// workspace as CLAUDE.md so claude-code auto-loads it as project memory
// ahead of the skill prompt. A workspace copy (rather than a bind mount)
// avoids Docker Desktop's refusal to materialise a sub-path mountpoint
// inside another bind mount. No-ops when the profile has no guide;
// failures are reported via emit but never block the scan.
func (d DockerRunner) injectProfileGuide(profile, absWork string, emit func(Event)) {
	guide := d.profileGuidePath(profile)
	if guide == "" {
		return
	}
	target := filepath.Join(absWork, "CLAUDE.md")
	data, err := os.ReadFile(guide)
	if err != nil {
		emit(Event{Kind: KindText, Text: "profile guide: read " + guide + ": " + err.Error()})
		return
	}
	if err := os.WriteFile(target, data, profileGuideFileMode); err != nil {
		emit(Event{Kind: KindText, Text: "profile guide: write " + target + ": " + err.Error()})
		return
	}
	emit(Event{Kind: KindText, Text: "profile guide: " + guide + " -> /work/CLAUDE.md"})
}

// profileGuidePath returns the profile's on-disk PROFILE.md if present.
// The caller mounts it at the agent's project-memory path (CLAUDE.md
// for claude-code) so it's auto-loaded before the skill prompt runs.
// The on-disk name stays agent-neutral to support a future codex runner
// reading the same file as AGENTS.md.
func (d DockerRunner) profileGuidePath(profile string) string {
	if profile == "" || d.ProfilesDir == "" {
		return ""
	}
	guide := filepath.Join(d.ProfilesDir, profile, "PROFILE.md")
	abs, err := filepath.Abs(guide)
	if err != nil {
		return ""
	}
	if _, err := os.Stat(abs); err != nil {
		return ""
	}
	return abs
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
// path out. The function is idempotent: a retry of a scan that crashed
// after the network was created (but before the post-scan rm ran) will
// reuse the existing network instead of failing.
func EnsureHardenedNetwork(name string) error {
	if out, err := exec.Command("docker", "network", "inspect", "--", name).Output(); err == nil && len(out) > 0 {
		return nil
	}
	cmd := exec.Command("docker", "network", "create", "--internal", "--", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker network create --internal %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SweepOrphanHardenedNetworks removes per-scan hardened docker networks
// left over by previous scrutineer processes (typically after a crash
// mid-scan). Docker refuses to remove a network that still has
// containers attached, so a concurrently running scan from another
// scrutineer instance is safe from this sweep. Returns the number of
// networks actually removed; rm failures are intentionally swallowed
// since a busy network is exactly what we want to leave alone.
func SweepOrphanHardenedNetworks() (int, error) {
	out, err := exec.Command("docker", "network", "ls",
		"--filter", "name="+hardenedNetworkPrefix,
		"--format", "{{.Name}}").Output()
	if err != nil {
		return 0, fmt.Errorf("docker network ls: %w", err)
	}
	removed := 0
	for _, n := range parseHardenedNetworkNames(out) {
		if err := exec.Command("docker", "network", "rm", "--", n).Run(); err == nil {
			removed++
		}
	}
	return removed, nil
}

// parseHardenedNetworkNames extracts strict-prefix matches from the
// output of `docker network ls --format {{.Name}}`. Docker's --filter
// name= is a substring match, so we re-check the prefix here to avoid
// touching a user-named network that happens to contain the substring.
func parseHardenedNetworkNames(out []byte) []string {
	var names []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && strings.HasPrefix(name, hardenedNetworkPrefix) {
			names = append(names, name)
		}
	}
	return names
}
