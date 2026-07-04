// Package worker provides a ContainerRunner that executes claude in an ephemeral
// container via a container runtime (docker, podman, or Apple's container).
// Used when a runtime is available on the host; falls back to LocalClaude
// otherwise. The scrutineer process runs on the host (not containerised) and
// calls the runtime directly -- no socket mounting needed (T12). Rootless podman
// is supported, which keeps runtime access non-root-equivalent (see
// threatmodel.md T12).
package worker

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const DefaultRunnerImage = "ghcr.io/alpha-omega-security/scrutineer-runner:latest"

// ContainerRunner launches claude inside an ephemeral container with the scan
// workspace (clone + staged skill + output file) mounted at /work. It drives
// docker, podman, or Apple's container (selected via the Runtime field) and
// implements SkillRunner.
type ContainerRunner struct {
	Image  string
	Effort string
	// Harness is the agent CLI exec'd inside the container. nil means
	// claude-code (the historical default), so a bare ContainerRunner{}
	// keeps working and no caller needs to set it until a second harness
	// exists.
	Harness          Harness
	ProxyURL         string // http://user:token@host-or-gateway:port; "" disables egress
	FullClone        bool
	MaxTurns         int
	AnthropicBaseURL string // passed as ANTHROPIC_BASE_URL env var to the container
	HostGatewayIP    string // Docker/Podman IPv4 address for --add-host; falls back to "host-gateway"
	// ProfilesDir is the host directory containing docker/profiles/<name>/
	// Dockerfile entries. When empty, profile resolution is skipped and
	// every scan runs in the default Image.
	ProfilesDir string
	// Hardened toggles the strict sandbox: rootfs is mounted read-only,
	// no-new-privileges is set on the container where the runtime supports it
	// (Apple's CLI does not expose it, so its per-container VM substitutes), and
	// the runner creates a per-scan --internal network so the only egress path
	// is the host proxy and concurrent scans cannot reach each other.
	// Profile images must work with a read-only rootfs when this is
	// enabled (writable paths beyond /work and /tmp will fail).
	Hardened bool
	// HardenedRuntimeOnly applies the non-network half of --hardened -- a
	// read-only rootfs, no-new-privileges, and the post-clone workspace cap --
	// WITHOUT the per-scan --internal network. Those are all independent of the
	// network, so unlike full --hardened they work under rootless podman (whose
	// --internal network cannot route to the host egress proxy; see
	// docs/podman.md). The always-on baseline (--cap-drop ALL, non-root --user,
	// the /tmp tmpfs) applies regardless of this field. --hardened already
	// implies all of these, so this is the rootless stand-in for them, not an
	// addition on top (setting both is harmless). The read-only rootfs can break
	// custom profile images that write outside /work and /tmp.
	HardenedRuntimeOnly bool
	// Runtime selects the OCI engine (docker, podman, or Apple's container) and
	// carries the rootless flag that gates --userns=keep-id. The zero value is
	// docker, so a bare ContainerRunner{} keeps shelling out to "docker".
	Runtime ContainerRuntime
	// SELinuxRelabel, when true, appends the ":z" relabel option to every host
	// bind mount (/work, /claude-config, /src) so the container can access them
	// on an SELinux-enabled host. Without it, container_t is denied the host
	// labels and every scan fails with EACCES on the clone and output. Resolved
	// once at startup from the --selinux switch (auto/on/off); see bindMount for
	// the ":z" vs ":Z" rationale and ResolveSELinuxRelabel for the gating. The
	// zero value is false, so docker on a non-SELinux host stays byte-for-byte
	// unchanged.
	SELinuxRelabel bool
	// Egress, when set, routes a hardened scan's egress through a proxy sidecar
	// container instead of the in-process host proxy. setupRunner populates it
	// only for rootless podman under --hardened -- the one configuration where
	// the host proxy is unreachable across the per-scan --internal network. The
	// zero value keeps the host-proxy path (docker, rootful podman, and all
	// non-hardened scans). See usesEgressSidecar.
	Egress EgressSidecarConfig
}

// EgressSidecarConfig carries what setupHardenedNetwork needs to launch the
// egress proxy as a sidecar container under rootless --hardened. The zero value
// disables the sidecar.
type EgressSidecarConfig struct {
	// Token is the Proxy-Authorization secret; the same value is embedded in the
	// scan's HTTPS_PROXY URL so the scan can authenticate to the sidecar.
	Token string
	// Allow is the egress allowlist handed to the sidecar (the same list the
	// host proxy would enforce, so the allowlist has a single source of truth).
	Allow []string
	// APIPort is the host skill API port; the sidecar restricts the host alias
	// to it, matching the host proxy's APIPort.
	APIPort string
	// GatewayIP is the default-network host-gateway IPv4 the sidecar dials to
	// reach the host skill API. Required: an empty value means the sidecar
	// cannot reach the host, so setupHardenedNetwork fails the scan closed.
	GatewayIP string
}

// hardenedNetworkPrefix is the common prefix used to name the per-scan
// --internal networks. SweepOrphanHardenedNetworks relies on it
// to identify residue from crashed scrutineer processes.
const hardenedNetworkPrefix = "scrutineer-hardened-"

// hardenedNetworkName returns the network name dedicated to a
// single hardened scan. Uniqueness per scan is the whole isolation
// property: two scans must never produce the same name.
func hardenedNetworkName(scanID uint) string {
	return fmt.Sprintf("%s%d", hardenedNetworkPrefix, scanID)
}

// proxySidecarPrefix names the per-scan egress proxy sidecar containers.
// SweepOrphanProxySidecars relies on it to find residue from crashed
// scrutineer processes, mirroring hardenedNetworkPrefix for the networks.
const proxySidecarPrefix = "scrutineer-proxy-"

// proxySidecarPort is the fixed port the egress proxy sidecar listens on inside
// its own network namespace. It does not collide with anything: each sidecar is
// alone in its container, and the scan reaches it by its --internal IP (e.g.
// 10.89.1.2:3128), not on a shared host port.
const proxySidecarPort = "3128"

// proxySidecarReadyTimeout bounds how long verifyHardenedNetwork waits for the
// sidecar to become reachable. The sidecar holds its listener until it confirms
// it can reach the host skill API (up to its own readiness timeout), so this
// must exceed that; on expiry the scan is refused (fail closed).
const proxySidecarReadyTimeout = 30 * time.Second

// proxySidecarReadyPoll is the gap between sidecar-reachability probes while
// waiting for it to come up.
const proxySidecarReadyPoll = 1 * time.Second

// proxySidecarName returns the container name for a single hardened scan's
// egress proxy sidecar. Uniqueness per scan keeps concurrent scans' sidecars and
// the networks they pin from colliding.
func proxySidecarName(scanID uint) string {
	return fmt.Sprintf("%s%d", proxySidecarPrefix, scanID)
}

// usesEgressSidecar reports whether this scan routes egress through a proxy
// sidecar container instead of the in-process host proxy. True only for rootless
// podman under --hardened: there the per-scan --internal network cannot reach
// the host proxy across the pasta/slirp4netns boundary (see docs/podman.md), so
// the proxy must live on the network with the scan. docker and
// rootful podman keep the host-proxy path unchanged, and so does Apple's
// container -- its CLI has neither `--network podman` nor `network connect`, so it
// must not take the sidecar path even though it still needs the per-scan
// --internal verification (see needsEgressSidecar vs needsHardenedNetVerify).
func (d ContainerRunner) usesEgressSidecar() bool {
	return d.Hardened && d.Runtime.needsEgressSidecar()
}

func (d ContainerRunner) image() string {
	if d.Image != "" {
		return d.Image
	}
	return DefaultRunnerImage
}

// redactURLUserinfo strips embedded credentials from a URL before logging.
// Anthropic-compatible base URLs sometimes carry a token in userinfo
// (https://user:tok@proxy/...); we still want to surface that auth was
// configured, so the username is replaced with "REDACTED" rather than
// dropped entirely. Inputs that fail to parse as URLs or that carry no
// userinfo round-trip unchanged.
func redactURLUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("REDACTED")
	return u.String()
}

// proxyURLWithHost rewrites the host of a proxy URL, keeping its scheme, the
// proxy-token userinfo, and port. Apple --hardened scans reach the host proxy
// through the per-scan --internal network's gateway rather than the default
// network's, and Apple has no --add-host alias to repoint, so the gateway IP is
// baked into the proxy env here. Returns the input unchanged if it does not
// parse.
func proxyURLWithHost(proxyURL, host string) string {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return proxyURL
	}
	u.Host = net.JoinHostPort(host, u.Port())
	return u.String()
}

// HardenedWorkspaceCapBytes caps the per-scan workspace footprint that the
// hardening modes (--hardened and --hardened-runtime-only) tolerate after
// clone completes. This is a post-clone check, not a clone-time bound: a clone
// that already exceeds disk capacity fails earlier on its own, so this cap is
// what hardening will agree to scan, not a guarantee against disk fill during
// clone (use OS-level disk quotas for that). It is a pure host-side size check
// with no container/network/rootless dependency, which is why it applies under
// --hardened-runtime-only too. 2 GiB leaves room for genuinely large
// legitimate repos.
const HardenedWorkspaceCapBytes int64 = 2 << 30

// RunSkill runs a skill inside an ephemeral container. The whole workspace
// (clone + staged .claude/skills + context.json + output) is mounted at
// /work read-write so claude can read the skill files and write its output.
// Egress is routed through scrutineer's allowlisting proxy on the host;
// see EgressProxy. tmpfs/cap-drop rules mirror the local runner's intent.
func (d ContainerRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
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

	profile, image := d.resolveProfile(ctx, sj.Profile, src, sj.SubPath, emit)
	if sj.RequiresProfile != "" && profile != sj.RequiresProfile {
		got := profile
		if got == "" {
			got = "default"
		}
		return SkillResult{Commit: commit, Profile: profile}, fmt.Errorf("skill %q requires profile %q, resolved %q", sj.Name, sj.RequiresProfile, got)
	}
	d.injectProfileGuide(profile, absWork, emit)

	hnet, cleanupNetwork, err := d.setupHardenedNetwork(sj, image)
	if err != nil {
		return SkillResult{Commit: commit, Profile: profile}, err
	}
	// Capture the sidecar's egress decisions (allowlist denials) into the scan
	// record before teardown removes the ephemeral sidecar.
	defer d.teardownHardenedScan(sj, hnet, cleanupNetwork, emit)

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	// the runtime treats a non-absolute -v source as a named volume (which
	// rejects '/'), so the config dir must be absolutised like absWork.
	var absConfig string
	if sj.ClaudeConfigDir != "" {
		absConfig, _ = filepath.Abs(sj.ClaudeConfigDir)
		if err := os.MkdirAll(absConfig, dirPerm); err != nil {
			return SkillResult{Commit: commit, Profile: profile}, fmt.Errorf("create claude config dir: %w", err)
		}
	}
	runBase := d.buildRunArgs(absWork, image, hnet, absConfig)

	logLine := "$ " + d.Runtime.bin() + " run --rm " + image + " <skill:" + sj.Name + ">"
	if d.AnthropicBaseURL != "" {
		logLine += " [ANTHROPIC_BASE_URL=" + redactURLUserinfo(d.AnthropicBaseURL) + "]"
	}
	emit(Event{Kind: KindText, Text: logLine})

	h := d.harness()
	accountErrText := ""
	var rateLimitReset *RateLimitInfo
	wrappedEmit := func(e Event) {
		accountErrText = preferAccountErrText(accountErrText, h.AccountErrorText(e.Text))
		if e.Kind == KindRateLimit && e.RateLimit != nil {
			rateLimitReset = preferRateLimitReset(rateLimitReset, e.RateLimit)
		}
		emit(e)
	}
	hitMaxTurns, sessionID, waitErr := d.runContainerOnce(ctx, runBase, sj, wrappedEmit)

	if waitErr != nil && sj.ResumeSessionID != "" && sessionID == "" && accountErrText == "" {
		if sj.ResumePrompt != "" {
			emit(Event{Kind: KindText, Text: "resume of session " + sj.ResumeSessionID + " failed; " + resumePromptNoFreshFallbackText})
			return SkillResult{Commit: commit, Profile: profile}, fmt.Errorf("%s exited: %w", d.Runtime.bin(), waitErr)
		}
		// The resume produced no session event, so claude could not load the
		// saved conversation (gone from the mounted store). Restart fresh in
		// the same /work + config mount so the retry lineage isn't wedged on
		// a dead session id.
		emit(Event{Kind: KindText, Text: "resume of session " + sj.ResumeSessionID + " failed; restarting fresh"})
		fresh := sj
		fresh.ResumeSessionID = ""
		hitMaxTurns, sessionID, waitErr = d.runContainerOnce(ctx, runBase, fresh, wrappedEmit)
	}

	res := SkillResult{Commit: commit, Profile: profile, SessionID: sessionID}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	if waitErr != nil {
		if hitMaxTurns {
			return res, &MaxTurnsReachedError{}
		}
		if accountErrText != "" {
			return res, &ClaudeAccountError{Detail: accountErrText, ResetAt: resumableReset(accountErrText, rateLimitReset)}
		}
		return res, fmt.Errorf("%s exited: %w", d.Runtime.bin(), waitErr)
	}
	return res, nil
}

// runContainerOnce launches one container for the given skill job, appending
// the in-container `claude` command to runBase, streaming its output
// through emit, and reporting the wait error, whether the run hit the
// max-turns cap, and the session id from the init event (empty when no init
// event arrived, e.g. a --resume that could not find the conversation).
func (d ContainerRunner) runContainerOnce(ctx context.Context, runBase []string, sj SkillJob, emit func(Event)) (hitMaxTurns bool, sessionID string, waitErr error) {
	h := d.harness()
	harnessArgs := append([]string{h.Binary()}, h.Args(sj, d.Effort, d.MaxTurns)...)
	runArgs := append(append([]string{}, runBase...), harnessArgs...)

	cmd := exec.CommandContext(ctx, d.Runtime.bin(), runArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = os.Environ()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return false, "", fmt.Errorf("start container: %w", err)
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
	h.ParseStream(stdout, wrappedEmit)
	waitErr = cmd.Wait()
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	return hitMaxTurns, sessionID, waitErr
}

// buildRunArgs assembles the container run flags for a skill invocation.
// Returns the args up to and including the image name; the caller appends
// the in-container command. Split out of RunSkill to keep its cognitive
// complexity manageable as new toggles (hardened mode, proxy, profiles)
// accumulate.
func (d ContainerRunner) buildRunArgs(absWork, image string, hnet hardenedNet, claudeConfigDir string) []string {
	gwTarget := "host-gateway"
	if d.Hardened {
		// setupHardenedNetwork resolved the gateway once against this per-scan
		// network and passed it in (no re-probe here, so this stays a pure
		// function). An empty result falls through to the literal host-gateway
		// alias.
		if hnet.gatewayIP != "" {
			gwTarget = hnet.gatewayIP
		}
	} else if d.HostGatewayIP != "" {
		gwTarget = d.HostGatewayIP
	}
	args := d.Runtime.runArgs(
		"--rm",
		"--cap-drop", "ALL",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "HOME=/tmp",
		"-e", "SEMGREP_SEND_METRICS=off",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"-v", bindMount(absWork, "/work", d.SELinuxRelabel),
		"-w", "/work",
	)
	// Harness-specific env: model-API credential, base URL, and the
	// harness's own telemetry / autoupdate suppressors.
	for _, e := range d.harness().Env(d.AnthropicBaseURL) {
		args = append(args, "-e", e)
	}
	if d.Runtime.supportsHostGatewayAddHost() {
		args = append(args, "--add-host", HostGatewayAlias+":"+gwTarget)
	}
	if d.Runtime.needsKeepID() {
		// Rootless podman remaps --user uid:gid through /etc/subuid, so writes
		// to the bind mounts (/work output and the /claude-config resume store)
		// would land owned by a subordinate uid. keep-id maps the container
		// user back to the invoking host uid so output stays host-owned.
		args = append(args, "--userns=keep-id")
	}
	if claudeConfigDir != "" {
		// Persist the harness's resumable session store outside the
		// container. Without this it lands in the /tmp tmpfs and dies
		// with the container, so a retry could not resume the agent
		// loop. The bind mount stays writable even under hardened
		// mode's --read-only rootfs. The /claude-config mountpoint name
		// is historical; only the env var that points the harness at it
		// varies (CLAUDE_CONFIG_DIR, CODEX_HOME, OPENCODE_CONFIG_DIR).
		args = append(args, "-v", bindMount(claudeConfigDir, "/claude-config", d.SELinuxRelabel))
		for _, e := range d.harness().StateEnv("/claude-config") {
			args = append(args, "-e", e)
		}
	}
	if d.Hardened || d.HardenedRuntimeOnly {
		// Read-only rootfs + no-new-privileges close the residual paths a
		// hostile skill could use to escalate inside the container. /work
		// stays writable (skill output) and /tmp is the tmpfs declared above
		// with HOME=/tmp redirecting claude session storage. These are pure
		// container options with no network dependency, so --hardened-rootless-
		// runtime applies them under the default network -- unlike the
		// --internal network below, which rootless podman can't route to the
		// host proxy. --cap-drop ALL and the non-root --user are already set
		// unconditionally above, in every mode.
		args = append(args,
			"--read-only",
		)
		if d.Runtime.supportsNoNewPrivileges() {
			args = append(args, "--security-opt", "no-new-privileges")
		}
	}
	if d.Hardened {
		// The per-scan --internal network is the egress-enforcement half of
		// --hardened, kept separate from the container hardening above because
		// it does not work under rootless podman (the startup verification
		// fails closed when it can't reach the host proxy here; see
		// docs/podman.md). --hardened-runtime-only deliberately omits it.
		args = append(args, "--network", hnet.name)
	}
	// In sidecar mode the proxy is a per-scan container reached by name on the
	// --internal network, so the proxy URL is built per scan from the sidecar's
	// endpoint rather than the process-wide host-proxy URL.
	proxyURL := d.ProxyURL
	if hnet.proxyEndpoint != "" {
		proxyURL = ProxyURLForEndpoint(d.Egress.Token, hnet.proxyEndpoint)
	}
	// Apple has no --add-host, so the proxy env must name the per-scan
	// gateway directly. Under --hardened the runner attaches to its own
	// --internal network, whose gateway differs from the default network the
	// startup ProxyURL was built for, so rewrite the host to this scan's
	// gateway. docker/podman instead keep a constant host.docker.internal
	// that --add-host repoints per scan.
	if d.Runtime.Bin == runtimeApple && d.Hardened && hnet.gatewayIP != "" {
		proxyURL = proxyURLWithHost(d.ProxyURL, hnet.gatewayIP)
	}
	if proxyURL != "" {
		args = append(args,
			"-e", "HTTPS_PROXY="+proxyURL,
			"-e", "HTTP_PROXY="+proxyURL,
			"-e", "ALL_PROXY="+proxyURL,
			"-e", "NO_PROXY=",
		)
	} else if !d.Hardened {
		args = append(args, "--network", "none")
	}
	return append(args, "--", image)
}

// resolveProfile picks the runner image for this scan. When requested
// is non-empty, the operator's choice wins (and "default" forces the
// default image); when empty, scrutineer probes the clone with `brief`
// to auto-select. Any failure along the way falls back to the default
// image with a log line so a missing profile never blocks a scan.
func (d ContainerRunner) resolveProfile(ctx context.Context, requested, src, subPath string, emit func(Event)) (string, string) {
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
		srcDir := src
		if subPath != "" {
			srcDir = filepath.Join(src, subPath)
		}
		p = DetectProfile(ctx, d.Runtime, defaultImg, srcDir, d.SELinuxRelabel)
		if p.IsDefault() {
			return "", defaultImg
		}
	}
	img, err := p.EnsureImage(ctx, d.Runtime, d.ProfilesDir, defaultImg, emit)
	if err != nil {
		emit(Event{Kind: KindText, Text: "profile: " + p.Name + " build failed, using default: " + err.Error()})
		return "", defaultImg
	}
	emit(Event{Kind: KindText, Text: "profile: " + p.Name + " (" + img + ")"})
	return p.Name, img
}

// profileGuideFileMode is the mode used when copying a profile's
// PROFILE.md into the workspace as CLAUDE.md. The workspace already
// belongs to the host user (the container runner mounts it as that uid),
// so a plain 0644 keeps it readable by the agent without surprises.
const profileGuideFileMode os.FileMode = 0o644

// checkHardenedWorkspace returns an error when a hardening mode is on and the
// cloned workspace exceeds HardenedWorkspaceCapBytes. It applies under both
// --hardened and --hardened-runtime-only (the cap is a host-side size check,
// not network-coupled), and is a no-op for plain default scans.
func (d ContainerRunner) checkHardenedWorkspace(workRoot string) error {
	if !d.Hardened && !d.HardenedRuntimeOnly {
		return nil
	}
	size, err := dirSize(workRoot)
	if err != nil {
		return fmt.Errorf("workspace size check: %w", err)
	}
	if size > HardenedWorkspaceCapBytes {
		return fmt.Errorf("workspace exceeds the %d-byte hardening cap after clone (got %d)", HardenedWorkspaceCapBytes, size)
	}
	return nil
}

// injectProfileGuide copies the resolved profile's PROFILE.md into the
// workspace as CLAUDE.md so claude-code auto-loads it as project memory
// ahead of the skill prompt. A workspace copy (rather than a bind mount)
// avoids Docker Desktop's refusal to materialise a sub-path mountpoint
// inside another bind mount. No-ops when the profile has no guide;
// failures are reported via emit but never block the scan.
func (d ContainerRunner) injectProfileGuide(profile, absWork string, emit func(Event)) {
	guide := d.profileGuidePath(profile)
	if guide == "" {
		return
	}
	name := d.harness().GuideFilename()
	target := filepath.Join(absWork, name)
	data, err := os.ReadFile(guide)
	if err != nil {
		emit(Event{Kind: KindText, Text: "profile guide: read " + guide + ": " + err.Error()})
		return
	}
	if err := os.WriteFile(target, data, profileGuideFileMode); err != nil {
		emit(Event{Kind: KindText, Text: "profile guide: write " + target + ": " + err.Error()})
		return
	}
	emit(Event{Kind: KindText, Text: "profile guide: " + guide + " -> /work/" + name})
}

// SkillDir delegates to the harness so the worker stages SKILL.md
// where this runner's agent CLI will discover it.
func (d ContainerRunner) SkillDir(workRoot, name string) string {
	return d.harness().SkillDir(workRoot, name)
}

// harness returns the agent CLI to exec inside the container, defaulting
// to claude-code when none is set so the zero ContainerRunner{} keeps its
// historical behaviour.
func (d ContainerRunner) harness() Harness { //nolint:ireturn // nil-default accessor; the field IS the interface
	if d.Harness != nil {
		return d.Harness
	}
	return ClaudeHarness{}
}

// profileGuidePath returns the profile's on-disk PROFILE.md if present.
// The caller mounts it at the agent's project-memory path (CLAUDE.md
// for claude-code) so it's auto-loaded before the skill prompt runs.
// The on-disk name stays agent-neutral to support a future codex runner
// reading the same file as AGENTS.md.
func (d ContainerRunner) profileGuidePath(profile string) string {
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

// ResolveHostGatewayIPv4 returns the IPv4 address that the runtime's
// host-gateway maps to on the given network. An empty network probes
// the default bridge, which is what scrutineer uses outside hardened
// mode. The hardened path passes its --internal network name so the
// resolved gateway matches the network the runner actually attaches to.
// Both docker and podman add IPv4 and IPv6 /etc/hosts entries for
// host-gateway; tools that prefer IPv6 (like Node's fetch) fail when the
// server only listens on 127.0.0.1. Using the explicit IPv4 address avoids
// the dual-stack ambiguity.
func ResolveHostGatewayIPv4(rt ContainerRuntime, image, network string) string {
	if rt.Bin == runtimeApple {
		return resolveAppleHostGatewayIPv4(rt, image, network)
	}
	args := rt.runArgs("--rm", "--add-host", "hgw:host-gateway")
	if network != "" {
		args = append(args, "--network", network)
	}
	args = append(args, "--entrypoint", "grep", "--", image, "hgw", "/etc/hosts")
	out, err := exec.Command(rt.bin(), args...).Output()
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

func resolveAppleHostGatewayIPv4(rt ContainerRuntime, image, network string) string {
	if image == "" {
		return ""
	}
	const script = `awk '$2 == "00000000" { print $3; exit }' /proc/net/route`
	args := rt.runArgs("--rm")
	if network != "" {
		args = append(args, "--network", network)
	}
	args = append(args, "--entrypoint", "sh", "--", image, "-c", script)
	out, err := exec.Command(rt.bin(), args...).Output()
	if err != nil {
		return ""
	}
	return routeGatewayIPv4(out)
}

func routeGatewayIPv4(out []byte) string {
	// resolveAppleHostGatewayIPv4's awk (`$2 == "00000000" { print $3 }`) already
	// isolates the default route's gateway column, so the only shape we see is a
	// single hex field per line.
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if ip := routeHexIPv4(strings.TrimSpace(line)); ip != "" {
			return ip
		}
	}
	return ""
}

func routeHexIPv4(field string) string {
	const ipv4HexLen = 8 // a 32-bit IPv4 address is 8 hex digits
	if len(field) != ipv4HexLen {
		return ""
	}
	n, err := strconv.ParseUint(field, 16, 32)
	if err != nil || n == 0 {
		return ""
	}
	// /proc/net/route stores the gateway little-endian, so shift each octet out.
	return net.IPv4(byte(n), byte(n>>8), byte(n>>16), byte(n>>24)).String() //nolint:mnd // octet shifts
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

// hardenedNetworkCreateArgs builds the `network create` args for the per-scan
// --internal network. --disable-dns is load-bearing: a sidecar later connected to
// this network must not inherit its aardvark resolver, which on an --internal
// network cannot forward external lookups and answers NXDOMAIN first, shadowing
// the sidecar's working bridge resolver. The scan dials the sidecar by IP, so the
// network needs no name resolution of its own.
func hardenedNetworkCreateArgs(name string) []string {
	return []string{"network", "create", "--internal", "--disable-dns", "--", name}
}

// EnsureHardenedNetwork creates an internal container network with the
// given name if it does not already exist. --internal blocks routes
// to external networks; the container can still reach the host via
// the bridge gateway, so the egress proxy on the host remains the only
// path out. The function is idempotent: a retry of a scan that crashed
// after the network was created (but before the post-scan rm ran) will
// reuse the existing network instead of failing.
func EnsureHardenedNetwork(rt ContainerRuntime, name string) error {
	if out, err := exec.Command(rt.bin(), "network", "inspect", "--", name).Output(); err == nil && len(out) > 0 {
		return nil
	}
	cmd := exec.Command(rt.bin(), hardenedNetworkCreateArgs(name)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s network create --internal %s: %w: %s", rt.bin(), name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// hardenedNet bundles a per-scan --internal network name with the host-gateway
// IPv4 resolved against it. setupHardenedNetwork resolves the gateway once and
// threads it through both verifyHardenedNetwork and buildRunArgs, so a
// hardened scan probes for it a single time instead of once per consumer. The
// zero value (both fields "") is the non-hardened case.
type hardenedNet struct {
	name      string // per-scan --internal network name
	gatewayIP string // host-gateway IPv4 for that network; "" if unresolved
	// proxyEndpoint is the IP:port the scan reaches the egress proxy sidecar at
	// (the sidecar's address on the --internal network, e.g. 10.89.1.2:3128). The
	// scan dials it by IP because the --internal network runs no DNS (see
	// EnsureHardenedNetwork). "" when there is no sidecar -- the host-proxy path --
	// in which case egress goes through d.ProxyURL via the gateway.
	proxyEndpoint string
	// proxyName is the sidecar's container name, used for status and log lookups
	// (the scan addresses the sidecar by IP via proxyEndpoint, not by name).
	proxyName string
}

// setupHardenedNetwork creates the per-scan --internal network for a hardened
// scan, resolves its host-gateway once, and (on rootless podman) verifies it
// actually isolates egress before the scan runs (fail closed). It returns the
// network + resolved gateway and a cleanup func the caller must defer to remove
// the network. Outside hardened mode it is a no-op with a zero hardenedNet and a
// no-op cleanup. On any error the network it created (if any) is already torn
// down, so the returned cleanup is always safe to defer.
func (d ContainerRunner) setupHardenedNetwork(sj SkillJob, image string) (hardenedNet, func(), error) {
	noop := func() {}
	if !d.Hardened {
		return hardenedNet{}, noop, nil
	}
	if sj.ScanID == 0 {
		return hardenedNet{}, noop, fmt.Errorf("hardened mode requires SkillJob.ScanID; refusing to share %s0 across scans", hardenedNetworkPrefix)
	}
	network := hardenedNetworkName(sj.ScanID)
	if err := EnsureHardenedNetwork(d.Runtime, network); err != nil {
		return hardenedNet{}, noop, fmt.Errorf("create hardened network: %w", err)
	}
	cleanup := func() { _ = exec.Command(d.Runtime.bin(), "network", "rm", "--", network).Run() }
	// Resolve the host-gateway once against the network just created; reused by
	// both the verification probe and the real run (for docker/podman an empty
	// result falls through to the literal host-gateway alias downstream).
	hn := hardenedNet{name: network, gatewayIP: ResolveHostGatewayIPv4(d.Runtime, image, network)}

	// Apple has no host-gateway alias to fall back on: the per-scan --internal
	// network has its own gateway and the proxy env must name its IP, so an
	// unresolved gateway means the scan cannot reach the egress proxy. Fail
	// closed rather than run a container with no working egress path.
	if d.Runtime.Bin == runtimeApple && hn.gatewayIP == "" {
		cleanup()
		return hardenedNet{}, noop, fmt.Errorf("hardened mode: could not resolve the Apple --internal network gateway for %q; cannot route to the egress proxy", network)
	}

	// Under rootless podman the scan cannot reach the host proxy across the
	// --internal boundary, so the proxy runs as a sidecar on this network. Start
	// it before verification; the sidecar must be torn down before the network
	// (a network with an attached container will not delete).
	if d.usesEgressSidecar() {
		endpoint, sidecarCleanup, err := d.startProxySidecar(sj, network)
		if err != nil {
			cleanup()
			return hardenedNet{}, noop, fmt.Errorf("start egress proxy sidecar: %w", err)
		}
		netCleanup := cleanup
		cleanup = func() {
			sidecarCleanup()
			netCleanup()
		}
		hn.proxyEndpoint = endpoint
		hn.proxyName = proxySidecarName(sj.ScanID)
	}

	// docker's bridge --internal is trusted, and so is rootful podman's (netavark
	// + a bridge in the host netns, gateway on the host -- docker's model).
	// Rootless podman and Apple need per-scan proof; see needsHardenedNetVerify.
	if d.Runtime.needsHardenedNetVerify() {
		if err := d.verifyHardenedNetwork(hn, image); err != nil {
			cleanup()
			return hardenedNet{}, noop, fmt.Errorf("hardened network verification: %w", err)
		}
	}
	return hn, cleanup, nil
}

// startProxySidecar launches the egress proxy as a detached container on the
// default (egress) network, then connects it to the per-scan --internal network
// so the scan can reach it. It returns the host:port the scan points HTTPS_PROXY
// at and a cleanup that force-removes the container. The sidecar self-gates its
// listener on reaching the host skill API (see runProxy / WaitHostAPIReachable),
// so a successful proxy-reach probe in verifyHardenedNetwork transitively proves
// the whole scan -> sidecar -> host-API chain.
func (d ContainerRunner) startProxySidecar(sj SkillJob, network string) (endpoint string, cleanup func(), err error) {
	noop := func() {}
	if d.Egress.GatewayIP == "" {
		// Without the host-gateway IPv4 the sidecar cannot reach the host skill
		// API; refuse rather than start a sidecar that would 502 every API call.
		return "", noop, fmt.Errorf("no host-gateway IPv4 resolved for the egress sidecar (podman >= 4.7 and a working rootless network backend are required)")
	}
	name := proxySidecarName(sj.ScanID)
	rmName := func() { _ = exec.Command(d.Runtime.bin(), "rm", "-f", "--", name).Run() }
	// A residual sidecar from a crashed scan with this id would clash on the name
	// and pin the network; remove it first (no-op when absent).
	rmName()

	if out, e := exec.Command(d.Runtime.bin(), d.proxySidecarRunArgs(name)...).CombinedOutput(); e != nil {
		rmName() // a failed `run -d` can still leave a created container behind
		return "", noop, fmt.Errorf("%s run sidecar: %w: %s", d.Runtime.bin(), e, strings.TrimSpace(string(out)))
	}

	if out, e := exec.Command(d.Runtime.bin(), "network", "connect", "--", network, name).CombinedOutput(); e != nil {
		rmName()
		return "", noop, fmt.Errorf("%s network connect %s: %w: %s", d.Runtime.bin(), network, e, strings.TrimSpace(string(out)))
	}
	// The --internal network runs no DNS, so the scan must reach the sidecar by
	// its address on that network rather than by name.
	ip, e := d.sidecarNetworkIP(name, network)
	if e != nil {
		rmName()
		return "", noop, fmt.Errorf("resolve egress sidecar address on %s: %w", network, e)
	}
	return net.JoinHostPort(ip, proxySidecarPort), rmName, nil
}

// sidecarNetworkIP returns the sidecar's IP on the per-scan --internal network.
// The scan addresses the sidecar by this IP because that network is created with
// --disable-dns (its aardvark resolver would otherwise NXDOMAIN the sidecar's own
// external lookups), so a container name would not resolve there.
func (d ContainerRunner) sidecarNetworkIP(name, network string) (string, error) {
	format := fmt.Sprintf(`{{(index .NetworkSettings.Networks %q).IPAddress}}`, network)
	out, err := exec.Command(d.Runtime.bin(), "inspect", "--format", format, "--", name).Output()
	if err != nil {
		return "", fmt.Errorf("%s inspect %s: %w", d.Runtime.bin(), name, err)
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("sidecar %q has no address on network %q", name, network)
	}
	return ip, nil
}

// proxySidecarRunArgs builds the detached `run` args for the egress proxy
// sidecar: locked down (cap-drop ALL, read-only rootfs, no-new-privileges, a
// small noexec /tmp tmpfs), on the default egress network with the host-gateway
// alias wired to the resolved IPv4 so it reaches the host skill API, running
// `scrutineer proxy` with its config passed via env. It deliberately runs the
// DEFAULT runner image (d.image()), which is guaranteed to carry the scrutineer
// binary, not the per-scan profile image. It is NOT attached to the --internal
// network here; startProxySidecar connects that leg after the container exists.
// No --rm, so a sidecar that exits on an unreachable host API lingers long
// enough for verifyHardenedNetwork to capture its logs.
func (d ContainerRunner) proxySidecarRunArgs(name string) []string {
	args := []string{
		"run", "-d",
		"--name", name,
		// The sidecar is dual-homed: startProxySidecar attaches the per-scan
		// --internal network to it after launch with `podman network connect`,
		// which only works on a netavark bridge. The rootless default (pasta)
		// rejects it ("pasta is not supported: invalid network mode"), so pin the
		// default bridge for the egress leg rather than inheriting pasta.
		"--network", "podman",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
		"--add-host", HostGatewayAlias + ":" + d.Egress.GatewayIP,
	}
	for _, e := range EgressSidecarEnv(d.Egress, ":"+proxySidecarPort) {
		args = append(args, "-e", e)
	}
	return append(args, "--", d.image(), "scrutineer", "proxy")
}

// EgressSidecarEnv returns the SCRUTINEER_PROXY_* environment assignments the
// container runner injects into the egress proxy sidecar. It is the single
// source of truth for the host<->sidecar env contract: the runner sets these
// (proxySidecarRunArgs) and `scrutineer proxy` reads them back, so both sides
// must agree on the names. listen is the full listen address (e.g. ":3128").
func EgressSidecarEnv(cfg EgressSidecarConfig, listen string) []string {
	return []string{
		"SCRUTINEER_PROXY_TOKEN=" + cfg.Token,
		"SCRUTINEER_PROXY_ALLOW=" + strings.Join(cfg.Allow, ","),
		"SCRUTINEER_PROXY_API_HOST=" + cfg.GatewayIP,
		"SCRUTINEER_PROXY_API_PORT=" + cfg.APIPort,
		"SCRUTINEER_PROXY_LISTEN=" + listen,
	}
}

// teardownHardenedScan runs at the end of a hardened scan: it forwards the
// egress proxy sidecar's noteworthy logs (allowlist denials, failures) into the
// scan record before tearing everything down, so those egress decisions survive
// the ephemeral sidecar instead of vanishing with it. cleanupNetwork removes the
// sidecar and then its network. Deferred by RunSkill; a no-sidecar scan just
// runs cleanupNetwork.
func (d ContainerRunner) teardownHardenedScan(sj SkillJob, hnet hardenedNet, cleanupNetwork func(), emit func(Event)) {
	if hnet.proxyEndpoint != "" {
		d.emitSidecarLogs(proxySidecarName(sj.ScanID), emit)
	}
	cleanupNetwork()
}

// emitSidecarLogs captures the egress proxy sidecar's logs (while it still
// exists) and forwards the noteworthy lines into the scan's event stream.
// Best-effort: an already-gone sidecar or a logs failure yields nothing.
func (d ContainerRunner) emitSidecarLogs(name string, emit func(Event)) {
	out, err := exec.Command(d.Runtime.bin(), "logs", "--", name).CombinedOutput()
	if err != nil {
		return
	}
	emitProxyLogLines(out, emit)
}

// emitProxyLogLines forwards the WARN/ERROR lines of a sidecar's log output into
// the scan record (prefixed "egress-proxy:"), dropping routine INFO readiness
// chatter so a clean scan stays quiet. The sidecar logs allowlist denials and
// failures at WARN/ERROR, so this is what preserves a hardened scan's egress
// decisions for the operator.
func emitProxyLogLines(out []byte, emit func(Event)) {
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" && noteworthyProxyLogLine(line) {
			emit(Event{Kind: KindText, Text: "egress-proxy: " + line})
		}
	}
}

// noteworthyProxyLogLine reports whether a sidecar log line is worth surfacing
// into the scan record -- denials and failures (WARN/ERROR), not routine INFO.
func noteworthyProxyLogLine(line string) bool {
	return strings.Contains(line, "level=WARN") || strings.Contains(line, "level=ERROR")
}

// VerifyProxyBinary smoke-tests that the runner image carries the scrutineer
// binary the egress proxy sidecar runs (`scrutineer proxy`). A runner image
// without it -- an old cached image, or a custom --runner-image not built from
// Dockerfile.runner -- would otherwise make every rootless --hardened scan fail
// with a cryptic per-scan exec error; this turns that into one clear startup
// failure. It is a no-op when the image is not present locally yet (the first
// scan pulls it and would surface the same issue then), matching VerifyKeepID.
// Only meaningful on the sidecar path; the caller gates on rootless --hardened.
func VerifyProxyBinary(ctx context.Context, rt ContainerRuntime, image string) error {
	if image == "" || !imageExistsLocally(ctx, rt, image) {
		return nil
	}
	out, err := exec.CommandContext(ctx, rt.bin(), "run", "--rm", "--pull", "never",
		"--", image, "scrutineer", "proxy", "-h").CombinedOutput()
	if err != nil {
		return fmt.Errorf("runner image %q is missing the scrutineer binary required for the "+
			"rootless --hardened egress proxy sidecar (rebuild it from Dockerfile.runner): %w: %s",
			image, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// verifyHardenedNetwork fails closed when the per-scan --internal network does
// not deliver the isolation --hardened promises. It is used on podman, where
// rootless network backends (pasta, slirp4netns, netavark) implement --internal
// differently enough from docker's bridge driver that the property must be
// proven, not assumed. Two short-lived probes run on the network:
//
//	(a) a container with no proxy env must FAIL to reach a routable public IP
//	    (a literal address, so a pass means no IP-level egress rather than
//	    merely blocked DNS); and
//	(b) a container must still reach the egress proxy -- the sidecar by its IP on
//	    this network, or the host proxy through the gateway when there is no
//	    sidecar.
//
// Any probe that cannot even run (image won't start, curl missing) is treated
// as a failure: the runner must never fall back to a weaker sandbox silently.
func (d ContainerRunner) verifyHardenedNetwork(hn hardenedNet, image string) error {
	network := hn.name

	out, err := exec.Command(d.Runtime.bin(), d.Runtime.hardenedEgressBlockArgs(network, image)...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("egress-block probe could not run on network %q: %w: %s", network, err, s)
	}
	if strings.Contains(s, "NOCURL") {
		return fmt.Errorf("runner image %q lacks curl, which hardened verification needs", image)
	}
	if !strings.Contains(s, "BLOCKED") {
		return fmt.Errorf("internal network %q did not block external egress (probe output: %q); refusing to run a weaker sandbox than --hardened promises", network, s)
	}

	if hn.proxyEndpoint != "" {
		return d.verifyProxySidecarReachable(hn, image)
	}
	return d.verifyHostProxyReachable(hn, image)
}

// verifyHostProxyReachable runs probe (b) for the host-proxy path: a throwaway
// container on the --internal network, wiring the gateway alias exactly as the
// real run does, must reach the host egress proxy. This is the path docker and
// rootful podman use; under rootless --hardened the sidecar path is used instead
// (verifyProxySidecarReachable).
func (d ContainerRunner) verifyHostProxyReachable(hn hardenedNet, image string) error {
	gwTarget := "host-gateway"
	if hn.gatewayIP != "" {
		gwTarget = hn.gatewayIP
	}
	port, err := proxyPortFromURL(d.ProxyURL)
	if err != nil {
		return fmt.Errorf("parse proxy url: %w", err)
	}
	out, err := exec.Command(d.Runtime.bin(), d.Runtime.hardenedProxyReachArgs(hn.name, gwTarget, port, image)...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("proxy-reach probe could not run on network %q: %w: %s", hn.name, err, s)
	}
	if !strings.Contains(s, "REACHED") {
		return fmt.Errorf("internal network %q cannot reach the host egress proxy at %s:%s (probe output: %q); the only egress path is broken", hn.name, gwTarget, port, s)
	}
	return nil
}

// verifyProxySidecarReachable runs probe (b) for the sidecar path: a throwaway
// container on the --internal network must reach the egress proxy sidecar at its
// --internal IP. The sidecar holds its listener until it has confirmed it can
// reach the host skill API, so reachability here transitively proves the whole
// scan -> sidecar -> host-API chain. It retries because the sidecar may still be
// running that upstream check when verification starts; if the sidecar exits
// first (e.g. the backend never forwards host-gateway to the host loopback), or
// the deadline passes, the error is enriched with the sidecar's logs, which name
// the real cause.
func (d ContainerRunner) verifyProxySidecarReachable(hn hardenedNet, image string) error {
	name := hn.proxyName
	deadline := time.Now().Add(proxySidecarReadyTimeout)
	var last string
	for {
		out, err := exec.Command(d.Runtime.bin(), sidecarReachArgs(hn.name, hn.proxyEndpoint, image)...).CombinedOutput()
		last = strings.TrimSpace(string(out))
		if err == nil && strings.Contains(last, "REACHED") {
			return nil
		}
		// If the sidecar has exited, stop early and surface its logs rather than
		// waiting out the whole deadline -- its stderr names the real cause.
		if !d.sidecarRunning(name) {
			return fmt.Errorf("egress proxy sidecar %q exited before becoming reachable on network %q; sidecar logs: %s", name, hn.name, d.sidecarLogTail(name))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("internal network %q cannot reach the egress proxy sidecar at %s (probe output: %q); sidecar logs: %s", hn.name, hn.proxyEndpoint, last, d.sidecarLogTail(name))
		}
		time.Sleep(proxySidecarReadyPoll)
	}
}

// sidecarRunning reports whether the named sidecar container is still running.
// A non-running sidecar during verification means it gave up reaching the host
// skill API and exited, so verification should fail fast with its logs.
func (d ContainerRunner) sidecarRunning(name string) bool {
	out, err := exec.Command(d.Runtime.bin(), "inspect", "--format", "{{.State.Running}}", "--", name).Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// sidecarLogTail returns the tail of the sidecar's logs for error enrichment.
func (d ContainerRunner) sidecarLogTail(name string) string {
	out, _ := exec.Command(d.Runtime.bin(), "logs", "--tail", "20", "--", name).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "(no logs)"
	}
	return s
}

// hardenedEgressBlockArgs builds the `run` args for probe (a): a container on
// the per-scan --internal network, no proxy env, that must fail to reach a
// routable public IP. A literal IP avoids a false pass from blocked DNS. curl
// absence is reported as NOCURL so the caller can fail closed rather than read
// the curl-not-found exit as "egress blocked". runArgs keeps Apple's
// --progress none out of the probe output.
func (rt ContainerRuntime) hardenedEgressBlockArgs(network, image string) []string {
	const script = `command -v curl >/dev/null 2>&1 || { echo NOCURL; exit 0; }
curl -s -m 5 -o /dev/null http://1.1.1.1 && echo REACHED || echo BLOCKED`
	return rt.runArgs("--rm", "--cap-drop", "ALL", "--network", network,
		"--entrypoint", "sh", "--", image, "-c", script)
}

// hardenedProxyReachArgs builds the `run` args for probe (b): a container on the
// per-scan --internal network that must reach the host egress proxy. curl exit 0
// (the proxy answers, e.g. 407 without auth) means the TCP path to the host is
// open. docker/podman wire the host-gateway alias with --add-host exactly as the
// real run does; Apple's CLI has no --add-host, so the probe targets the
// resolved gateway IP directly -- the same address buildRunArgs points the proxy
// env at for an Apple hardened scan.
func (rt ContainerRuntime) hardenedProxyReachArgs(network, gatewayIP, proxyPort, image string) []string {
	args := rt.runArgs("--rm", "--cap-drop", "ALL", "--network", network)
	var target string
	if rt.supportsHostGatewayAddHost() {
		args = append(args, "--add-host", HostGatewayAlias+":"+gatewayIP)
		target = "http://" + HostGatewayAlias + ":" + proxyPort + "/"
	} else {
		target = "http://" + net.JoinHostPort(gatewayIP, proxyPort) + "/"
	}
	script := "curl -s -m 5 -o /dev/null " + target + " && echo REACHED || echo UNREACHABLE"
	return append(args, "--entrypoint", "sh", "--", image, "-c", script)
}

// sidecarReachArgs builds the `run` args for the sidecar variant of probe (b): a
// throwaway container on the per-scan --internal network that must reach the
// egress proxy sidecar at endpoint (its IP:port on that network; the network runs
// no DNS, so no name resolution or --add-host is needed). curl exit 0 (the proxy
// answers, e.g. 407 without auth) means the in-network path to the sidecar is
// open, which by the sidecar's readiness gate also means the host API is
// reachable through it.
func sidecarReachArgs(network, endpoint, image string) []string {
	target := "http://" + endpoint + "/"
	script := "curl -s -m 5 -o /dev/null " + target + " && echo REACHED || echo UNREACHABLE"
	return []string{
		"run", "--rm", "--cap-drop", "ALL", "--network", network,
		"--entrypoint", "sh", "--", image, "-c", script,
	}
}

// proxyPortFromURL extracts the port from a proxy URL of the shape ProxyURL
// produces (http://user:tok@HOST:PORT).
func proxyPortFromURL(proxyURL string) (string, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}
	if u.Port() == "" {
		return "", fmt.Errorf("no port in proxy url %q", proxyURL)
	}
	return u.Port(), nil
}

// SweepOrphanHardenedNetworks removes per-scan hardened networks
// left over by previous scrutineer processes (typically after a crash
// mid-scan). The runtime refuses to remove a network that still has
// containers attached, so a concurrently running scan from another
// scrutineer instance is safe from this sweep. Returns the number of
// networks actually removed; rm failures are intentionally swallowed
// since a busy network is exactly what we want to leave alone.
func SweepOrphanHardenedNetworks(rt ContainerRuntime) (int, error) {
	out, err := exec.Command(rt.bin(), networkListNamesArgs(rt)...).Output()
	if err != nil {
		return 0, fmt.Errorf("%s network list: %w", rt.bin(), err)
	}
	removed := 0
	for _, n := range parseHardenedNetworkNames(out) {
		if err := exec.Command(rt.bin(), "network", "rm", "--", n).Run(); err == nil {
			removed++
		}
	}
	return removed, nil
}

// networkListNamesArgs returns the args that list one network name per line.
// docker/podman support `network ls --filter name= --format {{.Name}}`; Apple's
// CLI has neither flag, so it lists every name with `network list --quiet`.
// parseHardenedNetworkNames re-applies the prefix filter for all runtimes (the
// docker/podman --filter name= is only a substring match), so listing every
// Apple network and filtering in Go is equivalent.
func networkListNamesArgs(rt ContainerRuntime) []string {
	if rt.Bin == runtimeApple {
		return []string{"network", "list", "--quiet"}
	}
	return []string{"network", "ls", "--filter", "name=" + hardenedNetworkPrefix, "--format", "{{.Name}}"}
}

// parseHardenedNetworkNames extracts strict-prefix matches from the
// output of the runtime's network listing. The docker/podman --filter
// name= is a substring match (and Apple's --quiet is unfiltered), so we
// re-check the prefix here to avoid touching a user-named network that
// happens to contain the substring.
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

// SweepOrphanProxySidecars force-removes egress proxy sidecar containers left
// behind by a previous scrutineer process (name prefix proxySidecarPrefix),
// typically after a crash mid-scan. A detached sidecar outlives its parent and
// pins its per-scan --internal network, so SweepOrphanHardenedNetworks cannot
// reclaim that network until the sidecar is gone -- callers run this sweep
// first. It is meant to run at startup, before this process has launched any
// scan, so every match is residue rather than a live sidecar of ours (the same
// single-host operating assumption the scan-id-based network naming already
// makes). Returns the number removed; rm failures are swallowed (a container
// already exiting is fine to skip).
func SweepOrphanProxySidecars(rt ContainerRuntime) (int, error) {
	out, err := exec.Command(rt.bin(), "ps", "-a",
		"--filter", "name="+proxySidecarPrefix,
		"--format", "{{.Names}}").Output()
	if err != nil {
		return 0, fmt.Errorf("%s ps: %w", rt.bin(), err)
	}
	removed := 0
	for _, n := range parseProxySidecarNames(out) {
		if err := exec.Command(rt.bin(), "rm", "-f", "--", n).Run(); err == nil {
			removed++
		}
	}
	return removed, nil
}

// parseProxySidecarNames extracts strict-prefix matches from the runtime's `ps
// --format {{.Names}}`. Its --filter name= is a substring match, so we re-check
// the prefix here to avoid touching a user-named container that merely contains
// the substring.
func parseProxySidecarNames(out []byte) []string {
	var names []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		name := strings.TrimSpace(line)
		if name != "" && strings.HasPrefix(name, proxySidecarPrefix) {
			names = append(names, name)
		}
	}
	return names
}
