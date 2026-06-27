// Package worker provides a ContainerRunner that executes claude in an ephemeral
// container via a container runtime (docker or podman). Used when a runtime is
// available on the host; falls back to LocalClaude otherwise. The scrutineer
// process runs on the host (not containerised) and calls the runtime directly
// -- no socket mounting needed (T12). Rootless podman is supported, which keeps
// runtime access non-root-equivalent (see threatmodel.md T12).
package worker

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const DefaultRunnerImage = "ghcr.io/alpha-omega-security/scrutineer-runner:latest"

// ContainerRunner launches claude inside an ephemeral container with the scan
// workspace (clone + staged skill + output file) mounted at /work. It drives
// either docker or podman (selected via the Runtime field) and implements
// SkillRunner.
type ContainerRunner struct {
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
	// a per-scan --internal network so the only egress path is
	// the host proxy and concurrent scans cannot reach each other.
	// Profile images must work with a read-only rootfs when this is
	// enabled (writable paths beyond /work and /tmp will fail).
	Hardened bool
	// HardenedRootlessRuntime applies the non-network half of --hardened -- a
	// read-only rootfs, no-new-privileges, and the post-clone workspace cap --
	// WITHOUT the per-scan --internal network. Those are all independent of the
	// network, so unlike full --hardened they work under rootless podman (whose
	// --internal network cannot route to the host egress proxy; see
	// docs/podman.md). The always-on baseline (--cap-drop ALL, non-root --user,
	// the /tmp tmpfs) applies regardless of this field. --hardened already
	// implies all of these, so this is the rootless stand-in for them, not an
	// addition on top (setting both is harmless). The read-only rootfs can break
	// custom profile images that write outside /work and /tmp.
	HardenedRootlessRuntime bool
	// Runtime selects the OCI engine (docker or podman) and carries the
	// rootless flag that gates --userns=keep-id. The zero value is docker, so
	// a bare ContainerRunner{} keeps shelling out to "docker".
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

// HardenedWorkspaceCapBytes caps the per-scan workspace footprint that the
// hardening modes (--hardened and --hardened-rootless-runtime) tolerate after
// clone completes. This is a post-clone check, not a clone-time bound: a clone
// that already exceeds disk capacity fails earlier on its own, so this cap is
// what hardening will agree to scan, not a guarantee against disk fill during
// clone (use OS-level disk quotas for that). It is a pure host-side size check
// with no container/network/rootless dependency, which is why it applies under
// --hardened-rootless-runtime too. 2 GiB leaves room for genuinely large
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
	defer cleanupNetwork()

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

	accountErrText := ""
	wrappedEmit := func(e Event) {
		if accountErrText == "" {
			accountErrText = claudeAccountErrorText(e.Text)
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
			return res, &ClaudeAccountError{Detail: accountErrText}
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
	claudeArgs := append([]string{"claude"}, buildClaudeArgs(sj, d.Effort, d.MaxTurns)...)
	runArgs := append(append([]string{}, runBase...), claudeArgs...)

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
	ParseStream(stdout, wrappedEmit)
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
		"-v", bindMount(absWork, "/work", d.SELinuxRelabel),
		"-w", "/work",
		"--add-host", HostGatewayAlias + ":" + gwTarget,
	}
	if d.Runtime.needsKeepID() {
		// Rootless podman remaps --user uid:gid through /etc/subuid, so writes
		// to the bind mounts (/work output and the /claude-config resume store)
		// would land owned by a subordinate uid. keep-id maps the container
		// user back to the invoking host uid so output stays host-owned.
		args = append(args, "--userns=keep-id")
	}
	if claudeConfigDir != "" {
		// Persist the resumable claude session store outside the container.
		// Without this it lands in the /tmp tmpfs and dies with the
		// container, so --resume on a retry would find nothing. The bind
		// mount stays writable even under hardened mode's --read-only
		// rootfs, so resume works there too.
		args = append(args,
			"-v", bindMount(claudeConfigDir, "/claude-config", d.SELinuxRelabel),
			"-e", "CLAUDE_CONFIG_DIR=/claude-config",
		)
	}
	if d.Hardened || d.HardenedRootlessRuntime {
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
			"--security-opt", "no-new-privileges",
		)
	}
	if d.Hardened {
		// The per-scan --internal network is the egress-enforcement half of
		// --hardened, kept separate from the container hardening above because
		// it does not work under rootless podman (the startup verification
		// fails closed when it can't reach the host proxy here; see
		// docs/podman.md). --hardened-rootless-runtime deliberately omits it.
		args = append(args, "--network", hnet.name)
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
	// Forwarding the host Anthropic credential into the container is a known
	// residual: in-container code (T1) can read it. Closing it needs proxy-side
	// credential injection -- see threatmodel.md T1/T13.
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
// --hardened and --hardened-rootless-runtime (the cap is a host-side size check,
// not network-coupled), and is a no-op for plain default scans.
func (d ContainerRunner) checkHardenedWorkspace(workRoot string) error {
	if !d.Hardened && !d.HardenedRootlessRuntime {
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
	args := []string{"run", "--rm", "--add-host", "hgw:host-gateway"}
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
	cmd := exec.Command(rt.bin(), "network", "create", "--internal", "--", name)
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
	// both the verification probe and the real run (an empty result falls through
	// to the literal host-gateway alias downstream).
	hn := hardenedNet{name: network, gatewayIP: ResolveHostGatewayIPv4(d.Runtime, image, network)}
	// docker's bridge --internal is trusted, and so is rootful podman's (netavark
	// + a bridge in the host netns, gateway on the host -- docker's model). Only
	// rootless podman needs per-scan proof; see needsHardenedNetVerify.
	if d.Runtime.needsHardenedNetVerify() {
		if err := d.verifyHardenedNetwork(hn, image); err != nil {
			cleanup()
			return hardenedNet{}, noop, fmt.Errorf("hardened network verification: %w", err)
		}
	}
	return hn, cleanup, nil
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
//	(b) a container must still reach the host egress proxy through the gateway.
//
// Any probe that cannot even run (image won't start, curl missing) is treated
// as a failure: the runner must never fall back to a weaker sandbox silently.
func (d ContainerRunner) verifyHardenedNetwork(hn hardenedNet, image string) error {
	network := hn.name
	gwTarget := "host-gateway"
	if hn.gatewayIP != "" {
		gwTarget = hn.gatewayIP
	}
	port, err := proxyPortFromURL(d.ProxyURL)
	if err != nil {
		return fmt.Errorf("parse proxy url: %w", err)
	}

	out, err := exec.Command(d.Runtime.bin(), hardenedEgressBlockArgs(network, image)...).CombinedOutput()
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

	out, err = exec.Command(d.Runtime.bin(), hardenedProxyReachArgs(network, gwTarget, port, image)...).CombinedOutput()
	s = strings.TrimSpace(string(out))
	if err != nil {
		return fmt.Errorf("proxy-reach probe could not run on network %q: %w: %s", network, err, s)
	}
	if !strings.Contains(s, "REACHED") {
		return fmt.Errorf("internal network %q cannot reach the host egress proxy at %s:%s (probe output: %q); the only egress path is broken", network, gwTarget, port, s)
	}
	return nil
}

// hardenedEgressBlockArgs builds the `run` args for probe (a): a container on
// the per-scan --internal network, no proxy env, that must fail to reach a
// routable public IP. A literal IP avoids a false pass from blocked DNS. curl
// absence is reported as NOCURL so the caller can fail closed rather than read
// the curl-not-found exit as "egress blocked".
func hardenedEgressBlockArgs(network, image string) []string {
	const script = `command -v curl >/dev/null 2>&1 || { echo NOCURL; exit 0; }
curl -s -m 5 -o /dev/null http://1.1.1.1 && echo REACHED || echo BLOCKED`
	return []string{
		"run", "--rm", "--cap-drop", "ALL", "--network", network,
		"--entrypoint", "sh", "--", image, "-c", script,
	}
}

// hardenedProxyReachArgs builds the `run` args for probe (b): a container on the
// per-scan --internal network, with the host-gateway alias wired exactly as the
// real run wires it, that must reach the host egress proxy. curl exit 0 (the
// proxy answers, e.g. 407 without auth) means the TCP path to the host is open.
func hardenedProxyReachArgs(network, gatewayIP, proxyPort, image string) []string {
	target := "http://" + HostGatewayAlias + ":" + proxyPort + "/"
	script := "curl -s -m 5 -o /dev/null " + target + " && echo REACHED || echo UNREACHABLE"
	return []string{
		"run", "--rm", "--cap-drop", "ALL", "--network", network,
		"--add-host", HostGatewayAlias + ":" + gatewayIP,
		"--entrypoint", "sh", "--", image, "-c", script,
	}
}

// proxyPortFromURL extracts the port from a proxy URL of the shape ProxyURL
// produces (http://user:tok@host.docker.internal:PORT).
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
	out, err := exec.Command(rt.bin(), "network", "ls",
		"--filter", "name="+hardenedNetworkPrefix,
		"--format", "{{.Name}}").Output()
	if err != nil {
		return 0, fmt.Errorf("%s network ls: %w", rt.bin(), err)
	}
	removed := 0
	for _, n := range parseHardenedNetworkNames(out) {
		if err := exec.Command(rt.bin(), "network", "rm", "--", n).Run(); err == nil {
			removed++
		}
	}
	return removed, nil
}

// parseHardenedNetworkNames extracts strict-prefix matches from the
// output of the runtime's `network ls --format {{.Name}}`. Its --filter
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
