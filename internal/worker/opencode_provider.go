package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// OpencodeProviderConfig is the runtime portion of one configured OpenCode
// provider. ConfigContent is loaded from config_file during startup so a scan
// never reads mutable provider configuration from its repository workspace.
type OpencodeProviderConfig struct {
	RunnerImage      string
	ConfigContent    string
	APIKeyEnv        string
	AuthMetadata     map[string]string
	PassEnv          []string
	RequiredBinaries []string
	EgressHosts      []string
	HostPort         string
	StateDir         string
}

// opencodeProvider is the provider configuration resolved for one model. Its
// environment map contains values only for that provider. Container arguments
// receive bare variable names so credentials do not appear in the runtime
// process's argv.
type opencodeProvider struct {
	ID                  string
	Model               string
	RunnerImage         string
	StateDir            string
	Env                 map[string]string
	RequiredBinaries    []string
	EgressHosts         []string
	HostPort            string
	ExternalCredentials bool
	Configured          bool
}

type opencodeAuthEntry struct {
	Type     string            `json:"type"`
	Key      string            `json:"key"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

const (
	opencodeProviderStatePerm = 0o700
	opencodeAuthFilePerm      = 0o600
)

// OpencodeReadinessCache holds the OpenCode runtime state that must be shared
// across concurrent scans: cached successful catalog probes (so a repaired
// image or credential can be retried without restarting Scrutineer, but a good
// one is not re-proven before every scan) and per-state_dir locks (so two scans
// never mount the same rotating auth.json read-write at once).
type OpencodeReadinessCache struct {
	mu         sync.Mutex
	ready      map[string]bool
	stateLocks map[string]*sync.Mutex
}

func NewOpencodeReadinessCache() *OpencodeReadinessCache {
	return &OpencodeReadinessCache{ready: make(map[string]bool), stateLocks: make(map[string]*sync.Mutex)}
}

// lockState serialises scans that share one provider state_dir. OpenCode can
// refresh OAuth credentials and rewrite auth.json without cross-process
// locking, so a second concurrent mount can lose a rotated refresh token. The
// lock is held for the whole scan (readiness through skill exit) and released
// by the returned func.
func (c *OpencodeReadinessCache) lockState(dir string) func() {
	if c == nil || dir == "" {
		return func() {}
	}
	c.mu.Lock()
	m, ok := c.stateLocks[dir]
	if !ok {
		m = &sync.Mutex{}
		c.stateLocks[dir] = m
	}
	c.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// OpencodeProviderID returns the provider prefix of an OpenCode model id.
func OpencodeProviderID(model string) string {
	id, _, ok := strings.Cut(model, "/")
	if !ok || id == "" {
		return ""
	}
	return id
}

// opencodeStockProviders are the OpenCode provider ids that work in the stock
// runner without an opencode.providers block: OpencodeHarness.Env passes their
// API-key variables through and OpencodeHarness.EgressHosts already allows
// their endpoints. Any other prefix needs an explicit provider block so it
// gets config, credentials, and egress; without one OpenCode fails inside its
// server with a generic message and no readiness check runs.
var opencodeStockProviders = map[string]bool{
	"anthropic": true,
	"openai":    true,
}

func (d ContainerRunner) resolveOpencodeProvider(model string) (opencodeProvider, error) {
	resolved := opencodeProvider{
		Model:       model,
		RunnerImage: d.image(),
		Env:         make(map[string]string),
	}
	if HarnessName(d.harness()) != "opencode" {
		return resolved, nil
	}
	resolved.ID = OpencodeProviderID(model)
	if resolved.ID == "" {
		return resolved, nil
	}
	cfg, ok := d.OpencodeProviders[resolved.ID]
	if !ok {
		if opencodeStockProviders[resolved.ID] {
			return resolved, nil
		}
		return resolved, fmt.Errorf("OpenCode model %q uses provider %q, which has no opencode.providers.%s entry; see docs/opencode.md", model, resolved.ID, resolved.ID)
	}
	resolved.Configured = true
	resolved.StateDir = cfg.StateDir
	resolved.HostPort = cfg.HostPort
	resolved.RequiredBinaries = append([]string(nil), cfg.RequiredBinaries...)
	resolved.EgressHosts = append([]string(nil), cfg.EgressHosts...)
	if cfg.RunnerImage != "" {
		resolved.RunnerImage = cfg.RunnerImage
		resolved.RequiredBinaries = appendUniqueStrings(resolved.RequiredBinaries, "brief", "scrutineer")
	}
	if cfg.ConfigContent != "" {
		resolved.Env["OPENCODE_CONFIG_CONTENT"] = cfg.ConfigContent
	}
	if cfg.APIKeyEnv != "" {
		key, ok := os.LookupEnv(cfg.APIKeyEnv)
		if !ok || key == "" {
			return resolved, fmt.Errorf("OpenCode provider %q is missing credential environment variable %s", resolved.ID, cfg.APIKeyEnv)
		}
		auth, err := json.Marshal(map[string]opencodeAuthEntry{
			resolved.ID: {Type: "api", Key: key, Metadata: cfg.AuthMetadata},
		})
		if err != nil {
			return resolved, fmt.Errorf("encode OpenCode provider %q auth: %w", resolved.ID, err)
		}
		resolved.Env["OPENCODE_AUTH_CONTENT"] = string(auth)
		resolved.ExternalCredentials = true
	}
	for _, name := range cfg.PassEnv {
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return resolved, fmt.Errorf("OpenCode provider %q is missing credential environment variable %s", resolved.ID, name)
		}
		resolved.Env[name] = value
		resolved.ExternalCredentials = true
	}
	return resolved, nil
}

func (d ContainerRunner) configureOpencodeProviderEgress(provider opencodeProvider) (ContainerRunner, func(), error) {
	noop := func() {}
	if !provider.Configured {
		return d, noop, nil
	}
	d.Egress.Allow = appendUniqueStrings(d.Egress.Allow, provider.EgressHosts...)
	d.ProviderProxy.Allow = appendUniqueStrings(d.ProviderProxy.Allow, provider.EgressHosts...)
	var hostPorts []string
	if provider.HostPort != "" {
		hostPorts = []string{provider.HostPort}
		d.Egress.HostPorts = appendUniqueStrings(d.Egress.HostPorts, provider.HostPort)
	}
	if d.usesEgressSidecar() {
		return d, noop, nil
	}
	if d.ProviderProxy.ContainerHost == "" {
		return d, noop, fmt.Errorf("OpenCode provider %q cannot configure scoped egress because the container host endpoint is unavailable", provider.ID)
	}
	token := NewProxyToken()
	port, cleanup, err := StartScopedEgressProxy(&EgressProxy{
		Allow:     d.ProviderProxy.Allow,
		Token:     token,
		APIPort:   d.ProviderProxy.APIPort,
		APIHosts:  d.ProviderProxy.APIHosts,
		HostPorts: hostPorts,
		Log:       d.ProviderProxy.Log,
	})
	if err != nil {
		return d, noop, fmt.Errorf("start OpenCode provider %q egress proxy: %w", provider.ID, err)
	}
	d.ProxyURL = ProxyURLForHost(token, d.ProviderProxy.ContainerHost, port)
	return d, cleanup, nil
}

func (d ContainerRunner) prepareOpencodeExecution(ctx context.Context, model string) (ContainerRunner, opencodeProvider, SkillResult, func(), error) {
	noop := func() {}
	provider, err := d.resolveOpencodeProvider(model)
	result := SkillResult{Backend: HarnessName(d.harness())}
	if result.Backend == "opencode" {
		result.Provider = provider.ID
		result.RunnerImage = provider.RunnerImage
	}
	if err != nil {
		result.RunnerImageDigest = d.opencodeRunnerImageDigest(ctx, provider.RunnerImage)
		return d, provider, result, noop, err
	}
	if provider.StateDir != "" {
		provider.StateDir, _ = filepath.Abs(provider.StateDir)
	}
	// Lock before ensureOpencodeProviderState so a queued scan never reads
	// auth.json while a running scan's OpenCode is rewriting it mid-refresh.
	unlock := d.OpencodeReadiness.lockState(provider.StateDir)
	if err := ensureOpencodeProviderState(provider); err != nil {
		unlock()
		result.RunnerImageDigest = d.opencodeRunnerImageDigest(ctx, provider.RunnerImage)
		return d, provider, result, noop, err
	}
	// Provider images are bases for the existing language profiles, so replace
	// the copied runner's default image before profile resolution.
	d.Image = provider.RunnerImage
	d, closeProxy, err := d.configureOpencodeProviderEgress(provider)
	if err != nil {
		unlock()
		return d, provider, result, noop, err
	}
	return d, provider, result, func() { closeProxy(); unlock() }, nil
}

func (d ContainerRunner) prepareHarnessState(ctx context.Context, stateDir string, provider opencodeProvider, absWork, image string, hnet hardenedNet) (string, string, error) {
	// A non-absolute bind source is a runtime-managed volume, so resolve the
	// scan state path the same way as the workspace before building arguments.
	var absState string
	if stateDir != "" {
		absState, _ = filepath.Abs(stateDir)
		if err := os.MkdirAll(absState, dirPerm); err != nil {
			return "", "", fmt.Errorf("create harness state dir: %w", err)
		}
	}
	if err := prepareOpencodeScanState(provider, absState); err != nil {
		return "", "", err
	}
	readinessErr := d.checkOpencodeReadiness(ctx, provider, absWork, image, hnet, absState)
	digest := d.opencodeRunnerImageDigest(ctx, d.image())
	return absState, digest, readinessErr
}

func (d ContainerRunner) appendOpencodeStateArgs(args []string, harnessStateDir string, provider opencodeProvider) []string {
	if harnessStateDir != "" {
		// Logs, repository metadata, and all other OpenCode data stay scoped to
		// this scan lineage. A configured provider mounts only auth.json below.
		args = append(args, "-e", "XDG_DATA_HOME=/harness-state/data")
	}
	if provider.StateDir != "" && harnessStateDir != "" {
		args = append(args, "-v", bindMount(
			opencodeProviderAuthPath(provider.StateDir),
			"/harness-state/data/opencode/auth.json",
			d.SELinuxRelabel,
		))
	}
	return args
}

func appendUniqueStrings(values []string, additions ...string) []string {
	out := append([]string(nil), values...)
	seen := make(map[string]bool, len(out)+len(additions))
	for _, value := range out {
		seen[value] = true
	}
	for _, addition := range additions {
		if !seen[addition] {
			out = append(out, addition)
			seen[addition] = true
		}
	}
	return out
}

func (d ContainerRunner) opencodeRunnerImageDigest(ctx context.Context, image string) string {
	if HarnessName(d.harness()) != "opencode" {
		return ""
	}
	return runnerImageContentDigest(ctx, d.Runtime, image)
}

func ensureOpencodeProviderState(provider opencodeProvider) error {
	if provider.StateDir == "" {
		return nil
	}
	if err := os.MkdirAll(provider.StateDir, opencodeProviderStatePerm); err != nil {
		return fmt.Errorf("create OpenCode provider %q state directory: %w", provider.ID, err)
	}
	info, err := os.Stat(provider.StateDir)
	if err != nil {
		return fmt.Errorf("inspect OpenCode provider %q state directory: %w", provider.ID, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("OpenCode provider %q state path is not a directory", provider.ID)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("OpenCode provider %q state directory permissions %04o expose credentials; require 0700 or stricter", provider.ID, info.Mode().Perm())
	}
	authPath := opencodeProviderAuthPath(provider.StateDir)
	data, err := os.ReadFile(authPath)
	if os.IsNotExist(err) {
		if !provider.ExternalCredentials {
			return fmt.Errorf("OpenCode provider %q is missing stored credentials at %s", provider.ID, authPath)
		}
		if err := os.MkdirAll(filepath.Dir(authPath), opencodeProviderStatePerm); err != nil {
			return fmt.Errorf("create OpenCode provider %q auth directory: %w", provider.ID, err)
		}
		file, createErr := os.OpenFile(authPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, opencodeAuthFilePerm)
		if createErr != nil && !os.IsExist(createErr) {
			return fmt.Errorf("create OpenCode provider %q auth state: %w", provider.ID, createErr)
		}
		if createErr == nil {
			if _, writeErr := file.WriteString("{}\n"); writeErr != nil {
				_ = file.Close()
				return fmt.Errorf("initialise OpenCode provider %q auth state: %w", provider.ID, writeErr)
			}
			if closeErr := file.Close(); closeErr != nil {
				return fmt.Errorf("initialise OpenCode provider %q auth state: %w", provider.ID, closeErr)
			}
			return nil
		}
		data, err = os.ReadFile(authPath)
	}
	if err != nil {
		return fmt.Errorf("read OpenCode provider %q auth state: %w", provider.ID, err)
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parse OpenCode provider %q auth state: %w", provider.ID, err)
	}
	for id := range entries {
		if id != provider.ID {
			return fmt.Errorf("OpenCode provider %q state contains credentials for provider %q", provider.ID, id)
		}
	}
	if _, ok := entries[provider.ID]; !ok && !provider.ExternalCredentials {
		return fmt.Errorf("OpenCode provider %q state does not contain its stored credentials", provider.ID)
	}
	return nil
}

func opencodeProviderAuthPath(stateDir string) string {
	return filepath.Join(stateDir, "opencode", "auth.json")
}

func prepareOpencodeScanState(provider opencodeProvider, harnessStateDir string) error {
	if provider.StateDir == "" {
		return nil
	}
	if harnessStateDir == "" {
		return fmt.Errorf("OpenCode provider %q stored auth requires a per-scan harness state directory", provider.ID)
	}
	target := filepath.Join(harnessStateDir, "data", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(target), opencodeProviderStatePerm); err != nil {
		return fmt.Errorf("prepare OpenCode provider %q scan auth directory: %w", provider.ID, err)
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE, opencodeAuthFilePerm)
	if err != nil {
		return fmt.Errorf("prepare OpenCode provider %q scan auth mountpoint: %w", provider.ID, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("prepare OpenCode provider %q scan auth mountpoint: %w", provider.ID, err)
	}
	return nil
}

func (d ContainerRunner) checkOpencodeReadiness(ctx context.Context, provider opencodeProvider, absWork, image string, hnet hardenedNet, harnessStateDir string) error {
	if !provider.Configured {
		return nil
	}
	probe := func(argv ...string) ([]byte, error) {
		args := d.buildRunArgsForProvider(absWork, image, hnet, harnessStateDir, provider, "/tmp")
		cmd := exec.CommandContext(ctx, d.Runtime.bin(), append(args, argv...)...)
		cmd.Env = environmentWith(os.Environ(), provider.Env)
		return cmd.CombinedOutput()
	}
	cacheKey := image + "\x00" + provider.Model + "\x00" + provider.Env["OPENCODE_CONFIG_CONTENT"] + "\x00" + provider.StateDir + "\x00" + provider.HostPort + "\x00" + strings.Join(provider.RequiredBinaries, "\x00") + "\x00" + strings.Join(provider.EgressHosts, "\x00")
	if d.OpencodeReadiness != nil {
		d.OpencodeReadiness.mu.Lock()
		ready := d.OpencodeReadiness.ready[cacheKey]
		d.OpencodeReadiness.mu.Unlock()
		if ready {
			return d.checkOpencodeHostPort(provider, probe)
		}
	}
	if len(provider.RequiredBinaries) > 0 {
		argv := append([]string{"sh", "-c", `for b in "$@"; do command -v "$b" >/dev/null || { echo "scrutineer-readiness-fail: $b"; exit 1; }; done`, "provider-readiness"}, provider.RequiredBinaries...)
		if out, err := probe(argv...); err != nil {
			return fmt.Errorf("OpenCode provider %q readiness failed because supporting binary %q is missing: %w: %s", provider.ID, readinessFailTarget(out), err, cappedProviderOutput(out))
		}
	}
	if hosts := concreteEgressHosts(provider.EgressHosts); len(hosts) > 0 {
		argv := append([]string{"sh", "-c", `for h in "$@"; do curl --silent --show-error --output /dev/null --connect-timeout 5 --max-time 10 -- "https://$h/" || { echo "scrutineer-readiness-fail: $h"; exit 1; }; done`, "provider-readiness"}, hosts...)
		if out, err := probe(argv...); err != nil {
			return fmt.Errorf("OpenCode provider %q readiness failed while reaching configured egress host %q: %w: %s", provider.ID, readinessFailTarget(out), err, cappedProviderOutput(out))
		}
	}
	out, err := probe("opencode", "models", provider.ID)
	if err != nil {
		return classifyOpencodeReadinessError(provider, cappedProviderOutput(out), err)
	}
	models := strings.Fields(string(out))
	if !slices.Contains(models, provider.Model) {
		return fmt.Errorf("OpenCode provider %q model %q is unavailable in the selected image catalog: %s", provider.ID, provider.Model, cappedProviderOutput(out))
	}
	if d.OpencodeReadiness != nil {
		d.OpencodeReadiness.mu.Lock()
		if d.OpencodeReadiness.ready == nil {
			d.OpencodeReadiness.ready = make(map[string]bool)
		}
		d.OpencodeReadiness.ready[cacheKey] = true
		d.OpencodeReadiness.mu.Unlock()
	}
	return d.checkOpencodeHostPort(provider, probe)
}

// checkOpencodeHostPort probes the provider's host-local model server from
// inside the container. It runs on every scan (outside the readiness cache)
// because a host-local server can be stopped or restarted between scans while
// the image, catalog, and egress hosts the cache covers stay unchanged.
// --proxytunnel forces CONNECT for the plain-http target so a proxy 403/502
// (port denied or nothing listening on the host loopback) is a curl exit
// error; once the tunnel is up, any origin status counts as reachable.
func (d ContainerRunner) checkOpencodeHostPort(provider opencodeProvider, probe func(...string) ([]byte, error)) error {
	if provider.HostPort == "" {
		return nil
	}
	target := "http://" + HostGatewayAlias + ":" + provider.HostPort + "/"
	argv := []string{"curl", "--silent", "--show-error", "--proxytunnel", "--output", "/dev/null", "--connect-timeout", "5", "--max-time", "10", "--", target}
	out, err := probe(argv...)
	if err != nil {
		return fmt.Errorf("OpenCode provider %q readiness failed reaching the host-local model server on port %s: %w: %s", provider.ID, provider.HostPort, err, cappedProviderOutput(out))
	}
	return nil
}

func classifyOpencodeProviderRunError(provider opencodeProvider, output string, runErr error) error {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "network") || strings.Contains(lower, "connect") || strings.Contains(lower, "econn") || strings.Contains(lower, "timeout") || strings.Contains(lower, "certificate") || strings.Contains(lower, "proxy") {
		return fmt.Errorf("OpenCode provider %q failed while reaching its configured egress hosts: %w: %s", provider.ID, runErr, cappedProviderOutput([]byte(output)))
	}
	return fmt.Errorf("OpenCode provider %q failed: %w: %s", provider.ID, runErr, cappedProviderOutput([]byte(output)))
}

func classifyOpencodeReadinessError(provider opencodeProvider, output string, runErr error) error {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "executable file not found") || strings.Contains(lower, "opencode: not found"):
		return fmt.Errorf("OpenCode provider %q readiness failed because the selected image does not contain the opencode binary: %w: %s", provider.ID, runErr, output)
	case strings.Contains(lower, "module not found"), strings.Contains(lower, "cannot find module"), strings.Contains(lower, "cannot find package"):
		return fmt.Errorf("OpenCode provider %q readiness failed because a configured adapter or plugin is missing: %w: %s", provider.ID, runErr, output)
	case strings.Contains(lower, "command not found"), strings.Contains(lower, "no such file or directory"):
		return fmt.Errorf("OpenCode provider %q readiness failed because a supporting binary is missing: %w: %s", provider.ID, runErr, output)
	case strings.Contains(lower, "network"), strings.Contains(lower, "connect"), strings.Contains(lower, "econn"), strings.Contains(lower, "timeout"), strings.Contains(lower, "certificate"):
		return fmt.Errorf("OpenCode provider %q readiness failed while reaching its configured egress hosts: %w: %s", provider.ID, runErr, output)
	default:
		return fmt.Errorf("OpenCode provider %q readiness failed: %w: %s", provider.ID, runErr, output)
	}
}

func concreteEgressHosts(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if !strings.HasPrefix(h, "*.") {
			out = append(out, h)
		}
	}
	return out
}

// readinessFailTarget extracts the binary or host name a readiness probe
// script tagged as the failure. The marker is on its own stdout line, so it
// survives runtime warnings and curl stderr in CombinedOutput.
func readinessFailTarget(out []byte) string {
	for line := range strings.SplitSeq(string(out), "\n") {
		if target, ok := strings.CutPrefix(strings.TrimSpace(line), "scrutineer-readiness-fail: "); ok {
			return target
		}
	}
	return ""
}

func cappedProviderOutput(out []byte) string {
	const max = 2048
	text := strings.TrimSpace(string(out))
	if len(text) > max {
		return text[:max] + "..."
	}
	return text
}

func environmentWith(base []string, overrides map[string]string) []string {
	env := append([]string(nil), base...)
	for key, value := range overrides {
		prefix := key + "="
		replaced := false
		for i := range env {
			if strings.HasPrefix(env[i], prefix) {
				env[i] = prefix + value
				replaced = true
				break
			}
		}
		if !replaced {
			env = append(env, prefix+value)
		}
	}
	return env
}

// runnerImageContentDigest records the locally resolved content identity of
// the provider base. Registry-backed images use RepoDigests; locally built
// operator images fall back to their immutable image ID. Apple's container CLI
// has no --format flag on `image inspect`, so its JSON output is parsed for
// the equivalent descriptor digest.
func runnerImageContentDigest(ctx context.Context, rt ContainerRuntime, image string) string {
	if rt.Bin == runtimeApple {
		return appleImageContentDigest(ctx, image)
	}
	const format = `{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}`
	out, err := exec.CommandContext(ctx, rt.bin(), "image", "inspect", "--format", format, "--", image).Output()
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(out))
	if _, digest, ok := strings.Cut(value, "@"); ok {
		return digest
	}
	return value
}

func appleImageContentDigest(ctx context.Context, image string) string {
	out, err := exec.CommandContext(ctx, "container", "image", "inspect", image).Output()
	if err != nil {
		return ""
	}
	var records []struct {
		ID            string `json:"id"`
		Configuration struct {
			Descriptor struct {
				Digest string `json:"digest"`
			} `json:"descriptor"`
		} `json:"configuration"`
	}
	if err := json.Unmarshal(out, &records); err != nil || len(records) == 0 {
		return ""
	}
	if d := records[0].Configuration.Descriptor.Digest; d != "" {
		return d
	}
	return records[0].ID
}
