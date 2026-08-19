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

// OpencodeReadinessCache avoids launching the same catalog probe before every
// scan. Only successful probes are cached; a repaired image or credential can
// therefore be retried without restarting Scrutineer.
type OpencodeReadinessCache struct {
	mu    sync.Mutex
	ready map[string]bool
}

func NewOpencodeReadinessCache() *OpencodeReadinessCache {
	return &OpencodeReadinessCache{ready: make(map[string]bool)}
}

// OpencodeProviderID returns the provider prefix of an OpenCode model id.
func OpencodeProviderID(model string) string {
	id, _, ok := strings.Cut(model, "/")
	if !ok || id == "" {
		return ""
	}
	return id
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
		return resolved, nil
	}
	resolved.Configured = true
	resolved.StateDir = cfg.StateDir
	resolved.RequiredBinaries = append([]string(nil), cfg.RequiredBinaries...)
	resolved.EgressHosts = append([]string(nil), cfg.EgressHosts...)
	if cfg.RunnerImage != "" {
		resolved.RunnerImage = cfg.RunnerImage
		resolved.RequiredBinaries = appendMissing(resolved.RequiredBinaries, "brief", "scrutineer")
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
	if d.usesEgressSidecar() {
		return d, noop, nil
	}
	if d.ProviderProxy.ContainerHost == "" {
		return d, noop, fmt.Errorf("OpenCode provider %q cannot configure scoped egress because the container host endpoint is unavailable", provider.ID)
	}
	token := NewProxyToken()
	port, cleanup, err := StartScopedEgressProxy(&EgressProxy{
		Allow:    d.ProviderProxy.Allow,
		Token:    token,
		APIPort:  d.ProviderProxy.APIPort,
		APIHosts: d.ProviderProxy.APIHosts,
		Log:      d.ProviderProxy.Log,
	})
	if err != nil {
		return d, noop, fmt.Errorf("start OpenCode provider %q egress proxy: %w", provider.ID, err)
	}
	d.ProxyURL = ProxyURLForHost(token, d.ProviderProxy.ContainerHost, port)
	return d, cleanup, nil
}

func (d ContainerRunner) prepareOpencodeExecution(ctx context.Context, model string) (ContainerRunner, opencodeProvider, SkillResult, func(), error) {
	noop := func() {}
	d, provider, result, err := d.prepareOpencodeRun(ctx, model)
	if err != nil {
		return d, provider, result, noop, err
	}
	d, cleanup, err := d.configureOpencodeProviderEgress(provider)
	if err != nil {
		return d, provider, result, noop, err
	}
	return d, provider, result, cleanup, nil
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

func appendMissing(values []string, additions ...string) []string {
	for _, addition := range additions {
		if !slices.Contains(values, addition) {
			values = append(values, addition)
		}
	}
	return values
}

func (d ContainerRunner) prepareOpencodeRun(ctx context.Context, model string) (ContainerRunner, opencodeProvider, SkillResult, error) {
	provider, err := d.resolveOpencodeProvider(model)
	result := SkillResult{Backend: HarnessName(d.harness())}
	if result.Backend == "opencode" {
		result.Provider = provider.ID
		result.RunnerImage = provider.RunnerImage
	}
	if err != nil {
		result.RunnerImageDigest = d.opencodeRunnerImageDigest(ctx, provider.RunnerImage)
		return d, provider, result, err
	}
	if provider.StateDir != "" {
		provider.StateDir, _ = filepath.Abs(provider.StateDir)
		if err := ensureOpencodeProviderState(provider); err != nil {
			result.RunnerImageDigest = d.opencodeRunnerImageDigest(ctx, provider.RunnerImage)
			return d, provider, result, err
		}
	}
	// Provider images are bases for the existing language profiles, so replace
	// the copied runner's default image before profile resolution.
	d.Image = provider.RunnerImage
	if result.Backend == "opencode" {
		result.RunnerImage = d.image()
	}
	return d, provider, result, nil
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
	cacheKey := image + "\x00" + provider.Model + "\x00" + provider.Env["OPENCODE_CONFIG_CONTENT"] + "\x00" + provider.StateDir + "\x00" + strings.Join(provider.RequiredBinaries, "\x00") + "\x00" + strings.Join(provider.EgressHosts, "\x00")
	if d.OpencodeReadiness != nil {
		d.OpencodeReadiness.mu.Lock()
		ready := d.OpencodeReadiness.ready[cacheKey]
		d.OpencodeReadiness.mu.Unlock()
		if ready {
			return nil
		}
	}
	for _, binary := range provider.RequiredBinaries {
		args := d.buildRunArgsForProvider(absWork, image, hnet, harnessStateDir, provider, "/tmp")
		args = append(args, "sh", "-c", `command -v "$1" >/dev/null`, "provider-readiness", binary)
		cmd := exec.CommandContext(ctx, d.Runtime.bin(), args...)
		cmd.Env = environmentWith(os.Environ(), provider.Env)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("OpenCode provider %q readiness failed because supporting binary %q is missing: %w: %s", provider.ID, binary, err, cappedProviderOutput(out))
		}
	}
	for _, host := range provider.EgressHosts {
		if strings.HasPrefix(host, "*.") {
			continue
		}
		args := d.buildRunArgsForProvider(absWork, image, hnet, harnessStateDir, provider, "/tmp")
		args = append(args, "curl", "--silent", "--show-error", "--output", "/dev/null", "--connect-timeout", "5", "--max-time", "10", "--", "https://"+host+"/")
		cmd := exec.CommandContext(ctx, d.Runtime.bin(), args...)
		cmd.Env = environmentWith(os.Environ(), provider.Env)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("OpenCode provider %q readiness failed while reaching configured egress host %q: %w: %s", provider.ID, host, err, cappedProviderOutput(out))
		}
	}
	args := d.buildRunArgsForProvider(absWork, image, hnet, harnessStateDir, provider, "/tmp")
	args = append(args, "opencode", "models", provider.ID)
	cmd := exec.CommandContext(ctx, d.Runtime.bin(), args...)
	cmd.Env = environmentWith(os.Environ(), provider.Env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return classifyOpencodeReadinessError(provider, strings.TrimSpace(string(out)), err)
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
// operator images fall back to their immutable image ID.
func runnerImageContentDigest(ctx context.Context, rt ContainerRuntime, image string) string {
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
