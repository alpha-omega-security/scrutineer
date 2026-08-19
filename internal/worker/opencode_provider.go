package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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
	ExternalCredentials bool
	Configured          bool
}

type opencodeAuthEntry struct {
	Type     string            `json:"type"`
	Key      string            `json:"key"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

const opencodeProviderStatePerm = 0o700

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

// OpencodeProviderEgress returns a stable, de-duplicated union of the hosts
// needed by configured providers. The proxy is process-wide, while credentials
// remain selected per scan.
func OpencodeProviderEgress(providers map[string]OpencodeProviderConfig) []string {
	seen := make(map[string]bool)
	var hosts []string
	for _, provider := range providers {
		for _, host := range provider.EgressHosts {
			if !seen[host] {
				seen[host] = true
				hosts = append(hosts, host)
			}
		}
	}
	sort.Strings(hosts)
	return hosts
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
	authPath := filepath.Join(provider.StateDir, "opencode", "auth.json")
	data, err := os.ReadFile(authPath)
	if os.IsNotExist(err) {
		if !provider.ExternalCredentials {
			return fmt.Errorf("OpenCode provider %q is missing stored credentials at %s", provider.ID, authPath)
		}
		return nil
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

func (d ContainerRunner) checkOpencodeReadiness(ctx context.Context, provider opencodeProvider, absWork, image string, hnet hardenedNet, harnessStateDir string) error {
	if !provider.Configured {
		return nil
	}
	cacheKey := image + "\x00" + provider.Model + "\x00" + provider.Env["OPENCODE_CONFIG_CONTENT"] + "\x00" + provider.StateDir + "\x00" + strings.Join(provider.RequiredBinaries, "\x00")
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
