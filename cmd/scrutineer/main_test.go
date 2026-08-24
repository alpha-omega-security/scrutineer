package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
)

type identityFunc func([]*age.Stanza) ([]byte, error)

func (f identityFunc) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return f(stanzas)
}

func fullConfig() *config.Config {
	return &config.Config{
		Addr:            "0.0.0.0:9090",
		Data:            "/var/lib/scrutineer",
		Effort:          "medium",
		Backend:         "codex",
		NoContainer:     new(true),
		Hardened:        new(true),
		RunnerImage:     "custom:v1",
		SkillsRepo:      "https://example.com/skills.git",
		SkillsRepoToken: "private-skills-token",
		Skills:          []string{"/etc/skills"},
		Concurrency:     8,
		Clone:           "full",
		ScanTimeout:     "30m",
		MaxTurns:        200,
		ModelBaseURL:    "https://proxy.corp.com/v1",
		ForkOrg:         "fork-central",

		FederationSalt:    "s3cret",
		FederationContact: "security@corp.com",
	}
}

func TestFlagsMerge_configFillsUnset(t *testing.T) {
	cfg := fullConfig()
	f := &flags{addr: "127.0.0.1:8080", cloneMode: "shallow", set: map[string]bool{}}
	f.merge(cfg)
	if f.addr != cfg.Addr {
		t.Errorf("addr = %q, want %q", f.addr, cfg.Addr)
	}
	if f.dataDir != cfg.Data {
		t.Errorf("dataDir = %q", f.dataDir)
	}
	if !f.noContainer {
		t.Errorf("noContainer not applied")
	}
	if f.backend != "codex" {
		t.Errorf("backend = %q, want codex", f.backend)
	}
	if !f.hardened {
		t.Errorf("hardened not applied")
	}
	if f.concurrency != 8 {
		t.Errorf("concurrency = %d", f.concurrency)
	}
	if !f.fullClone() {
		t.Errorf("cloneMode = %q, want full", f.cloneMode)
	}
	if len(f.skillLocal) != 1 || f.skillLocal[0] != "/etc/skills" {
		t.Errorf("skillLocal = %v", f.skillLocal)
	}
	if f.skillsRepoToken != cfg.SkillsRepoToken {
		t.Errorf("skillsRepoToken was not loaded from config")
	}
	if f.scanTimeout != 30*time.Minute {
		t.Errorf("scanTimeout = %v", f.scanTimeout)
	}
	if f.maxTurns != 200 {
		t.Errorf("maxTurns = %d", f.maxTurns)
	}
	if f.modelBaseURL != cfg.ModelBaseURL {
		t.Errorf("modelBaseURL = %q, want %q", f.modelBaseURL, cfg.ModelBaseURL)
	}
	if f.forkOrg != cfg.ForkOrg {
		t.Errorf("forkOrg = %q, want %q", f.forkOrg, cfg.ForkOrg)
	}
	if f.federationSalt != cfg.FederationSalt {
		t.Errorf("federationSalt = %q, want %q", f.federationSalt, cfg.FederationSalt)
	}
	if f.federationContact != cfg.FederationContact {
		t.Errorf("federationContact = %q, want %q", f.federationContact, cfg.FederationContact)
	}
}

func TestFlagsMerge_cliFlagWins(t *testing.T) {
	cfg := fullConfig()
	f := &flags{
		addr: "127.0.0.1:8080", cloneMode: "shallow", concurrency: 2,
		modelBaseURL:      "https://my-flag.example.com/v1",
		federationContact: "flag-contact@example.com",
		set: map[string]bool{
			"addr": true, "clone": true, "concurrency": true,
			"model-base-url": true, "federation-contact": true,
		},
	}
	f.merge(cfg)
	if f.addr != "127.0.0.1:8080" {
		t.Errorf("addr overridden despite explicit flag: %q", f.addr)
	}
	if f.cloneMode != "shallow" {
		t.Errorf("cloneMode overridden despite explicit flag: %q", f.cloneMode)
	}
	if f.concurrency != 2 {
		t.Errorf("concurrency overridden despite explicit flag: %d", f.concurrency)
	}
	// effort wasn't in set, so config still applies
	if f.effort != cfg.Effort {
		t.Errorf("effort = %q, want %q", f.effort, cfg.Effort)
	}
	if f.modelBaseURL != "https://my-flag.example.com/v1" {
		t.Errorf("modelBaseURL overridden despite explicit flag: %q", f.modelBaseURL)
	}
	if f.federationContact != "flag-contact@example.com" {
		t.Errorf("federationContact overridden despite explicit flag: %q", f.federationContact)
	}
	// federation_salt has no flag, so config always applies
	if f.federationSalt != cfg.FederationSalt {
		t.Errorf("federationSalt = %q, want %q", f.federationSalt, cfg.FederationSalt)
	}
}

func TestValidateFederation(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    flags
		want bool
	}{
		{"salt with contact", flags{federationSalt: "s3cret", federationContact: "security@example.com"}, true},
		{"federation disabled", flags{}, true},
		{"salt without contact", flags{federationSalt: "s3cret"}, false},
		{"members feed with recipients and identity", flags{federationMembersFeed: "git@host:o/f.git", recipientsFile: "./recipients.txt", identityFile: "~/.ssh/id_ed25519"}, true},
		{"members feed without recipients", flags{federationMembersFeed: "git@host:o/f.git", identityFile: "~/.ssh/id_ed25519"}, false},
		{"members feed without identity", flags{federationMembersFeed: "git@host:o/f.git", recipientsFile: "./recipients.txt"}, false},
		{"public feed needs nothing else", flags{federationPublicFeed: "git@host:o/f.git"}, true},
		{"credentialed public feed", flags{federationPublicFeed: "https://u:tok@host/o/f.git"}, false},
		{"credentialed import feed", flags{federationImportFeeds: []string{"https://u:tok@host/o/f.git"}}, false},
		{"both tiers on one remote", flags{
			federationPublicFeed: "git@host:o/f.git", federationMembersFeed: "git@host:o/f.git",
			recipientsFile: "./recipients.txt", identityFile: "~/.ssh/id_ed25519",
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFederation(&tc.f)
			if tc.want && err != nil {
				t.Errorf("must be accepted: %v", err)
			}
			if !tc.want && err == nil {
				t.Error("must be refused")
			}
		})
	}
}

// A whitespace-only remote must come out of validation as no remote at all.
// ValidateFeedRemote trims its own copy and so reports it as fine, and every
// != "" test downstream, StartFederation's included, would then read it as
// configured and run an hourly clone job against a remote git cannot resolve.
func TestValidateFederation_dropsBlankRemotes(t *testing.T) {
	f := flags{
		federationPublicFeed:  "  ",
		federationMembersFeed: "\t",
		federationImportFeeds: []string{" ", "  git@host:o/f.git  ", ""},
	}
	if err := validateFederation(&f); err != nil {
		t.Fatalf("blank remotes are no configuration, not a bad one: %v", err)
	}
	if f.federationPublicFeed != "" || f.federationMembersFeed != "" {
		t.Errorf("blank feeds left configured: public %q, members %q", f.federationPublicFeed, f.federationMembersFeed)
	}
	if !slices.Equal(f.federationImportFeeds, []string{"git@host:o/f.git"}) {
		t.Errorf("import feeds = %#v, want only the real remote, trimmed", f.federationImportFeeds)
	}
}

func TestFlagsMerge_zeroConfigLeavesDefaults(t *testing.T) {
	f := &flags{addr: "127.0.0.1:8080", concurrency: 4, scanTimeout: time.Hour, set: map[string]bool{}}
	f.merge(&config.Config{})
	if f.addr != "127.0.0.1:8080" {
		t.Errorf("empty config clobbered addr: %q", f.addr)
	}
	if f.concurrency != 4 {
		t.Errorf("zero concurrency clobbered default: %d", f.concurrency)
	}
	if f.scanTimeout != time.Hour {
		t.Errorf("empty scan_timeout clobbered default: %v", f.scanTimeout)
	}
	if f.modelBaseURL != "" {
		t.Errorf("empty config set modelBaseURL: %q", f.modelBaseURL)
	}
}

func TestIsLoopbackListenAddr(t *testing.T) {
	for _, tt := range []struct {
		addr string
		want bool
	}{
		{addr: "localhost:8080", want: true},
		{addr: "127.0.0.1:8080", want: true},
		{addr: "127.23.45.67:8080", want: true},
		{addr: "[::1]:8080", want: true},
		{addr: "0.0.0.0:8080", want: false},
		{addr: "203.0.113.10:8080", want: false},
		{addr: "scanner.example.com:8080", want: false},
	} {
		if got := isLoopbackListenAddr(tt.addr); got != tt.want {
			t.Errorf("isLoopbackListenAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestFlagsMerge_zeroConfigSeedsModelsFromHarness(t *testing.T) {
	// run() calls merge with an empty config when no config file exists;
	// that path must still seed the pick list from the harness defaults so
	// a fresh install has a working model dropdown.
	saved := web.Models
	web.Models = nil
	t.Cleanup(func() { web.Models = saved })

	f := &flags{set: map[string]bool{}}
	f.merge(&config.Config{})
	if len(web.Models) == 0 {
		t.Fatal("merge with empty config did not seed web.Models from harness defaults")
	}
}

func TestApplyServerDefaults_warnsOnModelOutsidePickList(t *testing.T) {
	saved := web.Models
	t.Cleanup(func() { web.Models = saved })
	web.SetModels([]web.Model{{Name: "Opus 5.0", ID: "claude-opus-5"}})

	for _, tc := range []struct {
		name         string
		defaultModel string
		wantWarn     bool
	}{
		{"id outside the pick list", "claude-opus-4-7", true},
		{"id in pick list", "claude-opus-5", false},
		{"no default configured", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			log := slog.New(slog.NewTextHandler(&out, nil))
			applyServerDefaults(&web.Server{}, &flags{defaultModel: tc.defaultModel, effort: "high"}, log)
			if got := strings.Contains(out.String(), "not in the pick list"); got != tc.wantWarn {
				t.Errorf("warned = %v, want %v; log=%q", got, tc.wantWarn, out.String())
			}
		})
	}
}

func TestFlagsMerge_modelBaseURLAliasCliWins(t *testing.T) {
	// The deprecated -anthropic-base-url flag must hold against a yaml
	// model_base_url the same way the canonical flag does.
	f := &flags{
		modelBaseURL: "https://cli.example.com/v1",
		set:          map[string]bool{"anthropic-base-url": true},
	}
	f.merge(&config.Config{ModelBaseURL: "https://yaml.example.com/v1"})
	if f.modelBaseURL != "https://cli.example.com/v1" {
		t.Errorf("modelBaseURL = %q; deprecated CLI alias lost to yaml", f.modelBaseURL)
	}
}

func TestFlagsMerge_hardenedCliWinsOverConfig(t *testing.T) {
	// CLI hardened=false must not be overridden by config hardened:true.
	cfg := &config.Config{Hardened: new(true)}
	f := &flags{set: map[string]bool{"hardened": true}}
	f.merge(cfg)
	if f.hardened {
		t.Errorf("CLI --hardened=false was overridden by config")
	}
}

func TestFlagsMerge_legacyNoDockerFlagHonored(t *testing.T) {
	// The pre-rename --no-docker alias must behave exactly like --no-container:
	// passing it on the CLI suppresses a conflicting config value. Both flags
	// bind to the same variable, and merge checks both set-keys.
	cfg := &config.Config{NoContainer: new(false)} // config wants the container ON
	f := &flags{noContainer: true, set: map[string]bool{"no-docker": true}}
	f.merge(cfg)
	if !f.noContainer {
		t.Error("legacy --no-docker on the CLI was overridden by config; the alias must win like --no-container")
	}
}

func TestFlagsMerge_backendCLIOverridesConfig(t *testing.T) {
	cfg := &config.Config{Backend: "codex"}
	f := &flags{backend: "claude", set: map[string]bool{"backend": true}}
	f.merge(cfg)
	if f.backend != "claude" {
		t.Errorf("CLI -backend was overridden by config: got %q", f.backend)
	}
}

func TestSetupRunner_nonClaudeBackendRejectsNoContainer(t *testing.T) {
	// Non-claude harnesses run only inside the container (their binaries
	// live in the runner image, not the host), so combining one with
	// --no-container must fail at startup rather than later when the
	// binary is missing.
	f := &flags{backend: "codex", noContainer: true, addr: "127.0.0.1:8080"}
	_, _, err := setupRunner(f, nil, quietLog())
	if err == nil || !strings.Contains(err.Error(), "containerised runner") {
		t.Errorf("codex + --no-container: err = %v, want a container-required error", err)
	}

	// claude (the default) keeps working under --no-container.
	f = &flags{backend: "", noContainer: true, addr: "127.0.0.1:8080"}
	r, _, err := setupRunner(f, nil, quietLog())
	if err != nil {
		t.Fatalf("default backend + --no-container: %v", err)
	}
	if _, ok := r.(worker.LocalClaude); !ok {
		t.Errorf("default backend + --no-container returned %T, want LocalClaude", r)
	}
}

func TestLoadOpencodeProvidersResolvesConfigRelativePaths(t *testing.T) {
	dir := t.TempDir()
	providerDir := filepath.Join(dir, "providers")
	if err := os.MkdirAll(providerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(providerDir, "kiro.json"), []byte(`{"plugin":["kiro"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ollamaConfig := `{"provider":{"ollama":{"npm":"@ai-sdk/openai-compatible","options":{"baseURL":"http://host.docker.internal:11434/v1"}}}}`
	if err := os.WriteFile(filepath.Join(providerDir, "ollama.json"), []byte(ollamaConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := worker.HarnessByName("opencode")
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadOpencodeProviders(h, map[string]config.OpencodeProvider{
		"kiro": {
			RunnerImage:      "registry.example/kiro:1",
			ConfigFile:       "providers/kiro.json",
			PassEnv:          []string{"KIRO_API_KEY"},
			RequiredBinaries: []string{"kiro-cli"},
			EgressAllow:      []string{"q.us-east-1.amazonaws.com"},
			StateDir:         "state/kiro",
		},
		"ollama": {ConfigFile: "providers/ollama.json", HostPort: 11434},
	}, filepath.Join(dir, "scrutineer.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	provider := got["kiro"]
	if provider.ConfigContent != `{"plugin":["kiro"]}` || provider.StateDir != filepath.Join(dir, "state", "kiro") {
		t.Errorf("loaded provider = %+v", provider)
	}
	if !slices.Equal(provider.EgressHosts, []string{"q.us-east-1.amazonaws.com"}) {
		t.Errorf("egress hosts = %v", provider.EgressHosts)
	}
	if !slices.Equal(provider.RequiredBinaries, []string{"kiro-cli"}) {
		t.Errorf("required binaries = %v", provider.RequiredBinaries)
	}
	if got["ollama"].HostPort != "11434" || got["kiro"].HostPort != "" {
		t.Errorf("host ports = kiro:%q ollama:%q", got["kiro"].HostPort, got["ollama"].HostPort)
	}
}

func TestLoadOpencodeProvidersRefusesHostPortWithoutMatchingBaseURL(t *testing.T) {
	dir := t.TempDir()
	h, err := worker.HarnessByName("opencode")
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"no config_file": "",
		// The container's own loopback, not the host's. This is the mistake the
		// check exists for: readiness at host.docker.internal:11434 passes and
		// then OpenCode dials 127.0.0.1:11434 inside the container.
		"127.0.0.1":  `{"provider":{"ollama":{"options":{"baseURL":"http://127.0.0.1:11434/v1"}}}}`,
		"wrong port": `{"provider":{"ollama":{"options":{"baseURL":"http://host.docker.internal:1234/v1"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			provider := config.OpencodeProvider{HostPort: 11434}
			if content != "" {
				path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				provider.ConfigFile = path
			}
			_, err := loadOpencodeProviders(h, map[string]config.OpencodeProvider{"ollama": provider}, filepath.Join(dir, "scrutineer.yaml"))
			if err == nil || !strings.Contains(err.Error(), "http://host.docker.internal:11434") {
				t.Fatalf("error = %v, want config_file/baseURL refusal", err)
			}
		})
	}
}

func TestLoadOpencodeProvidersIgnoredForOtherHarness(t *testing.T) {
	h, err := worker.HarnessByName("claude")
	if err != nil {
		t.Fatal(err)
	}
	got, err := loadOpencodeProviders(h, map[string]config.OpencodeProvider{
		"kiro": {ConfigFile: "does-not-exist.json"},
	}, filepath.Join(t.TempDir(), "scrutineer.yaml"))
	if err != nil || got != nil {
		t.Fatalf("non-OpenCode provider load = %v, %v", got, err)
	}
}

func TestRegisterFlags_noContainerAliasParsesFromArgv(t *testing.T) {
	// Both the canonical --no-container and the deprecated --no-docker alias
	// must parse off the command line and set the same noContainer field, so
	// existing `scrutineer --no-docker ...` invocations keep working.
	for _, name := range []string{"--no-container", "--no-docker"} {
		f := &flags{}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		registerFlags(fs, f)
		if err := fs.Parse([]string{name}); err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		if !f.noContainer {
			t.Errorf("%s did not set noContainer", name)
		}
	}
}

func TestRegisterFlags_identityPluginIsRepeatable(t *testing.T) {
	f := &flags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs, f)
	if err := fs.Parse([]string{
		"-identity-plugin", "1p",
		"-identity-plugin", "provider-b",
	}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !slices.Equal([]string(f.identityPlugins), []string{"1p", "provider-b"}) {
		t.Errorf("identity plugins = %v, want [1p provider-b]", f.identityPlugins)
	}
}

func TestRegisterFlags_modelBaseURLAliasParsesFromArgv(t *testing.T) {
	// Both the canonical -model-base-url and the deprecated
	// -anthropic-base-url alias must parse off the command line and set
	// the same modelBaseURL field.
	for _, name := range []string{"-model-base-url", "-anthropic-base-url"} {
		f := &flags{}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		registerFlags(fs, f)
		if err := fs.Parse([]string{name, "https://x.test/v1"}); err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		if f.modelBaseURL != "https://x.test/v1" {
			t.Errorf("%s did not set modelBaseURL: got %q", name, f.modelBaseURL)
		}
	}
}

func TestValidateFlags_modelBaseURLRequiresHTTPS(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{"empty", "", false},
		{"https", "https://models.example.com/v1", false},
		{"loopback IPv4 development", "http://127.0.0.1:11434/v1", false},
		{"loopback IPv6 development", "http://[::1]:11434/v1", false},
		{"localhost development", "http://localhost:11434/v1", false},
		{"container host development", "http://host.docker.internal:11434/v1", false},
		{"remote http", "http://models.example.com/v1", true},
		{"non-http scheme", "ftp://models.example.com/v1", true},
		{"relative URL", "models.example.com/v1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlags(&flags{modelBaseURL: tt.baseURL})
			if (err != nil) != tt.wantErr {
				t.Errorf("validateFlags(%q) error = %v, wantErr %v", tt.baseURL, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFlags_rejectsInsecureEnvironmentBaseURL(t *testing.T) {
	t.Setenv("ANTHROPIC_BASE_URL", "http://models.example.com/v1")
	f := &flags{}
	configureBackendEnvironment(f, quietLog())
	err := validateFlags(f)
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("resolved environment base URL error = %v", err)
	}
}

func TestRegisterFlags_hardenedRuntimeOnlyAliasParsesFromArgv(t *testing.T) {
	// Both the canonical --hardened-runtime-only and the deprecated
	// --hardened-rootless-runtime alias must parse off the command line and set
	// the same hardenedRuntimeOnly field, so existing
	// `scrutineer --hardened-rootless-runtime ...` invocations keep working.
	for _, name := range []string{"--hardened-runtime-only", "--hardened-rootless-runtime"} {
		f := &flags{}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		registerFlags(fs, f)
		if err := fs.Parse([]string{name}); err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		if !f.hardenedRuntimeOnly {
			t.Errorf("%s did not set hardenedRuntimeOnly", name)
		}
	}
}

func TestFlagsMerge_hardenedRuntimeOnlyConfigAlias(t *testing.T) {
	// The deprecated hardened_rootless_runtime config key still applies when the
	// canonical hardened_runtime_only is absent.
	legacy := &flags{}
	legacy.merge(&config.Config{HardenedRootlessRuntime: new(true)})
	if !legacy.hardenedRuntimeOnly {
		t.Error("deprecated config hardened_rootless_runtime was ignored")
	}
	// The canonical key takes precedence over the deprecated alias.
	both := &flags{}
	both.merge(&config.Config{HardenedRuntimeOnly: new(false), HardenedRootlessRuntime: new(true)})
	if both.hardenedRuntimeOnly {
		t.Error("hardened_runtime_only should take precedence over hardened_rootless_runtime")
	}
}

func TestFlagsMerge_ecosystemsEnrichment(t *testing.T) {
	// The flag defaults to true, so an omitted config key must leave it on and
	// an explicit false must reach the flag.
	omitted := &flags{ecosystemsEnrichment: true}
	omitted.merge(&config.Config{})
	if !omitted.ecosystemsEnrichment {
		t.Error("omitted ecosystems_enrichment turned enrichment off")
	}
	off := &flags{ecosystemsEnrichment: true}
	off.merge(&config.Config{EcosystemsEnrichment: new(false)})
	if off.ecosystemsEnrichment {
		t.Error("ecosystems_enrichment: false was ignored")
	}
	// An explicit command-line value wins over the config file.
	cli := &flags{ecosystemsEnrichment: true, set: map[string]bool{"ecosystems-enrichment": true}}
	cli.merge(&config.Config{EcosystemsEnrichment: new(false)})
	if !cli.ecosystemsEnrichment {
		t.Error("config overrode an explicit -ecosystems-enrichment flag")
	}
}

func TestRegisterFlags_ecosystemsEnrichmentDefaultsOn(t *testing.T) {
	f := &flags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs, f)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.ecosystemsEnrichment {
		t.Error("enrichment is off by default, want on")
	}
	if err := fs.Parse([]string{"-ecosystems-enrichment=false"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.ecosystemsEnrichment {
		t.Error("-ecosystems-enrichment=false did not turn enrichment off")
	}
}

// Go's flag package does not accept the space-separated form for a boolean:
// it leaves the flag at its default and parks the operand in Args(). This is
// the first flag here defaulting to true, so that silently reads as the
// opposite of what was typed. parseFlags exits on a leftover argument; this
// pins the signal it keys on.
func TestRegisterFlags_booleanSpaceFormLeavesAStrayArgument(t *testing.T) {
	f := &flags{}
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	registerFlags(fs, f)
	if err := fs.Parse([]string{"-ecosystems-enrichment", "false"}); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !f.ecosystemsEnrichment {
		t.Fatal("the space form now applies; the guard in parseFlags is no longer needed")
	}
	if fs.NArg() != 1 || fs.Arg(0) != "false" {
		t.Fatalf("leftover args = %v, want [false] so parseFlags can refuse it", fs.Args())
	}
}

func TestBuildEgressAllow_defaultIncludesConfigAndAnthropicHost(t *testing.T) {
	cfg := &config.Config{EgressAllow: []string{"artifactory.internal", "*.mycorp.net"}}
	allow := buildEgressAllow(worker.ClaudeHarness{}.EgressHosts(), false, cfg, "https://proxy.corp.com/v1", quietLog())

	if !slices.Contains(allow, "*.anthropic.com") {
		t.Errorf("default mode dropped harness egress hosts: %v", allow)
	}
	if !slices.Contains(allow, "*.ecosyste.ms") {
		t.Errorf("default mode dropped DefaultEgressAllow entries: %v", allow)
	}
	if !slices.Contains(allow, "artifactory.internal") || !slices.Contains(allow, "*.mycorp.net") {
		t.Errorf("default mode did not honour egress_allow: %v", allow)
	}
	if !slices.Contains(allow, "proxy.corp.com") {
		t.Errorf("default mode did not auto-add model base URL host: %v", allow)
	}
}

func TestBuildEgressAllow_hardenedDropsConfigKeepsHarness(t *testing.T) {
	cfg := &config.Config{EgressAllow: []string{"artifactory.internal"}}
	allow := buildEgressAllow(worker.ClaudeHarness{}.EgressHosts(), true, cfg, "https://proxy.corp.com/v1", quietLog())

	if slices.Contains(allow, "*.ecosyste.ms") {
		t.Errorf("hardened leaked DefaultEgressAllow entries: %v", allow)
	}
	if slices.Contains(allow, "artifactory.internal") {
		t.Errorf("hardened honoured egress_allow when it must not: %v", allow)
	}
	if !slices.Contains(allow, "*.anthropic.com") {
		t.Errorf("hardened did not include the harness egress hosts: %v", allow)
	}
	if !slices.Contains(allow, worker.HostGatewayAlias) {
		t.Errorf("hardened did not include HardenedEgressAllow entries: %v", allow)
	}
	if !slices.Contains(allow, "proxy.corp.com") {
		t.Errorf("hardened dropped the model base URL host: %v", allow)
	}
}

func TestBuildEgressAllow_hardenedNilConfig(t *testing.T) {
	harnessHosts := worker.ClaudeHarness{}.EgressHosts()
	allow := buildEgressAllow(harnessHosts, true, nil, "", quietLog())
	if len(allow) != len(harnessHosts)+len(worker.HardenedEgressAllow) {
		t.Errorf("hardened minimal allow = %v, want exactly harness hosts + HardenedEgressAllow", allow)
	}
}

func TestBuildEgressAllow_nonClaudeHarnessExcludesAnthropic(t *testing.T) {
	// A non-claude harness must not inherit *.anthropic.com from the
	// static lists; only the hosts it declares are added.
	allow := buildEgressAllow([]string{"api.openai.com"}, true, nil, "", quietLog())
	if slices.Contains(allow, "*.anthropic.com") {
		t.Errorf("non-claude harness allowlist still contains anthropic: %v", allow)
	}
	if !slices.Contains(allow, "api.openai.com") {
		t.Errorf("non-claude harness hosts not included: %v", allow)
	}
}

func TestResolveEgressSidecar_NoSidecarForNonRootless(t *testing.T) {
	// docker, rootful podman, and the zero (docker) runtime keep the in-process
	// host proxy: resolveEgressSidecar returns the zero config (no sidecar), and
	// without probing for a gateway. Only rootless podman gets a sidecar, which
	// is covered end to end by the podman integration test.
	f := &flags{addr: "127.0.0.1:8080", runnerImage: "img"}
	for _, rt := range []worker.ContainerRuntime{
		{Bin: "docker"},
		{Bin: "podman"}, // rootful
		{Bin: "apple"},  // apple -- hardened, but uses the host proxy, not a sidecar
		{},              // zero value = docker
	} {
		got, err := resolveEgressSidecar(rt, f, []string{"x"}, "tok", quietLog())
		if err != nil {
			t.Errorf("runtime %+v: unexpected error: %v", rt, err)
		}
		if got.Token != "" || got.GatewayIP != "" || got.APIPort != "" || got.Allow != nil {
			t.Errorf("runtime %+v: expected no sidecar config, got %+v", rt, got)
		}
	}
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeTestKey writes PEM bytes to a temp file and returns the path.
func writeTestKey(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// genSSHKey returns an unencrypted OpenSSH ed25519 private key PEM and
// the corresponding public key line.
func genSSHKey(t *testing.T) (pemBytes []byte, pubLine string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), string(ssh.MarshalAuthorizedKey(sshPub))
}

// genEncryptedSSHKey returns a passphrase-protected OpenSSH ed25519
// private key PEM.
func genEncryptedSSHKey(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestLoadIdentities_unencryptedSSH(t *testing.T) {
	pemData, _ := genSSHKey(t)
	ids, err := loadIdentities(writeTestKey(t, pemData))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestLoadIdentities_encryptedSSH(t *testing.T) {
	passphrase := []byte("test-passphrase")
	pemData := genEncryptedSSHKey(t, passphrase)

	// Inject the passphrase so the prompt is not needed.
	orig := promptPassphrase
	promptPassphrase = func(string) ([]byte, error) { return passphrase, nil }
	t.Cleanup(func() { promptPassphrase = orig })

	ids, err := loadIdentities(writeTestKey(t, pemData))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestLoadIdentities_encryptedSSH_wrongPassphrase(t *testing.T) {
	pemData := genEncryptedSSHKey(t, []byte("correct"))

	orig := promptPassphrase
	promptPassphrase = func(string) ([]byte, error) { return []byte("wrong"), nil }
	t.Cleanup(func() { promptPassphrase = orig })

	_, err := loadIdentities(writeTestKey(t, pemData))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestLoadIdentities_encryptedSSH_noTerminal(t *testing.T) {
	pemData := genEncryptedSSHKey(t, []byte("secret"))

	// Use the real promptPassphrase — stdin is not a terminal in tests.
	orig := promptPassphrase
	promptPassphrase = defaultPromptPassphrase
	t.Cleanup(func() { promptPassphrase = orig })

	_, err := loadIdentities(writeTestKey(t, pemData))
	if err == nil {
		t.Fatal("expected error when stdin is not a terminal")
	}
}

func TestLoadIdentities_ageNative(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ids, err := loadIdentities(writeTestKey(t, []byte(id.String()+"\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestLoadIdentityPlugins_validAndMultiple(t *testing.T) {
	ids, err := loadIdentityPlugins([]string{"1p", "provider-b"}, &plugin.ClientUI{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %d identities, want 2", len(ids))
	}
	for i, want := range []string{"1p", "provider-b"} {
		id, ok := ids[i].(*serializedPluginIdentity)
		if !ok {
			t.Fatalf("identity %d has type %T, want *serializedPluginIdentity", i, ids[i])
		}
		if id.Name() != want {
			t.Errorf("identity %d name = %q, want %q", i, id.Name(), want)
		}
	}
}

func TestConfigureEncryptionCombinesSources(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	f := &flags{
		recipientsFile:  writeTestKey(t, []byte(id.Recipient().String()+"\n")),
		identityFile:    writeTestKey(t, []byte(id.String()+"\n")),
		identityPlugins: pluginNames{"provider-a", "provider-b"},
	}
	srv := &web.Server{}
	if err := configureEncryption(srv, f, quietLog()); err != nil {
		t.Fatal(err)
	}
	if len(srv.EncRecipients) != 1 {
		t.Fatalf("recipients = %d, want 1", len(srv.EncRecipients))
	}
	if len(srv.EncIdentities) != 3 {
		t.Fatalf("identities = %d, want one file identity and two plugin identities", len(srv.EncIdentities))
	}
	// Order is load-bearing: age ties a non-native file identity with the
	// plugin identities, so insertion order is the only thing that keeps a
	// local key from being tried after a plugin prompts.
	if _, isPlugin := srv.EncIdentities[0].(*serializedPluginIdentity); isPlugin {
		t.Error("a plugin identity precedes the identity file")
	}
	for i, want := range []string{"provider-a", "provider-b"} {
		got, ok := srv.EncIdentities[i+1].(*serializedPluginIdentity)
		if !ok {
			t.Errorf("identity %d has type %T, want *serializedPluginIdentity", i+1, srv.EncIdentities[i+1])
			continue
		}
		if got.Name() != want {
			t.Errorf("identity %d name = %q, want %q", i+1, got.Name(), want)
		}
	}
}

func TestPluginIdentitiesSerializeInteractions(t *testing.T) {
	var active atomic.Int32
	var overlapped atomic.Bool
	underlying := identityFunc(func([]*age.Stanza) ([]byte, error) {
		if active.Add(1) > 1 {
			overlapped.Store(true)
		}
		time.Sleep(25 * time.Millisecond)
		active.Add(-1)
		return nil, age.ErrIncorrectIdentity
	})
	mutex := new(sync.Mutex)
	identities := []*serializedPluginIdentity{
		{name: "provider-a", identity: underlying, mutex: mutex},
		{name: "provider-b", identity: underlying, mutex: mutex},
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range identities {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = id.Unwrap(nil)
		}()
	}
	close(start)
	wg.Wait()
	if overlapped.Load() {
		t.Fatal("identity plugin interactions overlapped")
	}
}

func TestPluginIdentityNonMatchIsNotReportedAsPluginFailure(t *testing.T) {
	recipientIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, recipientIdentity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("not for this plugin")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	id := &serializedPluginIdentity{
		name: "provider-a",
		identity: identityFunc(func([]*age.Stanza) ([]byte, error) {
			return nil, age.ErrIncorrectIdentity
		}),
		mutex: new(sync.Mutex),
	}
	if _, err := id.Unwrap(nil); err != age.ErrIncorrectIdentity {
		t.Fatalf("Unwrap error = %v, want canonical age.ErrIncorrectIdentity", err)
	}
	_, err = age.Decrypt(bytes.NewReader(ciphertext.Bytes()), id)
	if err == nil {
		t.Fatal("expected identity non-match")
	}
	if !strings.Contains(err.Error(), "identity did not match any of the recipients") {
		t.Fatalf("error does not describe an ordinary non-match: %v", err)
	}
	if strings.Contains(err.Error(), `configured identity plugin "provider-a" failed`) {
		t.Fatalf("ordinary non-match was reported as a plugin failure: %v", err)
	}
}

func TestPluginIdentityErrorsDoNotExposePluginText(t *testing.T) {
	secret := errors.New("op://vault/item/private-key")
	id := &serializedPluginIdentity{
		name: "provider-a",
		identity: identityFunc(func([]*age.Stanza) ([]byte, error) {
			return nil, secret
		}),
		mutex: new(sync.Mutex),
	}
	_, err := id.Unwrap(nil)
	if err == nil {
		t.Fatal("expected plugin failure")
	}
	if strings.Contains(err.Error(), "op://") {
		t.Fatalf("plugin error text escaped the safe boundary: %v", err)
	}
	if !errors.Is(err, secret) {
		t.Fatalf("wrapped error no longer preserves its cause: %v", err)
	}
}

func TestPluginIdentityMissingExecutableErrorIsSafeAndSpecific(t *testing.T) {
	underlying := &plugin.NotFoundError{
		Name: "provider-a",
		Err:  errors.New("private process detail"),
	}
	id := &serializedPluginIdentity{
		name: "provider-a",
		identity: identityFunc(func([]*age.Stanza) ([]byte, error) {
			return nil, underlying
		}),
		mutex: new(sync.Mutex),
	}
	_, err := id.Unwrap(nil)
	if err == nil {
		t.Fatal("expected missing plugin failure")
	}
	if got := err.Error(); got != `configured identity plugin "provider-a" is unavailable; expected age-plugin-provider-a in PATH` {
		t.Fatalf("error = %q", got)
	}
	if !errors.Is(err, underlying) {
		t.Fatalf("wrapped error no longer preserves its cause: %v", err)
	}
}

func TestLoadIdentityPlugins_invalidName(t *testing.T) {
	_, err := loadIdentityPlugins([]string{"1p", "bad/name"}, &plugin.ClientUI{})
	if err == nil {
		t.Fatal("expected invalid plugin name error")
	}
	if !strings.Contains(err.Error(), `identity plugin "bad/name"`) ||
		!strings.Contains(err.Error(), "invalid plugin name") {
		t.Fatalf("error = %v, want the invalid plugin name and source", err)
	}
}

func TestValidateFlags_identityPluginNames(t *testing.T) {
	if err := validateFlags(&flags{identityPlugins: pluginNames{"1p", "test-plugin_2"}}); err != nil {
		t.Fatalf("valid plugin names rejected: %v", err)
	}
	err := validateFlags(&flags{identityPlugins: pluginNames{"bad/name"}})
	if err == nil || !strings.Contains(err.Error(), `identity plugin "bad/name"`) {
		t.Fatalf("invalid plugin name error = %v", err)
	}
}

func TestValidateFlags_identityPluginsRejectProtocolDebugLogging(t *testing.T) {
	t.Setenv("AGEDEBUG", "plugin")
	err := validateFlags(&flags{identityPlugins: pluginNames{"1p"}})
	if err == nil || !strings.Contains(err.Error(), "raw plugin protocol traffic") ||
		!strings.Contains(err.Error(), "entered secrets") {
		t.Fatalf("AGEDEBUG=plugin error = %v", err)
	}
}

func TestLoadRecipients_mixedKeyTypes(t *testing.T) {
	_, sshPub := genSSHKey(t)
	ageID, _ := age.GenerateX25519Identity()

	content := "# comment\n" + sshPub + ageID.Recipient().String() + "\n"
	recs, err := loadRecipients(writeTestKey(t, []byte(content)))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d recipients, want 2 (one SSH, one age)", len(recs))
	}
}

// A feed fingerprints its recipients by their public key to notice a
// membership change, and an agessh recipient cannot render its own, so the
// loader has to carry it. The authorized_keys comment is not part of the key:
// two lines differing only by it are the same member and must digest the same,
// or editing a comment re-encrypts the whole feed.
func TestLoadRecipients_sshKeysCarryTheirKey(t *testing.T) {
	_, sshPub := genSSHKey(t)
	recs, err := loadRecipients(writeTestKey(t, []byte(sshPub)))
	if err != nil {
		t.Fatal(err)
	}
	bare, ok := recs[0].(interchange.Recipient)
	if !ok {
		t.Fatalf("an SSH recipient must carry its key, got %T", recs[0])
	}
	if bare.Key == "" {
		t.Fatal("an SSH recipient with no key cannot be fingerprinted")
	}
	commented, err := loadRecipients(writeTestKey(t, []byte(strings.TrimRight(sshPub, "\n")+" alex@example.com\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got := commented[0].(interchange.Recipient).Key; got != bare.Key {
		t.Fatalf("the authorized_keys comment must not change the key, got %q want %q", got, bare.Key)
	}
}

func TestLoadRecipients_empty(t *testing.T) {
	// A file with only comments and blank lines yields zero recipients.
	// That must be an error: the operator configured the path expecting
	// keys, so loading nothing silently would defer the failure to a
	// confusing 400 at export time.
	path := writeTestKey(t, []byte("# only a comment\n\n   \n"))
	_, err := loadRecipients(path)
	if err == nil {
		t.Fatal("expected error for a recipients file with no keys")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir available: %v", err)
	}
	cases := []struct{ in, want string }{
		{"", ""},
		{"/etc/recipients.txt", "/etc/recipients.txt"},
		{"relative/path", "relative/path"},
		{"~", home},
		{"~/.ssh/id_ed25519", filepath.Join(home, ".ssh/id_ed25519")},
		{"~notme/keys", "~notme/keys"}, // ~user form is left untouched
	}
	for _, tc := range cases {
		got, err := expandHome(tc.in)
		if err != nil {
			t.Fatalf("expandHome(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("expandHome(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if h, _ := os.UserHomeDir(); h != home {
		t.Skipf("os.UserHomeDir()=%q does not follow $HOME on this platform", h)
	}

	f := &flags{
		dataDir:        "~/data",
		profilesDir:    "~/profiles",
		recipientsFile: "~/keys/recipients.txt",
		identityFile:   "/abs/identity", // absolute — left untouched
		metadataDir:    "~/in-repo",     // in-repo path — must NOT expand
		skillLocal:     skillDirs{"~/skills-a", "./skills-b"},
	}
	if err := f.normalizePaths(); err != nil {
		t.Fatal(err)
	}

	checks := []struct{ name, got, want string }{
		{"dataDir", f.dataDir, filepath.Join(home, "data")},
		{"profilesDir", f.profilesDir, filepath.Join(home, "profiles")},
		{"recipientsFile", f.recipientsFile, filepath.Join(home, "keys/recipients.txt")},
		{"identityFile", f.identityFile, "/abs/identity"},
		{"metadataDir", f.metadataDir, "~/in-repo"},
		{"skillLocal[0]", f.skillLocal[0], filepath.Join(home, "skills-a")},
		{"skillLocal[1]", f.skillLocal[1], "./skills-b"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestFlagsMerge_recipientsAndIdentity(t *testing.T) {
	cfg := &config.Config{
		RecipientsFile: "/etc/recipients.txt",
		IdentityFile:   "/etc/identity.key",
	}
	f := &flags{set: map[string]bool{}}
	f.merge(cfg)
	if f.recipientsFile != cfg.RecipientsFile {
		t.Errorf("recipientsFile = %q, want %q", f.recipientsFile, cfg.RecipientsFile)
	}
	if f.identityFile != cfg.IdentityFile {
		t.Errorf("identityFile = %q, want %q", f.identityFile, cfg.IdentityFile)
	}
}

func TestFlagsMerge_recipientsCliFlagWins(t *testing.T) {
	cfg := &config.Config{RecipientsFile: "/from/config"}
	f := &flags{recipientsFile: "/from/cli", set: map[string]bool{"recipients-file": true}}
	f.merge(cfg)
	if f.recipientsFile != "/from/cli" {
		t.Errorf("CLI flag should win, got %q", f.recipientsFile)
	}
}

func TestFlagsMerge_identityPluginPrecedenceAndIdentityFileCombination(t *testing.T) {
	cfg := &config.Config{
		IdentityFile:    "/from/config.key",
		IdentityPlugins: []string{"config-a", "config-b"},
	}

	fromConfig := &flags{set: map[string]bool{}}
	fromConfig.merge(cfg)
	if fromConfig.identityFile != cfg.IdentityFile ||
		!slices.Equal([]string(fromConfig.identityPlugins), cfg.IdentityPlugins) {
		t.Errorf("config identities not combined: file=%q plugins=%v", fromConfig.identityFile, fromConfig.identityPlugins)
	}

	pluginCLI := &flags{
		identityPlugins: pluginNames{"cli-a", "cli-b"},
		set:             map[string]bool{"identity-plugin": true},
	}
	pluginCLI.merge(cfg)
	if !slices.Equal([]string(pluginCLI.identityPlugins), []string{"cli-a", "cli-b"}) {
		t.Errorf("config overrode CLI plugins: %v", pluginCLI.identityPlugins)
	}
	if pluginCLI.identityFile != cfg.IdentityFile {
		t.Errorf("config identity file was not combined with CLI plugins: %q", pluginCLI.identityFile)
	}

	fileCLI := &flags{
		identityFile: "/from/cli.key",
		set:          map[string]bool{"identity-file": true},
	}
	fileCLI.merge(cfg)
	if fileCLI.identityFile != "/from/cli.key" {
		t.Errorf("config overrode CLI identity file: %q", fileCLI.identityFile)
	}
	if !slices.Equal([]string(fileCLI.identityPlugins), cfg.IdentityPlugins) {
		t.Errorf("config plugins were not combined with CLI identity file: %v", fileCLI.identityPlugins)
	}
}

func TestValidateFederation_identitySources(t *testing.T) {
	for _, tc := range []struct {
		name            string
		recipientsFile  string
		identityFile    string
		identityPlugins pluginNames
		wantErr         bool
	}{
		{name: "file only", recipientsFile: "./recipients.txt", identityFile: "./identity.key"},
		{name: "plugin only", recipientsFile: "./recipients.txt", identityPlugins: pluginNames{"1p"}},
		{name: "both", recipientsFile: "./recipients.txt", identityFile: "./identity.key", identityPlugins: pluginNames{"1p"}},
		{name: "neither", recipientsFile: "./recipients.txt", wantErr: true},
		{name: "plugin without recipients", identityPlugins: pluginNames{"1p"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := flags{
				federationMembersFeed: "git@host:o/f.git",
				recipientsFile:        tc.recipientsFile,
				identityFile:          tc.identityFile,
				identityPlugins:       tc.identityPlugins,
			}
			err := validateFederation(&f)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateFederation error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestBaseURLHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"https://api.anthropic.com", "api.anthropic.com"},
		{"https://my-proxy.corp.com/v1", "my-proxy.corp.com"},
		{"https://my-proxy.corp.com:8443/v1", "my-proxy.corp.com"},
		{"http://localhost:4000", "localhost"},
		{"://broken", ""},
	}
	for _, tc := range cases {
		if got := baseURLHost(tc.in); got != tc.want {
			t.Errorf("baseURLHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLoadSkillsLoadsBundledSkillsWithoutLocalDirectory(t *testing.T) {
	dataDir := t.TempDir()
	gdb, err := db.Open(filepath.Join(dataDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	sha, err := loadSkills(log, gdb, dataDir, nil, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if sha != "" {
		t.Fatalf("skills repo SHA = %q, want empty", sha)
	}
	var count int64
	if err := gdb.Model(&db.Skill{}).Where("source = ?", "bundled").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("no bundled skills loaded")
	}
	var metadata db.Skill
	if err := gdb.Where("name = ?", "metadata").First(&metadata).Error; err != nil {
		t.Fatal(err)
	}
	if metadata.Source != "bundled" || !strings.Contains(metadata.SourcePath, "bundled-skills") {
		t.Fatalf("metadata source = %q path = %q, want materialized bundled source", metadata.Source, metadata.SourcePath)
	}
}

func TestLoadSkillsRejectsRepoUserinfoWithoutEcho(t *testing.T) {
	dataDir := t.TempDir()
	gdb, err := db.Open(filepath.Join(dataDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	const secret = "private-skills-token"

	_, err = loadSkills(log, gdb, dataDir, nil,
		"https://user:"+secret+"@github.com/org/skills", "", false)
	if err == nil {
		t.Fatal("expected URL userinfo to be rejected")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("loadSkills error leaked repository credential: %v", err)
	}
}

func TestLoadSkillsLocalDirectoryOverridesBundledSkill(t *testing.T) {
	dataDir := t.TempDir()
	localRoot := filepath.Join(t.TempDir(), "skills")
	localSkill := filepath.Join(localRoot, "metadata")
	if err := os.MkdirAll(localSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	const body = "---\nname: metadata\ndescription: Local metadata override.\n---\nlocal override body\n"
	if err := os.WriteFile(filepath.Join(localSkill, "SKILL.md"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	gdb, err := db.Open(filepath.Join(dataDir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if _, err := loadSkills(log, gdb, dataDir, skillDirs{localRoot}, "", "", false); err != nil {
		t.Fatal(err)
	}
	var metadata db.Skill
	if err := gdb.Where("name = ?", "metadata").First(&metadata).Error; err != nil {
		t.Fatal(err)
	}
	wantPath, err := filepath.Abs(localSkill)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Source != "local" || metadata.SourcePath != wantPath {
		t.Fatalf("metadata source = %q path = %q, want local path %q", metadata.Source, metadata.SourcePath, wantPath)
	}
	if metadata.Body != "local override body" {
		t.Fatalf("metadata body = %q, want local override", metadata.Body)
	}
	version := metadata.Version
	if _, err := loadSkills(log, gdb, dataDir, skillDirs{localRoot}, "", "", false); err != nil {
		t.Fatal(err)
	}
	if err := gdb.Where("name = ?", "metadata").First(&metadata).Error; err != nil {
		t.Fatal(err)
	}
	if metadata.Version != version {
		t.Fatalf("unchanged local override version = %d, want %d; bundled fallback caused version churn", metadata.Version, version)
	}
}

func TestResolveProfilesDirMaterializesBundledProfilesOutsideCheckout(t *testing.T) {
	t.Chdir(t.TempDir())
	f := &flags{
		dataDir:     t.TempDir(),
		profilesDir: "docker/profiles",
		set:         map[string]bool{},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := resolveProfilesDir(f, &config.Config{}, log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.profilesDir, "bundled-profiles") {
		t.Fatalf("profilesDir = %q, want materialized bundled profiles", f.profilesDir)
	}
	if _, err := os.Stat(filepath.Join(f.profilesDir, "ruby", "Dockerfile")); err != nil {
		t.Fatalf("bundled ruby profile missing: %v", err)
	}
}

func TestResolveProfilesDirFallsBackWhenDockerPathIsNotDirectory(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "docker"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(workDir)
	f := &flags{
		dataDir:     t.TempDir(),
		profilesDir: "docker/profiles",
		set:         map[string]bool{},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := resolveProfilesDir(f, &config.Config{}, log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.profilesDir, "bundled-profiles") {
		t.Fatalf("profilesDir = %q, want materialized bundled profiles", f.profilesDir)
	}
}

func TestResolveProfilesDirPreservesExplicitSelection(t *testing.T) {
	explicit := filepath.Join(t.TempDir(), "profiles")
	f := &flags{
		dataDir:     t.TempDir(),
		profilesDir: explicit,
		set:         map[string]bool{"profiles-dir": true},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := resolveProfilesDir(f, &config.Config{}, log); err != nil {
		t.Fatal(err)
	}
	if f.profilesDir != explicit {
		t.Fatalf("profilesDir = %q, want explicit %q", f.profilesDir, explicit)
	}
}

func TestResolveProfilesDirPreservesCheckoutDefault(t *testing.T) {
	checkout := t.TempDir()
	if err := os.MkdirAll(filepath.Join(checkout, "docker", "profiles"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(checkout)
	f := &flags{
		dataDir:     t.TempDir(),
		profilesDir: "docker/profiles",
		set:         map[string]bool{},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := resolveProfilesDir(f, &config.Config{}, log); err != nil {
		t.Fatal(err)
	}
	if f.profilesDir != "docker/profiles" {
		t.Fatalf("profilesDir = %q, want checkout-relative default", f.profilesDir)
	}
}

func TestResolveProfilesDirPreservesExplicitDisable(t *testing.T) {
	f := &flags{
		dataDir:     t.TempDir(),
		profilesDir: "",
		set:         map[string]bool{"profiles-dir": true},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := resolveProfilesDir(f, &config.Config{}, log); err != nil {
		t.Fatal(err)
	}
	if f.profilesDir != "" {
		t.Fatalf("profilesDir = %q, want explicit disable", f.profilesDir)
	}
}

func TestResolveProfilesDirPreservesConfigDisable(t *testing.T) {
	t.Chdir(t.TempDir())
	f := &flags{
		dataDir:     t.TempDir(),
		profilesDir: "docker/profiles",
		set:         map[string]bool{},
	}
	cfg := &config.Config{ProfilesDir: new("")}
	f.merge(cfg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := resolveProfilesDir(f, cfg, log); err != nil {
		t.Fatal(err)
	}
	if f.profilesDir != "" {
		t.Fatalf("profilesDir = %q, want config disable", f.profilesDir)
	}
	if _, err := os.Stat(filepath.Join(f.dataDir, "bundled-profiles")); !os.IsNotExist(err) {
		t.Fatalf("bundled profiles were materialized despite config disable: %v", err)
	}
}
