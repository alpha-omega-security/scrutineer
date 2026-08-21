package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gorm.io/gorm"

	bundledprofiles "scrutineer/docker/profiles"
	"scrutineer/internal/bundledassets"
	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/interchange"
	"scrutineer/internal/queue"
	"scrutineer/internal/skills"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
	bundledskills "scrutineer/skills"
)

// commit is the git SHA scrutineer was built from, injected at build time
// via -ldflags "-X main.commit=...". Empty in a plain `go build`/`go run`,
// where buildCommit falls back to the VCS revision in the build info.
var commit string

// buildCommit reports the commit scrutineer was built from. It prefers the
// ldflags-injected value (set in the container image build, where .git is excluded
// from the context so the VCS stamp is unavailable) and otherwise reads the
// vcs.revision the Go toolchain records during a normal local build.
func buildCommit() string {
	if commit != "" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}

// skillDirs collects repeated -skills flags.
type skillDirs []string

func (s *skillDirs) String() string     { return strings.Join(*s, ",") }
func (s *skillDirs) Set(v string) error { *s = append(*s, v); return nil }

// pluginNames collects repeated -identity-plugin flags.
type pluginNames []string

func (p *pluginNames) String() string     { return strings.Join(*p, ",") }
func (p *pluginNames) Set(v string) error { *p = append(*p, v); return nil }

const (
	dataPermSecure     = 0o700
	shutdownTimeout    = 5 * time.Second
	skillsCloneTimeout = 2 * time.Minute
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if handled, err := dispatch(os.Args[1:], os.Stdout); handled {
		if err != nil {
			log.Error("command failed", "err", err)
			os.Exit(1)
		}
		return
	}
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// flags holds the merged result of CLI flags and the YAML config file.
// parseFlags fills defaults and CLI overrides; merge layers the config
// file underneath any flag the user set explicitly.
type flags struct {
	configPath            string
	addr                  string
	dataDir               string
	effort                string
	defaultModel          string
	backend               string
	noContainer           bool
	runtime               string
	selinux               string
	hardened              bool
	hardenedRuntimeOnly   bool
	runnerImage           string
	profilesDir           string
	skillsRepo            string
	skillsRepoToken       string
	concurrency           int
	cloneMode             string
	scanTimeout           time.Duration
	smokeTimeout          time.Duration
	maxTurns              int
	modelBaseURL          string
	forkOrg               string
	metadataDir           string
	schemaStrict          bool
	downgradeOnOverage    bool
	recipientsFile        string
	identityFile          string
	identityPlugins       pluginNames
	autoRejectMissedCount int
	ecosystemsEnrichment  bool
	federationSalt        string
	federationContact     string
	federationPublicFeed  string
	federationMembersFeed string
	federationImportFeeds []string
	subprojectScope       string
	monorepoAttribution   bool
	skillLocal            skillDirs

	// set records which flags were passed on the command line so merge
	// knows not to let the config file override them.
	set map[string]bool
}

// validateFederation refuses a federation salt without a contact:
// claim-check would confirm matches while giving peers no way to
// coordinate, which is the endpoint's whole purpose. It also refuses the
// configurations that would leak or misfire: a members feed without age
// recipients would push non-clean certificates in the clear, and one without
// an identity could not read back what it published and so would re-encrypt
// the whole feed on every tick. It trims the feed remotes in f on the way
// through, so a blank one reads as no feed everywhere downstream.
func validateFederation(f *flags) error {
	// Trimmed and emptied out here rather than only inside ValidateFeedRemote,
	// which trims its own copy: a whitespace-only remote otherwise reads as
	// configured for every != "" test below and for StartFederation, which
	// would then clone a remote git cannot resolve, every tick.
	f.federationPublicFeed = strings.TrimSpace(f.federationPublicFeed)
	f.federationMembersFeed = strings.TrimSpace(f.federationMembersFeed)
	var imports []string
	for _, remote := range f.federationImportFeeds {
		if remote = strings.TrimSpace(remote); remote != "" {
			imports = append(imports, remote)
		}
	}
	f.federationImportFeeds = imports
	if f.federationSalt != "" && f.federationContact == "" {
		return errors.New("federation: federation_contact is required when federation_salt is set")
	}
	if f.federationMembersFeed != "" &&
		(f.recipientsFile == "" || (f.identityFile == "" && len(f.identityPlugins) == 0)) {
		return errors.New("federation: recipients_file and either identity_file or identity_plugins are required when federation_members_feed is set")
	}
	if f.federationPublicFeed != "" && f.federationPublicFeed == f.federationMembersFeed {
		return errors.New("federation: the public and members feeds must not share a git remote; each tier prunes the records the other publishes")
	}
	for _, remote := range append([]string{f.federationPublicFeed, f.federationMembersFeed}, f.federationImportFeeds...) {
		if remote == "" {
			continue
		}
		if err := web.ValidateFeedRemote(remote); err != nil {
			return err
		}
	}
	return nil
}

// mergeFederation layers the federation block of the config file under the
// flags, same precedence as merge itself. federation_salt has no flag so
// config always applies, and the two remote lists are config-file only.
func (f *flags) mergeFederation(cfg *config.Config) {
	if cfg.FederationSalt != "" {
		f.federationSalt = cfg.FederationSalt
	}
	if cfg.FederationContact != "" && !f.set["federation-contact"] {
		f.federationContact = cfg.FederationContact
	}
	if cfg.FederationPublicFeed != "" && !f.set["federation-public-feed"] {
		f.federationPublicFeed = cfg.FederationPublicFeed
	}
	if cfg.FederationMembersFeed != "" && !f.set["federation-members-feed"] {
		f.federationMembersFeed = cfg.FederationMembersFeed
	}
	f.federationImportFeeds = cfg.FederationImportFeeds
}

func parseFlags() *flags {
	f := &flags{}
	registerFlags(flag.CommandLine, f)
	flag.Parse()
	// Subcommands are consumed by dispatch() before we get here, so anything
	// left is a stray argument. Refusing it catches the space-separated form
	// of a boolean flag, which the flag package silently drops: `-flag false`
	// leaves the flag at its default and parks "false" here, and for a flag
	// that defaults to true that reads as the exact opposite of what was typed.
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q (booleans take the -flag=false form)\n", flag.Arg(0))
		os.Exit(2) //nolint:mnd // matches flag.ExitOnError's usage-error exit code
	}

	f.set = make(map[string]bool)
	flag.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return f
}

// registerFlags binds every CLI flag onto fs. Split out of parseFlags so a
// test can parse a synthetic argv against a throwaway FlagSet -- in particular
// to prove the deprecated --no-docker alias still maps onto noContainer.
func registerFlags(fs *flag.FlagSet, f *flags) {
	fs.StringVar(&f.configPath, "config", "", "path to YAML config file (default: ./scrutineer.yaml if present)")
	fs.StringVar(&f.addr, "addr", "127.0.0.1:8080", "listen address")
	fs.StringVar(&f.dataDir, "data", "./data", "data directory (db + workspaces)")
	fs.StringVar(&f.effort, "effort", "high", "claude effort")
	fs.StringVar(&f.backend, "backend", "", "agent CLI the container runner execs: "+worker.HarnessNames()+" (default claude). Non-claude backends require the containerised runner")
	fs.StringVar(&f.runtime, "runtime", "docker", "container runtime: docker, podman (rootless supported), or apple (Apple, experimental)")
	fs.StringVar(&f.selinux, "selinux", "auto", "SELinux bind-mount relabeling: auto (relabel when SELinux is detected on the host), on (always), off (never). Relabeling (\":z\") lets the container read /work and write its output on enforcing-SELinux hosts")
	fs.BoolVar(&f.noContainer, "no-container", false, "disable the containerised runner and run claude directly on the host (no isolation), even if a container runtime is available")
	fs.BoolVar(&f.noContainer, "no-docker", false, "deprecated alias for --no-container")
	fs.BoolVar(&f.hardened, "hardened", false, "strict sandbox mode: container runtime required (no --no-container fallback), egress restricted to the harness's model API + host skill API, read-only rootfs, internal network")
	fs.BoolVar(&f.hardenedRuntimeOnly, "hardened-runtime-only", false, "the non-network half of --hardened (read-only rootfs + no-new-privileges + 2 GiB post-clone workspace cap) WITHOUT the per-scan --internal network, so it works under rootless podman where --hardened cannot; --cap-drop ALL + non-root user + tmpfs apply regardless. Implied by --hardened")
	fs.BoolVar(&f.hardenedRuntimeOnly, "hardened-rootless-runtime", false, "deprecated alias for --hardened-runtime-only")
	fs.StringVar(&f.runnerImage, "runner-image", defaultRunnerImage, "container image for per-job containers (a custom image needs curl, and under rootless --hardened the scrutineer binary for the egress sidecar; build from Dockerfile.runner)")
	fs.StringVar(&f.profilesDir, "profiles-dir", "docker/profiles", "directory containing per-ecosystem runner profiles (Dockerfile per profile); empty disables profiles")
	fs.StringVar(&f.skillsRepo, "skills-repo", "", "clone skills on startup; owner/repo[@ref] or https://host/path[@ref]")
	fs.IntVar(&f.concurrency, "concurrency", queue.DefaultWorkerConcurrency, "number of scans to run in parallel")
	fs.StringVar(&f.cloneMode, "clone", "shallow", "clone depth: shallow (--depth 1) or full")
	fs.DurationVar(&f.scanTimeout, "scan-timeout", worker.DefaultScanTimeout, "wall-clock limit per scan")
	fs.DurationVar(&f.smokeTimeout, "runtime-smoke-timeout", defaultRuntimeSmokeTimeout, "timeout for each rootless-podman startup container check (keep-id image remap, SELinux mount probe); raise if first-run image remapping is slow, lower if the image is pre-warmed")
	fs.IntVar(&f.maxTurns, "max-turns", 0, "claude --max-turns limit (0 = unlimited)")
	fs.StringVar(&f.modelBaseURL, "model-base-url", "", "custom HTTPS model API base URL for the active backend (HTTP allowed for local development; env fallback: ANTHROPIC_BASE_URL for claude)")
	fs.StringVar(&f.modelBaseURL, "anthropic-base-url", "", "deprecated alias for -model-base-url")
	fs.StringVar(&f.forkOrg, "fork-org", "", "GitHub org the fork skill forks into and files draft advisories against")
	fs.StringVar(&f.subprojectScope, "subproject-scope", "hard", "how a subproject-scoped scan stages its workspace: \"hard\" (copy only the sub-folder so build+findings are confined to the sub-package) or \"soft\" (stage the whole clone, sub-path is an advisory hint)")
	fs.BoolVar(&f.monorepoAttribution, "monorepo-attribution", true, "link packages, advisories, maintainers and disclosure channel to the sub-package they belong to (matched by manifest name) instead of rolling up flat under the repository")
	fs.BoolVar(&f.schemaStrict, "schema-strict", false, "fail scans whose report.json does not validate against the skill's schema (default: warn and continue)")
	fs.BoolVar(&f.downgradeOnOverage, "downgrade-on-overage", false, "on a subscription token, fall the model tier back from max/high to the mid tier for new scans while the account is on overage; restores when the window resets")
	fs.StringVar(&f.recipientsFile, "recipients-file", "", "age recipients file (public keys) for encrypted export")
	fs.StringVar(&f.identityFile, "identity-file", "", "age identity file or SSH private key for decrypting imports and federation feeds")
	fs.Var(&f.identityPlugins, "identity-plugin", "data-less age identity plugin name for decrypting imports and federation feeds (repeatable)")
	fs.IntVar(&f.autoRejectMissedCount, "auto-reject-missed-count", 0, "auto-reject findings after this many consecutive missed rescans (0 disables)")
	fs.BoolVar(&f.ecosystemsEnrichment, "ecosystems-enrichment", true, "enrich repositories from ecosyste.ms (per-repository cache, warm on repo add, PURL-to-repository resolution); =false stops every lookup scrutineer's own process makes and leaves the dependents cache empty. Takes the -flag=false form")
	// federation_salt has no flag on purpose: a secret in argv leaks via
	// ps and shell history, so it is config-file only.
	fs.StringVar(&f.federationContact, "federation-contact", "", "contact returned by the claim-check endpoint on a finding-hash match")
	fs.StringVar(&f.federationPublicFeed, "federation-public-feed", "", "git remote the public interchange feed is pushed to")
	fs.StringVar(&f.federationMembersFeed, "federation-members-feed", "", "git remote the age-encrypted members interchange feed is pushed to")
	// federation_import_feeds is a list of remotes and is config-file only:
	// a repeatable flag would duplicate what the config file already
	// expresses as a YAML sequence.
	fs.Var(&f.skillLocal, "skills", "additional directory to load SKILL.md files from, overriding bundled skills with the same name (repeatable)")
}

// merge layers cfg underneath f: a config value applies only when the
// matching CLI flag was not set explicitly. Also pushes the model pick
// list and theme into the web package; runtime defaults (model, effort)
// are stored on flags here and applied to the Server after construction.
//
//nolint:gocognit,gocyclo,maintidx // flat: one guarded assignment per config key
func (f *flags) merge(cfg *config.Config) {
	if cfg.Addr != "" && !f.set["addr"] {
		f.addr = cfg.Addr
	}
	if cfg.Data != "" && !f.set["data"] {
		f.dataDir = cfg.Data
	}
	if cfg.Effort != "" && !f.set["effort"] {
		f.effort = cfg.Effort
	}
	if cfg.NoContainer != nil && !f.set["no-container"] && !f.set["no-docker"] {
		f.noContainer = *cfg.NoContainer
	}
	if cfg.Backend != "" && !f.set["backend"] {
		f.backend = cfg.Backend
	}
	if cfg.Runtime != "" && !f.set["runtime"] {
		f.runtime = cfg.Runtime
	}
	if cfg.SELinux != "" && !f.set["selinux"] {
		f.selinux = cfg.SELinux
	}
	if cfg.Hardened != nil && !f.set["hardened"] {
		f.hardened = *cfg.Hardened
	}
	// hardened_runtime_only, with the deprecated hardened_rootless_runtime alias.
	cfgRuntimeOnly := cfg.HardenedRuntimeOnly
	if cfgRuntimeOnly == nil {
		cfgRuntimeOnly = cfg.HardenedRootlessRuntime
	}
	if cfgRuntimeOnly != nil && !f.set["hardened-runtime-only"] && !f.set["hardened-rootless-runtime"] {
		f.hardenedRuntimeOnly = *cfgRuntimeOnly
	}
	if cfg.RunnerImage != "" && !f.set["runner-image"] {
		f.runnerImage = cfg.RunnerImage
	}
	if cfg.ProfilesDir != nil && !f.set["profiles-dir"] {
		f.profilesDir = *cfg.ProfilesDir
	}
	if cfg.SkillsRepo != "" && !f.set["skills-repo"] {
		f.skillsRepo = cfg.SkillsRepo
	}
	// Config-only: a command-line token would be visible in process listings.
	if cfg.SkillsRepoToken != "" {
		f.skillsRepoToken = cfg.SkillsRepoToken
	}
	if len(cfg.Skills) > 0 && !f.set["skills"] {
		f.skillLocal = append(f.skillLocal, cfg.Skills...)
	}
	if cfg.Concurrency > 0 && !f.set["concurrency"] {
		f.concurrency = cfg.Concurrency
	}
	if cfg.Clone != "" && !f.set["clone"] {
		f.cloneMode = cfg.Clone
	}
	if d, _ := config.ParseScanTimeout(cfg.ScanTimeout); d > 0 && !f.set["scan-timeout"] {
		f.scanTimeout = d
	}
	if cfg.MaxTurns > 0 && !f.set["max-turns"] {
		f.maxTurns = cfg.MaxTurns
	}
	if cfg.ModelBaseURL != "" && !f.set["model-base-url"] && !f.set["anthropic-base-url"] {
		f.modelBaseURL = cfg.ModelBaseURL
	}
	if cfg.ForkOrg != "" && !f.set["fork-org"] {
		f.forkOrg = cfg.ForkOrg
	}
	if cfg.SubprojectScope != "" && !f.set["subproject-scope"] {
		f.subprojectScope = cfg.SubprojectScope
	}
	if cfg.MonorepoAttribution != nil && !f.set["monorepo-attribution"] {
		f.monorepoAttribution = *cfg.MonorepoAttribution
	}
	if cfg.MetadataDir != "" {
		f.metadataDir = cfg.MetadataDir
	}
	if cfg.SchemaStrict != nil && !f.set["schema-strict"] {
		f.schemaStrict = *cfg.SchemaStrict
	}
	if cfg.DowngradeOnOverage != nil && !f.set["downgrade-on-overage"] {
		f.downgradeOnOverage = *cfg.DowngradeOnOverage
	}
	if cfg.RecipientsFile != "" && !f.set["recipients-file"] {
		f.recipientsFile = cfg.RecipientsFile
	}
	if cfg.IdentityFile != "" && !f.set["identity-file"] {
		f.identityFile = cfg.IdentityFile
	}
	if len(cfg.IdentityPlugins) > 0 && !f.set["identity-plugin"] {
		f.identityPlugins = append(pluginNames(nil), cfg.IdentityPlugins...)
	}
	if cfg.AutoRejectMissedCount > 0 && !f.set["auto-reject-missed-count"] {
		f.autoRejectMissedCount = cfg.AutoRejectMissedCount
	}
	if cfg.EcosystemsEnrichment != nil && !f.set["ecosystems-enrichment"] {
		f.ecosystemsEnrichment = *cfg.EcosystemsEnrichment
	}
	f.mergeFederation(cfg)

	// Seed the model pick list from the active harness's own defaults,
	// so a fresh install of any backend has a working list with correct
	// tier tags and no operator config. The operator's models: block
	// then overrides. An invalid backend name is caught later by
	// validateFlags; until then, HarnessByName("") gives claude.
	if h, err := worker.HarnessByName(f.backend); err == nil {
		defs := h.DefaultModels()
		models := make([]web.Model, 0, len(defs))
		for _, d := range defs {
			models = append(models, web.Model{Name: d.Name, ID: d.ID, Tier: d.Tier})
		}
		web.SetModels(models)
	}
	if len(cfg.Models) > 0 {
		models := make([]web.Model, 0, len(cfg.Models))
		for _, m := range cfg.Models {
			models = append(models, web.Model{Name: m.Name, ID: m.ID, Tier: m.Tier})
		}
		web.SetModels(models)
	}
	if cfg.DefaultModel != "" {
		f.defaultModel = cfg.DefaultModel
	}
	if cfg.Theme != "" {
		web.SetTheme(cfg.Theme)
	}
}

// applyServerDefaults installs the runtime default model and effort. It warns
// when a configured default_model is not in the pick list: SetDefaultModel
// ignores such an id silently, so the default would otherwise become the first
// pick-list entry with nothing said about it.
func applyServerDefaults(srv *web.Server, f *flags, log *slog.Logger) {
	if f.defaultModel != "" && !web.ValidModel(f.defaultModel) {
		log.Warn("configured default model is not in the pick list; falling back to the first entry",
			"default_model", f.defaultModel, "model", srv.DefaultModel())
	}
	srv.SetDefaultModel(f.defaultModel)
	srv.SetDefaultEffort(f.effort)
}

func (f *flags) fullClone() bool { return f.cloneMode == "full" }

// normalizePaths expands a leading ~ in the host-filesystem paths scrutineer
// opens or creates (data dir, local skill dirs, profiles dir, and the
// recipients/identity key files), so config values like "data: ~/scrutineer"
// work — the shell expands ~ for CLI flags but never for config-file values,
// and Go's os package does no tilde expansion of its own. metadata_dir is
// deliberately excluded (it names a path inside a staging git repo, not a host
// path); skills_repo is a URL, not a path.
func (f *flags) normalizePaths() error {
	for _, p := range []*string{&f.dataDir, &f.profilesDir, &f.recipientsFile, &f.identityFile} {
		expanded, err := expandHome(*p)
		if err != nil {
			return err
		}
		*p = expanded
	}
	for i, dir := range f.skillLocal {
		expanded, err := expandHome(dir)
		if err != nil {
			return err
		}
		f.skillLocal[i] = expanded
	}
	return nil
}

// expandHome expands a leading "~" or "~/" in path to the current user's
// home directory. Go's os.Open/os.ReadFile don't perform tilde expansion
// (only the shell does), so a config value like "~/.ssh/id_ed25519" would
// otherwise fail with file-not-found even though the equivalent CLI example
// works.
func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~")), nil
}

// validateFlags runs the value-validators shared with the YAML config so an
// invalid --clone / --runtime / --selinux fails the same way whether it came
// from a flag or the config file. Split out of run to keep its cognitive
// complexity in check.
func validateFlags(f *flags) error {
	if err := config.ValidateClone(f.cloneMode); err != nil {
		return err
	}
	if _, err := worker.HarnessByName(f.backend); err != nil {
		return err
	}
	if err := config.ValidateRuntime(f.runtime); err != nil {
		return err
	}
	if err := config.ValidateSELinux(f.selinux); err != nil {
		return err
	}
	if err := config.ValidateSubprojectScope(f.subprojectScope); err != nil {
		return err
	}
	if _, err := loadIdentityPlugins(f.identityPlugins, &plugin.ClientUI{}); err != nil {
		return err
	}
	if len(f.identityPlugins) > 0 && os.Getenv("AGEDEBUG") == "plugin" {
		return errors.New("identity plugins: AGEDEBUG=plugin is unsafe because it exposes raw plugin protocol traffic and may expose entered secrets")
	}
	if err := validateFederation(f); err != nil {
		return err
	}
	return validateModelBaseURL(f.modelBaseURL)
}

func isLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func warnIfNonLoopbackListenAddr(log *slog.Logger, addr string) {
	if !isLoopbackListenAddr(addr) {
		log.Warn("scrutineer has no authentication; a non-loopback bind exposes the UI and API to the network", "addr", addr)
	}
}

func configureBackendEnvironment(f *flags, log *slog.Logger) {
	if key := os.Getenv("ANTHROPIC_API_KEY"); strings.HasPrefix(key, "sk-ant-oat") {
		log.Warn("ANTHROPIC_API_KEY looks like an OAuth token from `claude setup-token`; set it as CLAUDE_CODE_OAUTH_TOKEN instead")
	}
	h, _ := worker.HarnessByName(f.backend)
	if _, ok := h.(worker.CodexHarness); ok && os.Getenv("CODEX_API_KEY") == "" && os.Getenv("OPENAI_API_KEY") != "" {
		_ = os.Setenv("CODEX_API_KEY", os.Getenv("OPENAI_API_KEY"))
		log.Warn("using OPENAI_API_KEY as CODEX_API_KEY for codex backend; prefer CODEX_API_KEY for codex exec")
	}

	// Suppress claude-code's telemetry, error reporting, auto-updater and
	// feedback command, and semgrep's metrics POST. The container runner sets
	// these on the container too; setting them here covers the local
	// runner, which inherits host env. The egress proxy already blocks the
	// hosts these reach (DataDog log-intake, metrics.semgrep.dev) so
	// without this the operator just sees denied-CONNECT noise.
	_ = os.Setenv("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
	_ = os.Setenv("SEMGREP_SEND_METRICS", "off")

	if _, ok := h.(worker.ClaudeHarness); !ok {
		return
	}
	if f.modelBaseURL == "" {
		f.modelBaseURL = os.Getenv("ANTHROPIC_BASE_URL")
	}
	// LocalClaude inherits the host env, so writing the resolved value
	// back here is what makes flag/config precedence apply on the local
	// runner path. ContainerRunner gets it explicitly via its struct field.
	if f.modelBaseURL != "" {
		_ = os.Setenv("ANTHROPIC_BASE_URL", f.modelBaseURL)
	}
}

func run(log *slog.Logger) error {
	f := parseFlags()

	cfg, err := config.Load(f.configPath)
	if err != nil {
		return err
	}
	if cfg != nil {
		log.Info("loaded config", "path", cfgPath(f.configPath))
	} else {
		// merge seeds the model pick list from the active harness even
		// when there is no config file to overlay, so a fresh install has
		// a working model dropdown; every field-merge below is a no-op on
		// the zero-value config.
		cfg = &config.Config{}
	}
	f.merge(cfg)
	if err := f.normalizePaths(); err != nil {
		return err
	}
	// Resolve the Claude environment fallback before validation so flags,
	// config, and ANTHROPIC_BASE_URL all pass through the same URL policy.
	configureBackendEnvironment(f, log)
	if err := validateFlags(f); err != nil {
		return err
	}
	warnIfNonLoopbackListenAddr(log, f.addr)
	// When --selinux is given explicitly, surface the host's SELinux mode at
	// startup so the operator can confirm what scrutineer detected (e.g. that an
	// enforcing host will get the :z relabel, or that --selinux=off on an
	// enforcing host is about to break file passing).
	if f.set["selinux"] {
		log.Info("selinux", "flag", f.selinux, "state", worker.HostSELinuxState())
	}
	if err := os.MkdirAll(f.dataDir, dataPermSecure); err != nil {
		return err
	}
	_ = os.Chmod(f.dataDir, dataPermSecure)
	if err := resolveProfilesDir(f, cfg, log); err != nil {
		return err
	}
	// Module-boundary sentinel so go tooling on the parent repo never
	// walks into cloned scan workspaces under data/work/.
	_ = os.WriteFile(filepath.Join(f.dataDir, "go.mod"), []byte("module scrutineer/data\n"), dataPermSecure)

	gdb, err := db.Open(filepath.Join(f.dataDir, "scrutineer.db"))
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	db.BackfillFindings(gdb)
	db.BackfillFindingRepository(gdb)
	db.BackfillFindingFingerprints(gdb)
	db.BackfillStatusPriority(gdb)
	worker.BackfillRepoDiskUsage(gdb, f.dataDir)
	if err := db.SeedDefaultLabels(gdb); err != nil {
		return fmt.Errorf("seed labels: %w", err)
	}
	if err := db.SweepRunning(gdb); err != nil {
		return fmt.Errorf("sweep: %w", err)
	}
	sqldb, err := gdb.DB()
	if err != nil {
		return err
	}

	// A UI-configured concurrency (Settings page) persists in the DB and
	// applies on restart, but an explicit --concurrency flag still wins so
	// the operator who just typed it isn't overridden. Mirrors merge().
	if !f.set["concurrency"] {
		if v := db.SettingInt(gdb, db.SettingConcurrency); v > 0 {
			f.concurrency = v
		}
	}

	q, err := queue.New(sqldb, log, f.concurrency)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}

	skills.ModelValidator = web.ValidModelPreference
	skills.ProfileValidator = worker.IsNamedProfile
	skillsRepoSHA, err := loadSkills(log, gdb, f.dataDir, f.skillLocal, f.skillsRepo, f.skillsRepoToken, f.fullClone())
	if err != nil {
		return err
	}
	retireRemovedSkills(log, gdb)

	go func() {
		if n, err := worker.SyncCNAs(context.Background(), gdb, ""); err != nil {
			log.Warn("CNA sync failed", "err", err)
		} else {
			log.Info("synced CNA list", "count", n)
		}
	}()

	broker := web.NewBroker()

	runner, apiBase, err := setupRunner(f, cfg, log)
	if err != nil {
		return err
	}

	w := &worker.Worker{
		DB:                    gdb,
		Log:                   log,
		DataDir:               filepath.Join(f.dataDir, "work"),
		APIBase:               apiBase,
		ForkOrg:               f.forkOrg,
		MetadataDir:           f.metadataDir,
		Runner:                runner,
		ScanTimeout:           f.scanTimeout,
		SchemaStrict:          f.schemaStrict,
		DowngradeOnOverage:    f.downgradeOnOverage,
		AutoRejectMissedCount: f.autoRejectMissedCount,
		SubprojectScope:       f.subprojectScope,
		MonorepoAttribution:   f.monorepoAttribution,
		OnEvent: func(scanID, repoID uint, name, data string) {
			broker.Publish(web.Event{Name: name, Data: data, ScanID: scanID, RepoID: repoID})
		},
	}
	w.Register(q)

	srv, err := web.New(gdb, q, log, broker, w)
	if err != nil {
		return err
	}
	srv.SkillsRepoSHA = skillsRepoSHA
	srv.Version = version
	wireEcosystems(f.ecosystemsEnrichment, w, srv, gdb, log)
	if h, err := worker.HarnessByName(f.backend); err == nil {
		srv.Backend = worker.HarnessName(h)
	}
	applyServerDefaults(srv, f, log)
	srv.FederationSalt = f.federationSalt
	srv.FederationContact = f.federationContact
	srv.MonorepoAttribution = f.monorepoAttribution
	srv.VINCE = cfg.VINCE
	srv.FederationPublicFeed = f.federationPublicFeed
	srv.FederationMembersFeed = f.federationMembersFeed
	srv.FederationImportFeeds = f.federationImportFeeds

	if err := configureEncryption(srv, f, log); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go q.Start(ctx)
	go srv.StartScheduler(ctx)
	go srv.StartRepositoryHealthScorer(ctx)
	go srv.StartFederation(ctx)

	httpSrv := &http.Server{Addr: f.addr, Handler: srv.Handler(), ReadHeaderTimeout: shutdownTimeout}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()

	// Notice (but never pull) a stale runner image. Runs in the background so a
	// slow or unreachable registry can't delay startup, and fails soft to
	// silence -- see issue #337. A genuine auto-update is left to the operator
	// (watchtower or `--pull=always`); this only surfaces the drift.
	go checkRunnerImage(srv, runner, log)

	log.Info("listening", "addr", "http://"+f.addr)
	if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func configureEncryption(srv *web.Server, f *flags, log *slog.Logger) error {
	if f.recipientsFile != "" {
		recs, err := loadRecipients(f.recipientsFile)
		if err != nil {
			return fmt.Errorf("recipients: %w", err)
		}
		srv.EncRecipients = recs
		log.Info("loaded recipients", "file", f.recipientsFile, "count", len(recs))
	}
	if f.identityFile != "" {
		ids, err := loadIdentities(f.identityFile)
		if err != nil {
			return fmt.Errorf("identity: %w", err)
		}
		srv.EncIdentities = append(srv.EncIdentities, ids...)
		log.Info("loaded identities", "file", f.identityFile, "count", len(ids))
	}
	if len(f.identityPlugins) > 0 {
		ids, err := loadIdentityPlugins(f.identityPlugins, newIdentityPluginUI(log))
		if err != nil {
			return err
		}
		srv.EncIdentities = append(srv.EncIdentities, ids...)
		log.Info("loaded identity plugins", "count", len(ids))
	}
	return nil
}

// wireEcosystems configures the worker's per-scan cache refresh and the
// server's PURL/prefetch seams from a single enrichment setting. When off,
// RefreshEcosystemsCache is left nil so a scan makes no ecosyste.ms call at
// all rather than one that fails against a denied domain, and the server's
// seams are neutered via DisableEcosystems. Called after both are constructed
// but before q.Start, so nothing reads the field before it is set.
func wireEcosystems(enabled bool, w *worker.Worker, srv *web.Server, gdb *gorm.DB, log *slog.Logger) {
	if !enabled {
		srv.DisableEcosystems()
		return
	}
	w.RefreshEcosystemsCache = func(ctx context.Context, repoID uint) error {
		return worker.RefreshEcosystems(ctx, gdb, repoID, true, log)
	}
}

func retireRemovedSkills(log *slog.Logger, gdb *gorm.DB) {
	if err := db.RetireDependentsSkill(gdb); err != nil {
		log.Warn("retire dependents skill failed", "err", err)
	}
}

// checkRunnerImage compares the pulled runner image against the registry and,
// when it is stale (a newer build exists and the local one is past the age
// threshold), logs a one-line nag and records the result so the Settings page
// can show a banner. It is deliberately quiet otherwise: a fresh image, a host
// without a container runtime, or an unreachable registry all produce no output.
func checkRunnerImage(srv *web.Server, runner worker.SkillRunner, log *slog.Logger) {
	image := worker.RunnerImageName(runner)
	if image == "" {
		return // --no-container: no fixed image to compare against.
	}
	ctx, cancel := context.WithTimeout(context.Background(), worker.RunnerStalenessTimeout)
	defer cancel()
	status, ok := worker.RunnerImageStaleness(ctx, worker.RuntimeOf(runner), image)
	if !ok {
		return // couldn't reach a verdict (registry down, image not pulled, ...): stay silent.
	}
	srv.SetRunnerImageStatus(status)
	if status.Stale {
		log.Warn("runner image is stale; update to pick up newer analysis tools",
			"image", image, "age_days", status.AgeDays, "update", status.PullCommand)
	}
}

// loadSkills materialises the skills embedded in the binary, loads configured
// local directories and an optional remote skills repository, then fills every
// name they did not override from the bundled tree. This preserves the
// source-checkout workflow: `-skills ./skills` still points SourcePath at the
// live checkout without a bundled copy temporarily replacing it and bumping its
// version on every restart. Returns the resolved commit SHA of the remote repo
// (empty when no repo is set) so the caller can stamp it on each Scan for
// reproducibility.
func loadSkills(log *slog.Logger, gdb *gorm.DB, dataDir string, dirs skillDirs, repoSpec, repoToken string, fullClone bool) (string, error) {
	bundleDir, bundleHash, err := bundledassets.Materialize(bundledskills.FS, dataDir, "bundled-skills")
	if err != nil {
		return "", fmt.Errorf("materialize bundled skills: %w", err)
	}

	overrides := make(map[string]bool)
	for _, d := range dirs {
		result, err := skills.LoadDirectoryExcept(gdb, log, d, "local", nil)
		if err != nil {
			return "", fmt.Errorf("load skills from %s: %w", d, err)
		}
		for name := range result.Names {
			overrides[name] = true
		}
		log.Info("loaded skills", "source", d, "count", result.Count)
	}

	var sha string
	if repoSpec != "" {
		url, ref, err := skills.ParseRepoSpec(repoSpec)
		if err != nil {
			// repoSpec may come from an older credential-bearing configuration.
			// The parser explains the validation failure without echoing the URL.
			return "", fmt.Errorf("parse skills_repo: %w", err)
		}
		dst := filepath.Join(dataDir, "skills-cache", hashPath(repoSpec))
		ctx, cancel := context.WithTimeout(context.Background(), skillsCloneTimeout)
		defer cancel()
		sha, err = skills.CloneOrPull(ctx, url, ref, dst, fullClone, repoToken)
		if err != nil {
			return "", fmt.Errorf("clone skills repo: %w", err)
		}
		result, err := skills.LoadDirectoryExcept(gdb, log, dst, "remote", nil)
		if err != nil {
			return "", fmt.Errorf("load skills from %s: %w", url, err)
		}
		for name := range result.Names {
			overrides[name] = true
		}
		log.Info("loaded skills", "source", url, "ref", ref, "sha", sha, "count", result.Count)
	}

	bundled, err := skills.LoadDirectoryExcept(gdb, log, bundleDir, skills.SourceBundled, overrides)
	if err != nil {
		return "", fmt.Errorf("load bundled skills: %w", err)
	}
	log.Info("loaded bundled skills", "source", bundleDir, "bundle", bundleHash, "count", bundled.Count, "overridden", len(overrides))
	return sha, nil
}

// resolveProfilesDir preserves every existing profile selection while making
// the zero-configuration binary independent of the source checkout. An
// explicit flag or config value always wins, including `-profiles-dir ""` to
// disable profiles. The historical docker/profiles default is retained when
// that directory exists (the normal `go run` development workflow); otherwise
// the profiles embedded in the binary are materialised below the data root.
func resolveProfilesDir(f *flags, cfg *config.Config, log *slog.Logger) error {
	const checkoutDefault = "docker/profiles"
	if f.set["profiles-dir"] || (cfg != nil && cfg.ProfilesDir != nil) || f.profilesDir != checkoutDefault {
		return nil
	}
	if info, err := os.Stat(checkoutDefault); err == nil && info.IsDir() {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
		return fmt.Errorf("stat profiles directory: %w", err)
	}
	dir, hash, err := bundledassets.Materialize(bundledprofiles.FS, f.dataDir, "bundled-profiles")
	if err != nil {
		return fmt.Errorf("materialize bundled profiles: %w", err)
	}
	f.profilesDir = dir
	log.Info("using bundled runner profiles", "source", dir, "bundle", hash)
	return nil
}

func addrPort(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return addr
}

func hashPath(s string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "?", "_", "&", "_", "=", "_")
	return r.Replace(s)
}

// defaultRuntimeSmokeTimeout bounds each container startup check (rootless
// keep-id and the SELinux bind-mount probe) so a hung runtime daemon can't
// block startup indefinitely. It is deliberately generous (minutes, not
// seconds): the FIRST rootless `--userns=keep-id` run remaps/chowns the entire
// runner image into the operator's subuid range, a one-time cost roughly
// proportional to image size (~1 min for the default runner image on overlay;
// slower disks or larger profile images take longer). The previous 30s bound
// killed that remap mid-flight, which both failed startup AND left an
// incomplete image layer podman had to delete on the next run. Operators can
// override (e.g. lower it once the image is pre-warmed) with
// -runtime-smoke-timeout.
const defaultRuntimeSmokeTimeout = 5 * time.Minute

// setupRunner picks the SkillRunner implementation for the run loop:
// ContainerRunner (docker, podman, or Apple's container) when a container runtime is in use,
// LocalClaude otherwise. It also starts the egress proxy, sweeps stale hardened
// networks, runs the rootless keep-id smoke test, and returns the apiBase the
// worker advertises to skills (the container path rewrites it to the selected
// runtime's host endpoint so containers can reach the loopback-bound web
// server through the egress proxy).
//
//nolint:ireturn // dispatched on f.noContainer; concrete types live in the worker pkg
func setupRunner(f *flags, cfg *config.Config, log *slog.Logger) (worker.SkillRunner, string, error) {
	apiBase := "http://" + f.addr + "/api"
	// Already validated in run(); ignore the error here.
	h, _ := worker.HarnessByName(f.backend)
	_, isClaude := h.(worker.ClaudeHarness)
	if f.hardened && f.noContainer {
		return nil, "", fmt.Errorf("--hardened requires a container runtime; remove --no-container")
	}
	if !isClaude && f.noContainer {
		return nil, "", fmt.Errorf("backend %q requires the containerised runner; remove --no-container", f.backend)
	}
	if f.hardenedRuntimeOnly && f.noContainer {
		log.Warn("--hardened-runtime-only has no effect with --no-container (no container to harden)")
	}
	if f.noContainer {
		log.Info("--no-container set, using local runner (no isolation)")
		return worker.LocalClaude{Effort: f.effort, FullClone: f.fullClone(), MaxTurns: f.maxTurns}, apiBase, nil
	}
	rt, ok := worker.DetectRuntime(f.runtime)
	if !ok {
		if f.hardened {
			return nil, "", fmt.Errorf("%s not available: --hardened requires a container runtime, install and start it", f.runtime)
		}
		return nil, "", fmt.Errorf("%s not available: install and start it, or pass --no-container to run without containerisation (no isolation)", f.runtime)
	}
	if err := rt.HardeningSupportError(f.hardenedRuntimeOnly); err != nil {
		return nil, "", err
	}
	if rt.Bin == "apple" {
		log.Warn("Apple container runtime support is experimental", "version", rt.Version)
		if f.hardened {
			log.Info("Apple hardened mode: per-container VM boundary substitutes for " +
				"--security-opt no-new-privileges (not exposed by Apple's CLI); the " +
				"per-scan --internal network is verified fail-closed before each scan")
		}
	}
	// Older podman lacks the host-gateway alias the egress path needs; warn
	// rather than fail since the hardened path verifies reachability per-scan.
	if !rt.HostGatewaySupported() {
		log.Warn("podman may be too old for host-gateway egress; upgrade to >= 4.7", "version", rt.Version)
	}
	// Rootless podman needs an adequate /etc/subuid range for --userns=keep-id;
	// smoke-test it once so a misconfiguration is one clear error here rather
	// than a cryptic bind-mount failure on every scan. The first such run also
	// remaps the whole runner image into the subuid range and can take a minute
	// (see defaultRuntimeSmokeTimeout); log it so that pause isn't a silent hang.
	if rt.NeedsKeepID() {
		log.Info("verifying rootless keep-id mapping (first run remaps the runner image into your subuid range and can take ~a minute)")
	}
	smokeCtx, cancel := context.WithTimeout(context.Background(), f.smokeTimeout)
	defer cancel()
	if err := worker.VerifyKeepID(smokeCtx, rt, f.runnerImage); err != nil {
		return nil, "", err
	}
	// SELinux bind-mount relabeling (--selinux auto/on/off). Resolve it once
	// here -- "auto" consults the host -- then prove a real relabeled mount works
	// so an SELinux denial fails at startup instead of on every scan's file
	// passing. Both no-op on a non-SELinux host with relabeling off (the default
	// there), keeping that path unchanged.
	relabel := worker.ResolveSELinuxRelabel(f.selinux)
	selinuxCtx, cancelSE := context.WithTimeout(context.Background(), f.smokeTimeout)
	defer cancelSE()
	if err := worker.VerifySELinuxMount(selinuxCtx, rt, f.runnerImage, relabel); err != nil {
		return nil, "", err
	}
	gwIP, apiHost, err := resolveScanNetworking(rt, f, log)
	if err != nil {
		return nil, "", err
	}
	var egress worker.EgressSidecarConfig
	var configuredProviders map[string]config.OpencodeProvider
	if cfg != nil {
		configuredProviders = cfg.Opencode.Providers
	}
	opencodeProviders, err := loadOpencodeProviders(h, configuredProviders, cfgPath(f.configPath))
	if err != nil {
		return nil, "", err
	}
	allow := buildEgressAllow(h.EgressHosts(), f.hardened, cfg, f.modelBaseURL, log)
	if apiHost != worker.HostGatewayAlias {
		allow = append(allow, apiHost)
	}
	token := worker.NewProxyToken()
	// Rootless --hardened runs the egress proxy as a per-scan sidecar reusing
	// this allow-list and token; resolve it before the in-process host proxy so
	// the latter can be skipped when the sidecar is in charge.
	if f.hardened {
		egress, err = resolveEgressSidecar(rt, f, allow, token, log)
		if err != nil {
			return nil, "", err
		}
	}
	// With a sidecar every scan routes through it (buildRunArgs shadows
	// ProxyURL with the sidecar endpoint), so the host proxy would only open an
	// unused host port -- skip it and leave port at 0 / ProxyURL empty.
	var port int
	var proxyURL string
	if egress.GatewayIP == "" {
		port, err = worker.StartEgressProxy(&worker.EgressProxy{
			Allow:    allow,
			Token:    token,
			APIPort:  addrPort(f.addr),
			APIHosts: []string{apiHost},
			Log:      log,
		})
		if err != nil {
			return nil, "", fmt.Errorf("start egress proxy: %w", err)
		}
		proxyURL = worker.ProxyURLForHost(token, apiHost, port)
	}
	log.Info("container runtime detected, using containerised runner",
		"runtime", rt.Bin, "rootless", rt.Rootless, "harness", h.Binary(), "image", f.runnerImage,
		"egress_proxy_port", port, "egress_allow", len(allow),
		"container_host", apiHost, "host_gateway_ipv4", gwIP, "hardened", f.hardened,
		"egress_sidecar", egress.GatewayIP != "",
		"hardened_runtime_only", f.hardenedRuntimeOnly, "selinux_relabel", relabel)
	// Skills inside the container reach the host via the runtime's host endpoint,
	// which the egress proxy rewrites to 127.0.0.1 when dialing the app.
	apiBase = "http://" + net.JoinHostPort(apiHost, addrPort(f.addr)) + "/api"
	return worker.ContainerRunner{
		Image:               f.runnerImage,
		Effort:              f.effort,
		Harness:             h,
		ProxyURL:            proxyURL,
		FullClone:           f.fullClone(),
		MaxTurns:            f.maxTurns,
		ModelBaseURL:        f.modelBaseURL,
		HostGatewayIP:       gwIP,
		ProfilesDir:         f.profilesDir,
		Hardened:            f.hardened,
		HardenedRuntimeOnly: f.hardenedRuntimeOnly,
		Runtime:             rt,
		SELinuxRelabel:      relabel,
		Egress:              egress,
		ProviderProxy: worker.ScopedEgressProxyConfig{
			Allow:         allow,
			APIPort:       addrPort(f.addr),
			APIHosts:      []string{apiHost},
			ContainerHost: apiHost,
			Log:           log,
		},
		OpencodeProviders: opencodeProviders,
		OpencodeReadiness: worker.NewOpencodeReadinessCache(),
	}, apiBase, nil
}

func loadOpencodeProviders(h worker.Harness, providers map[string]config.OpencodeProvider, configPath string) (map[string]worker.OpencodeProviderConfig, error) {
	if worker.HarnessName(h) != "opencode" || len(providers) == 0 {
		return nil, nil
	}
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("resolve OpenCode config path: %w", err)
	}
	baseDir := filepath.Dir(absConfig)
	result := make(map[string]worker.OpencodeProviderConfig, len(providers))
	for id, provider := range providers {
		configFile, err := resolveOpencodeHostPath(baseDir, provider.ConfigFile)
		if err != nil {
			return nil, fmt.Errorf("opencode.providers.%s.config_file: %w", id, err)
		}
		stateDir, err := resolveOpencodeHostPath(baseDir, provider.StateDir)
		if err != nil {
			return nil, fmt.Errorf("opencode.providers.%s.state_dir: %w", id, err)
		}
		var configContent string
		if configFile != "" {
			content, err := os.ReadFile(configFile)
			if err != nil {
				return nil, fmt.Errorf("read opencode.providers.%s.config_file: %w", id, err)
			}
			configContent = string(content)
		}
		var hostPort string
		if provider.HostPort > 0 {
			hostPort = strconv.Itoa(provider.HostPort)
		}
		result[id] = worker.OpencodeProviderConfig{
			RunnerImage:      provider.RunnerImage,
			ConfigContent:    configContent,
			APIKeyEnv:        provider.APIKeyEnv,
			AuthMetadata:     provider.AuthMetadata,
			PassEnv:          append([]string(nil), provider.PassEnv...),
			RequiredBinaries: append([]string(nil), provider.RequiredBinaries...),
			EgressHosts:      append([]string(nil), provider.EgressAllow...),
			HostPort:         hostPort,
			StateDir:         stateDir,
		}
	}
	return result, nil
}

func resolveOpencodeHostPath(baseDir, path string) (string, error) {
	if path == "" {
		return "", nil
	}
	expanded, err := expandHome(path)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(baseDir, expanded)
	}
	return filepath.Clean(expanded), nil
}

// resolveScanNetworking prepares per-scan networking before the egress proxy
// starts. In hardened mode it owns its per-scan networks -- the gateway IP is
// probed inside RunSkill against the network the runner will actually attach to,
// so it is left empty here -- and it sweeps orphan sidecars and networks left
// behind by crashed scans. Outside hardened mode it resolves the host-gateway
// IPv4 and the host the container reaches the skill API on: apiHost defaults to
// the host-gateway alias, and only Apple (which has no --add-host) needs the
// resolved gateway IP, where failing to resolve it is fatal.
func resolveScanNetworking(rt worker.ContainerRuntime, f *flags, log *slog.Logger) (gwIP, apiHost string, err error) {
	apiHost = worker.HostGatewayAlias
	if f.hardened {
		// Crash residue cleanup: remove orphan egress proxy sidecars first (a
		// lingering sidecar pins its per-scan network), then the freed networks.
		if removed, err := worker.SweepOrphanProxySidecars(rt); err != nil {
			log.Warn("orphan proxy sidecar sweep failed", "err", err)
		} else if removed > 0 {
			log.Info("removed orphan egress proxy sidecars", "count", removed)
		}
		if removed, err := worker.SweepOrphanHardenedNetworks(rt); err != nil {
			log.Warn("orphan hardened network sweep failed", "err", err)
		} else if removed > 0 {
			log.Info("removed orphan hardened networks", "count", removed)
		}
		return gwIP, apiHost, nil
	}
	gwIP = worker.ResolveHostGatewayIPv4(rt, f.runnerImage, "")
	switch {
	case rt.Bin == "podman" && gwIP == "":
		// Reuses the resolve probe just run (no extra launch). An empty
		// result means host-gateway is not wired, so containers cannot reach
		// the host egress proxy and scans will fail with network errors --
		// surface the likely cause now rather than once per scan.
		log.Warn("host-gateway did not resolve under podman; scans may fail to " +
			"reach the network because the container cannot reach the host egress " +
			"proxy (needs podman >= 4.7; see docs/podman.md)")
	case rt.Bin == "apple":
		if gwIP == "" {
			return "", "", fmt.Errorf("could not resolve the Apple container host gateway; cannot route scans to the egress proxy")
		}
		apiHost = gwIP
	}
	return gwIP, apiHost, nil
}

// resolveEgressSidecar builds the egress proxy sidecar config for a rootless
// --hardened run. It resolves the default-network host-gateway the sidecar dials
// to reach the loopback-bound host skill API, and warns when the podman backend
// may not forward host-gateway to the host loopback. Returns the zero value (no
// sidecar) for docker, rootful podman, and any non-rootless run -- those keep
// the in-process host proxy.
func resolveEgressSidecar(rt worker.ContainerRuntime, f *flags, allow []string, token string, log *slog.Logger) (worker.EgressSidecarConfig, error) {
	if !rt.NeedsEgressSidecar() {
		return worker.EgressSidecarConfig{}, nil
	}
	// Fail fast if the runner image lacks the scrutineer binary the sidecar runs,
	// rather than letting every hardened scan fail with a cryptic per-scan error.
	smokeCtx, cancel := context.WithTimeout(context.Background(), f.smokeTimeout)
	defer cancel()
	if err := worker.VerifyProxyBinary(smokeCtx, rt, f.runnerImage); err != nil {
		return worker.EgressSidecarConfig{}, err
	}
	// Rootless podman: the per-scan --internal network cannot reach the host
	// proxy, so egress runs through a proxy sidecar on the network. The sidecar
	// reaches the host skill API over its egress leg via the default-network
	// host-gateway, resolved once here.
	if !rt.HostLoopbackBackendLikely() {
		log.Warn("podman < 5.0 does not default to the pasta network backend; the egress proxy "+
			"sidecar needs the backend to forward host-gateway to the host loopback (pasta "+
			"--map-host-loopback, default in podman >= 5.0, or slirp4netns with host-loopback). "+
			"Hardened scans are refused fail-closed if it is unavailable; see docs/egress-sidecar.md",
			"version", rt.Version)
	}
	egressGwIP := worker.ResolveHostGatewayIPv4(rt, f.runnerImage, "")
	if egressGwIP == "" {
		log.Warn("host-gateway did not resolve under rootless podman; hardened scans will be refused " +
			"because the egress proxy sidecar cannot reach the host skill API (needs podman >= 4.7 and a " +
			"working rootless network backend; see docs/podman.md)")
	}
	return worker.EgressSidecarConfig{Token: token, Allow: allow, APIPort: addrPort(f.addr), GatewayIP: egressGwIP}, nil
}

// buildEgressAllow assembles the proxy allowlist: the harness's
// model-API hosts first, then the harness-neutral base. Hardened mode
// starts from HardenedEgressAllow and ignores cfg.EgressAllow (the
// operator must drop --hardened to widen). The model base URL host is
// still auto-added in both modes since it routes the same model API.
//
// ecosystems_enrichment deliberately does NOT filter *.ecosyste.ms out of
// this list. Dropping it would 403 the metadata, packages and advisories
// skills, which triage runs unconditionally, and their parsers replace the
// repository's whole row set: a blessed empty report would wipe the packages
// and advisories already recorded. The setting stops the enrichment
// scrutineer's own process performs; denying the domain to the runner is the
// operator's network policy to write.
func buildEgressAllow(harnessHosts []string, hardened bool, cfg *config.Config, modelBaseURL string, log *slog.Logger) []string {
	allow := append([]string{}, harnessHosts...)
	if hardened {
		allow = append(allow, worker.HardenedEgressAllow...)
		if cfg != nil && len(cfg.EgressAllow) > 0 {
			log.Warn("ignoring egress_allow config entries under --hardened", "count", len(cfg.EgressAllow))
		}
	} else {
		allow = append(allow, worker.DefaultEgressAllow...)
		if cfg != nil {
			allow = append(allow, cfg.EgressAllow...)
		}
	}
	if h := baseURLHost(modelBaseURL); h != "" {
		allow = append(allow, h)
		log.Info("added model base URL host to egress allowlist", "host", h)
	}
	return allow
}

func baseURLHost(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// validateModelBaseURL requires transport encryption for remote model APIs.
// Loopback and the container host-gateway alias remain available over HTTP for
// local model/proxy development.
func validateModelBaseURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("model base URL must be an absolute URL")
	}
	if strings.EqualFold(u.Scheme, "https") ||
		(strings.EqualFold(u.Scheme, "http") && localModelHost(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("model base URL must use https (http is allowed only for local development)")
}

func localModelHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, worker.HostGatewayAlias) {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// cfgPath returns the path the loader actually used for logging.
func cfgPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return config.DefaultPath
}

// loadRecipients parses a flat text file of public keys (one per line,
// '#' comments). Both age X25519 and SSH public keys are accepted. A
// configured file that yields zero recipients is treated as an error: the
// operator asked for encrypted export, so silently loading nothing would
// only surface later as a confusing 400 at request time. The path is assumed
// already tilde-expanded by normalizePaths.
func loadRecipients(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []age.Recipient
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r age.Recipient
		var perr error
		switch {
		case strings.HasPrefix(line, "age1"):
			r, perr = age.ParseX25519Recipient(line)
		case strings.HasPrefix(line, "ssh-"):
			// An agessh recipient keeps no handle on its key, and the feed's
			// rotation check needs one to notice a membership change, so it is
			// captured here. The marshalled form rather than the line itself:
			// the trailing comment is not part of the key and must not read as
			// a new recipient set.
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				return nil, err
			}
			if r, perr = agessh.ParseRecipient(line); perr == nil {
				r = interchange.Recipient{Recipient: r, Key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))}
			}
		default:
			perr = fmt.Errorf("unrecognised recipient key format: %q", line)
		}
		if perr != nil {
			return nil, perr
		}
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no recipients found in %s (expected one age or SSH public key per line)", path)
	}
	return out, nil
}

// loadIdentities reads an age identity file (one or more AGE-SECRET-KEY
// lines) or an SSH private key (PEM). Both formats are auto-detected.
// Encrypted SSH keys are supported: when one is detected, the user is
// prompted for the passphrase on stdin (echo disabled). The path is assumed
// already tilde-expanded by normalizePaths.
func loadIdentities(path string) ([]age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// SSH private keys start with a PEM header.
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		id, err := agessh.ParseIdentity(data)
		if err == nil {
			return []age.Identity{id}, nil
		}
		// Encrypted SSH key — prompt for passphrase.
		var pme *ssh.PassphraseMissingError
		if !errors.As(err, &pme) {
			return nil, fmt.Errorf("parse SSH identity: %w", err)
		}
		if pme.PublicKey == nil {
			return nil, fmt.Errorf("encrypted SSH key has no embedded public key; use the OpenSSH format or provide an unencrypted key")
		}
		passphrase, err := promptPassphrase(path)
		if err != nil {
			return nil, err
		}
		// Validate the passphrase immediately so startup fails fast.
		if _, err := ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase); err != nil {
			return nil, fmt.Errorf("wrong passphrase for %s", path)
		}
		eid, err := agessh.NewEncryptedSSHIdentity(pme.PublicKey, data, func() ([]byte, error) {
			return passphrase, nil
		})
		if err != nil {
			return nil, fmt.Errorf("encrypted SSH identity: %w", err)
		}
		return []age.Identity{eid}, nil
	}
	// Fall back to age-native identity format.
	ids, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse age identity: %w", err)
	}
	return ids, nil
}

// serializedPluginIdentity keeps terminal-backed plugin interactions from
// overlapping across concurrent imports and federation passes. It also keeps
// plugin-supplied error text behind a stable, provider-neutral boundary while
// preserving the underlying error for errors.Is/errors.As and age's identity
// fallback behavior.
type serializedPluginIdentity struct {
	name     string
	identity age.Identity
	mutex    *sync.Mutex
}

func (i *serializedPluginIdentity) Name() string { return i.name }

func (i *serializedPluginIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	fileKey, err := i.identity.Unwrap(stanzas)
	if err != nil {
		// A non-match is normal age control flow, not a plugin malfunction.
		// Canonicalize it to age's own sentinel so NoIdentityMatchError stays
		// accurate without carrying any plugin-controlled error text.
		if errors.Is(err, age.ErrIncorrectIdentity) {
			return nil, age.ErrIncorrectIdentity
		}
		return nil, &pluginIdentityError{name: i.name, err: err}
	}
	return fileKey, nil
}

type pluginIdentityError struct {
	name string
	// err is retained only for errors.Is/errors.As. It can contain
	// plugin-controlled protocol text and must not be logged or returned
	// directly to a user.
	err error
}

func (e *pluginIdentityError) Error() string {
	var notFound *plugin.NotFoundError
	if errors.As(e.err, &notFound) {
		return fmt.Sprintf(
			"configured identity plugin %q is unavailable; expected age-plugin-%s in PATH",
			e.name, e.name)
	}
	return fmt.Sprintf("configured identity plugin %q failed", e.name)
}

func (e *pluginIdentityError) Unwrap() error { return e.err }

// loadIdentityPlugins constructs data-less age plugin identities, equivalent
// to age's -j option. Construction validates names but does not start plugin
// executables or trigger authentication; that is deferred until decryption
// needs an identity.
func loadIdentityPlugins(names []string, ui *plugin.ClientUI) ([]age.Identity, error) {
	identities := make([]age.Identity, 0, len(names))
	mutex := new(sync.Mutex)
	for _, name := range names {
		identity, err := plugin.NewIdentityWithoutData(name, ui)
		if err != nil {
			return nil, fmt.Errorf("identity plugin %q: %w", name, err)
		}
		identities = append(identities, &serializedPluginIdentity{
			name:     name,
			identity: identity,
			mutex:    mutex,
		})
	}
	return identities, nil
}

// newIdentityPluginUI uses age's terminal UI so plugins can request public or
// secret input directly from the controlling terminal. Only display messages
// and UI errors reach structured logs; values entered by the user and raw age
// plugin protocol traffic do not.
func newIdentityPluginUI(log *slog.Logger) *plugin.ClientUI {
	return plugin.NewTerminalUI(
		func(format string, args ...any) {
			log.Info("age identity plugin", "message", fmt.Sprintf(format, args...))
		},
		func(format string, args ...any) {
			log.Warn("age identity plugin", "message", fmt.Sprintf(format, args...))
		},
	)
}

// promptPassphrase is the function called when an encrypted SSH key needs
// a passphrase. Variable so tests can substitute a non-interactive provider.
var promptPassphrase = defaultPromptPassphrase

func defaultPromptPassphrase(keyPath string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("encrypted SSH key %s requires a passphrase but stdin is not a terminal", keyPath)
	}
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", keyPath)
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	return pass, nil
}
