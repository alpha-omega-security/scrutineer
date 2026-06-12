package main

import (
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
	"strings"
	"syscall"
	"time"

	"gorm.io/gorm"

	"scrutineer/internal/config"
	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/skills"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
)

// commit is the git SHA scrutineer was built from, injected at build time
// via -ldflags "-X main.commit=...". Empty in a plain `go build`/`go run`,
// where buildCommit falls back to the VCS revision in the build info.
var commit string

// buildCommit reports the commit scrutineer was built from. It prefers the
// ldflags-injected value (set in the Docker build, where .git is excluded
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
	configPath       string
	addr             string
	dataDir          string
	effort           string
	noDocker         bool
	hardened         bool
	runnerImage      string
	profilesDir      string
	skillsRepo       string
	concurrency      int
	cloneMode        string
	scanTimeout      time.Duration
	maxTurns         int
	anthropicBaseURL string
	forkOrg          string
	metadataDir      string
	schemaStrict     bool
	skillLocal       skillDirs

	// set records which flags were passed on the command line so merge
	// knows not to let the config file override them.
	set map[string]bool
}

func parseFlags() *flags {
	f := &flags{}
	flag.StringVar(&f.configPath, "config", "", "path to YAML config file (default: ./scrutineer.yaml if present)")
	flag.StringVar(&f.addr, "addr", "127.0.0.1:8080", "listen address")
	flag.StringVar(&f.dataDir, "data", "./data", "data directory (db + workspaces)")
	flag.StringVar(&f.effort, "effort", "high", "claude effort")
	flag.BoolVar(&f.noDocker, "no-docker", false, "disable containerised runner even if docker is available")
	flag.BoolVar(&f.hardened, "hardened", false, "strict sandbox mode: docker required (no --no-docker fallback), egress restricted to *.anthropic.com + host skill API, read-only rootfs, internal docker network")
	flag.StringVar(&f.runnerImage, "runner-image", worker.DefaultRunnerImage, "docker image for per-job containers")
	flag.StringVar(&f.profilesDir, "profiles-dir", "docker/profiles", "directory containing per-ecosystem runner profiles (Dockerfile per profile); empty disables profiles")
	flag.StringVar(&f.skillsRepo, "skills-repo", "", "clone skills on startup; owner/repo[@ref] or https://host/path[@ref]")
	flag.IntVar(&f.concurrency, "concurrency", queue.DefaultWorkerConcurrency, "number of scans to run in parallel")
	flag.StringVar(&f.cloneMode, "clone", "shallow", "clone depth: shallow (--depth 1) or full")
	flag.DurationVar(&f.scanTimeout, "scan-timeout", worker.DefaultScanTimeout, "wall-clock limit per scan")
	flag.IntVar(&f.maxTurns, "max-turns", 0, "claude --max-turns limit (0 = unlimited)")
	flag.StringVar(&f.anthropicBaseURL, "anthropic-base-url", "", "custom Anthropic API base URL (env: ANTHROPIC_BASE_URL)")
	flag.StringVar(&f.forkOrg, "fork-org", "", "GitHub org the fork skill forks into and files draft advisories against")
	flag.BoolVar(&f.schemaStrict, "schema-strict", false, "fail scans whose report.json does not validate against the skill's schema (default: warn and continue)")
	flag.Var(&f.skillLocal, "skills", "directory to load SKILL.md files from (repeatable)")
	flag.Parse()

	f.set = make(map[string]bool)
	flag.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return f
}

// merge layers cfg underneath f: a config value applies only when the
// matching CLI flag was not set explicitly. Also pushes model overrides
// into the web package.
//
//nolint:gocognit,gocyclo // flat: one guarded assignment per config key
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
	if cfg.NoDocker != nil && !f.set["no-docker"] {
		f.noDocker = *cfg.NoDocker
	}
	if cfg.Hardened != nil && !f.set["hardened"] {
		f.hardened = *cfg.Hardened
	}
	if cfg.RunnerImage != "" && !f.set["runner-image"] {
		f.runnerImage = cfg.RunnerImage
	}
	if cfg.ProfilesDir != "" && !f.set["profiles-dir"] {
		f.profilesDir = cfg.ProfilesDir
	}
	if cfg.SkillsRepo != "" && !f.set["skills-repo"] {
		f.skillsRepo = cfg.SkillsRepo
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
	if cfg.AnthropicBaseURL != "" && !f.set["anthropic-base-url"] {
		f.anthropicBaseURL = cfg.AnthropicBaseURL
	}
	if cfg.ForkOrg != "" && !f.set["fork-org"] {
		f.forkOrg = cfg.ForkOrg
	}
	if cfg.MetadataDir != "" {
		f.metadataDir = cfg.MetadataDir
	}
	if cfg.SchemaStrict != nil && !f.set["schema-strict"] {
		f.schemaStrict = *cfg.SchemaStrict
	}

	if len(cfg.Models) > 0 {
		models := make([]web.Model, 0, len(cfg.Models))
		for _, m := range cfg.Models {
			models = append(models, web.Model{Name: m.Name, ID: m.ID})
		}
		web.SetModels(models)
	}
	if cfg.DefaultModel != "" {
		web.SetDefaultModel(cfg.DefaultModel)
	}
	web.SetDefaultEffort(f.effort)
	if cfg.Theme != "" {
		web.SetTheme(cfg.Theme)
	}
}

func (f *flags) fullClone() bool { return f.cloneMode == "full" }

func run(log *slog.Logger) error {
	f := parseFlags()

	cfg, err := config.Load(f.configPath)
	if err != nil {
		return err
	}
	if cfg != nil {
		f.merge(cfg)
		log.Info("loaded config", "path", cfgPath(f.configPath))
	}
	if err := config.ValidateClone(f.cloneMode); err != nil {
		return err
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); strings.HasPrefix(key, "sk-ant-oat") {
		log.Warn("ANTHROPIC_API_KEY looks like an OAuth token from `claude setup-token`; set it as CLAUDE_CODE_OAUTH_TOKEN instead")
	}

	// Suppress claude-code's telemetry, error reporting, auto-updater and
	// feedback command, and semgrep's metrics POST. The docker runner sets
	// these on the container too; setting them here covers the local
	// runner, which inherits host env. The egress proxy already blocks the
	// hosts these reach (DataDog log-intake, metrics.semgrep.dev) so
	// without this the operator just sees denied-CONNECT noise.
	_ = os.Setenv("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
	_ = os.Setenv("SEMGREP_SEND_METRICS", "off")

	if f.anthropicBaseURL == "" {
		f.anthropicBaseURL = os.Getenv("ANTHROPIC_BASE_URL")
	}
	// LocalClaude inherits the host env, so writing the resolved value
	// back here is what makes flag/config precedence apply on the local
	// runner path. DockerRunner gets it explicitly via its struct field.
	if f.anthropicBaseURL != "" {
		_ = os.Setenv("ANTHROPIC_BASE_URL", f.anthropicBaseURL)
	}

	if err := os.MkdirAll(f.dataDir, dataPermSecure); err != nil {
		return err
	}
	_ = os.Chmod(f.dataDir, dataPermSecure)
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

	skills.ModelValidator = web.ValidModel
	skills.ProfileValidator = worker.IsNamedProfile
	skillsRepoSHA, err := loadSkills(log, gdb, f.dataDir, f.skillLocal, f.skillsRepo, f.fullClone())
	if err != nil {
		return err
	}

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
		DB:           gdb,
		Log:          log,
		DataDir:      filepath.Join(f.dataDir, "work"),
		APIBase:      apiBase,
		ForkOrg:      f.forkOrg,
		MetadataDir:  f.metadataDir,
		Runner:       runner,
		ScanTimeout:  f.scanTimeout,
		SchemaStrict: f.schemaStrict,
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
	srv.Commit = buildCommit()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go q.Start(ctx)

	httpSrv := &http.Server{Addr: f.addr, Handler: srv.Handler(), ReadHeaderTimeout: shutdownTimeout}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()

	log.Info("listening", "addr", "http://"+f.addr)
	if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// loadSkills loads local skill directories and, if a remote skills repo is
// configured, clones/pulls it at the requested ref and loads it too. Returns
// the resolved commit SHA of the remote repo (empty when no repo is set) so
// the caller can stamp it on each Scan for reproducibility.
func loadSkills(log *slog.Logger, gdb *gorm.DB, dataDir string, dirs skillDirs, repoSpec string, fullClone bool) (string, error) {
	for _, d := range dirs {
		n, err := skills.LoadDirectory(gdb, log, d, "local")
		if err != nil {
			return "", fmt.Errorf("load skills from %s: %w", d, err)
		}
		log.Info("loaded skills", "source", d, "count", n)
	}
	if repoSpec == "" {
		return "", nil
	}
	url, ref, err := skills.ParseRepoSpec(repoSpec)
	if err != nil {
		return "", fmt.Errorf("parse skills_repo %q: %w", repoSpec, err)
	}
	dst := filepath.Join(dataDir, "skills-cache", hashPath(repoSpec))
	ctx, cancel := context.WithTimeout(context.Background(), skillsCloneTimeout)
	defer cancel()
	sha, err := skills.CloneOrPull(ctx, url, ref, dst, fullClone)
	if err != nil {
		return "", fmt.Errorf("clone skills repo: %w", err)
	}
	n, err := skills.LoadDirectory(gdb, log, dst, "remote")
	if err != nil {
		return "", fmt.Errorf("load skills from %s: %w", url, err)
	}
	log.Info("loaded skills", "source", url, "ref", ref, "sha", sha, "count", n)
	return sha, nil
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

// setupRunner picks the SkillRunner implementation for the run loop:
// DockerRunner when docker is in use, LocalClaude otherwise. It also
// starts the egress proxy, creates the hardened network if requested,
// and returns the apiBase the worker should advertise to skills (the
// docker path rewrites it to host.docker.internal so containers can
// reach the loopback-bound web server).
//
//nolint:ireturn // dispatched on f.noDocker; concrete types live in the worker pkg
func setupRunner(f *flags, cfg *config.Config, log *slog.Logger) (worker.SkillRunner, string, error) {
	apiBase := "http://" + f.addr + "/api"
	if f.hardened && f.noDocker {
		return nil, "", fmt.Errorf("--hardened requires the docker runner; remove --no-docker")
	}
	if !f.noDocker && !worker.DockerAvailable() {
		if f.hardened {
			return nil, "", fmt.Errorf("docker not available: --hardened requires docker, install and start it")
		}
		return nil, "", fmt.Errorf("docker not available: install and start docker, or pass --no-docker to run without containerisation (no isolation)")
	}
	if f.noDocker {
		log.Info("--no-docker set, using local runner (no isolation)")
		return worker.LocalClaude{Effort: f.effort, FullClone: f.fullClone(), MaxTurns: f.maxTurns}, apiBase, nil
	}
	allow := buildEgressAllow(f.hardened, cfg, f.anthropicBaseURL, log)
	token := worker.NewProxyToken()
	port, err := worker.StartEgressProxy(&worker.EgressProxy{Allow: allow, Token: token, APIPort: addrPort(f.addr), Log: log})
	if err != nil {
		return nil, "", fmt.Errorf("start egress proxy: %w", err)
	}
	// Hardened mode owns its docker networks per-scan, so the gateway
	// IP must be probed inside RunSkill against the network the runner
	// is about to attach to. Probing once here would point every scan
	// at whichever network happened to be probed first. The startup
	// sweep collects per-scan networks left over by crashed processes.
	var gwIP string
	if f.hardened {
		if removed, err := worker.SweepOrphanHardenedNetworks(); err != nil {
			log.Warn("orphan hardened network sweep failed", "err", err)
		} else if removed > 0 {
			log.Info("removed orphan hardened networks", "count", removed)
		}
	} else {
		gwIP = worker.ResolveHostGatewayIPv4(f.runnerImage, "")
	}
	log.Info("docker detected, using containerised runner",
		"image", f.runnerImage, "egress_proxy_port", port, "egress_allow", len(allow),
		"host_gateway_ipv4", gwIP, "hardened", f.hardened)
	// Skills inside the container reach the host via host.docker.internal,
	// which the egress proxy rewrites to 127.0.0.1 when dialing.
	apiBase = "http://" + net.JoinHostPort(worker.HostGatewayAlias, addrPort(f.addr)) + "/api"
	return worker.DockerRunner{
		Image:            f.runnerImage,
		Effort:           f.effort,
		ProxyURL:         worker.ProxyURL(token, port),
		FullClone:        f.fullClone(),
		MaxTurns:         f.maxTurns,
		AnthropicBaseURL: f.anthropicBaseURL,
		HostGatewayIP:    gwIP,
		ProfilesDir:      f.profilesDir,
		Hardened:         f.hardened,
	}, apiBase, nil
}

// buildEgressAllow assembles the proxy allowlist. Hardened mode starts
// from HardenedEgressAllow and ignores cfg.EgressAllow (the operator
// must drop --hardened to widen). The anthropic base URL host is still
// auto-added in both modes since it routes the same Anthropic API.
func buildEgressAllow(hardened bool, cfg *config.Config, anthropicBaseURL string, log *slog.Logger) []string {
	var allow []string
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
	if h := baseURLHost(anthropicBaseURL); h != "" {
		allow = append(allow, h)
		log.Info("added anthropic base URL host to egress allowlist", "host", h)
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

// cfgPath returns the path the loader actually used for logging.
func cfgPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return config.DefaultPath
}
