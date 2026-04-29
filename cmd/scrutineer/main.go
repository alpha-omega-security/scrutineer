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
	runnerImage      string
	skillsRepo       string
	concurrency      int
	cloneMode        string
	scanTimeout      time.Duration
	maxTurns         int
	anthropicBaseURL string
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
	flag.StringVar(&f.runnerImage, "runner-image", worker.DefaultRunnerImage, "docker image for per-job containers")
	flag.StringVar(&f.skillsRepo, "skills-repo", "", "clone skills from this git https URL on startup")
	flag.IntVar(&f.concurrency, "concurrency", queue.DefaultWorkerConcurrency, "number of scans to run in parallel")
	flag.StringVar(&f.cloneMode, "clone", "shallow", "clone depth: shallow (--depth 1) or full")
	flag.DurationVar(&f.scanTimeout, "scan-timeout", worker.DefaultScanTimeout, "wall-clock limit per scan")
	flag.IntVar(&f.maxTurns, "max-turns", 0, "claude --max-turns limit (0 = unlimited)")
	flag.StringVar(&f.anthropicBaseURL, "anthropic-base-url", "", "custom Anthropic API base URL (env: ANTHROPIC_BASE_URL)")
	flag.Var(&f.skillLocal, "skills", "directory to load SKILL.md files from (repeatable)")
	flag.Parse()

	f.set = make(map[string]bool)
	flag.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return f
}

// merge layers cfg underneath f: a config value applies only when the
// matching CLI flag was not set explicitly. Also pushes model overrides
// into the web package.
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
	if cfg.RunnerImage != "" && !f.set["runner-image"] {
		f.runnerImage = cfg.RunnerImage
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

	q, err := queue.New(sqldb, log, f.concurrency)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}

	if err := loadSkills(log, gdb, f.dataDir, f.skillLocal, f.skillsRepo, f.fullClone()); err != nil {
		return err
	}

	broker := web.NewBroker()

	var egressExtra []string
	if cfg != nil {
		egressExtra = cfg.EgressAllow
	}
	if h := baseURLHost(f.anthropicBaseURL); h != "" {
		egressExtra = append(egressExtra, h)
		log.Info("added anthropic base URL host to egress allowlist", "host", h)
	}

	var runner worker.SkillRunner
	apiBase := "http://" + f.addr + "/api"
	if !f.noDocker && worker.DockerAvailable() {
		allow := append(append([]string{}, worker.DefaultEgressAllow...), egressExtra...)
		token := worker.NewProxyToken()
		port, err := worker.StartEgressProxy(&worker.EgressProxy{Allow: allow, Token: token, Log: log})
		if err != nil {
			return fmt.Errorf("start egress proxy: %w", err)
		}
		log.Info("docker detected, using containerised runner",
			"image", f.runnerImage, "egress_proxy_port", port, "egress_allow", len(allow))
		runner = worker.DockerRunner{
			Image:            f.runnerImage,
			Effort:           f.effort,
			ProxyURL:         worker.ProxyURL(token, port),
			FullClone:        f.fullClone(),
			MaxTurns:         f.maxTurns,
			AnthropicBaseURL: f.anthropicBaseURL,
		}
		// Skills inside the container reach the host via host.docker.internal,
		// which the egress proxy rewrites to 127.0.0.1 when dialing.
		apiBase = "http://" + net.JoinHostPort(worker.HostGatewayAlias, addrPort(f.addr)) + "/api"
	} else {
		log.Info("docker not available or disabled, using local runner (no isolation)")
		runner = worker.LocalClaude{Effort: f.effort, FullClone: f.fullClone(), MaxTurns: f.maxTurns}
	}

	w := &worker.Worker{
		DB:          gdb,
		Log:         log,
		DataDir:     filepath.Join(f.dataDir, "work"),
		APIBase:     apiBase,
		Runner:      runner,
		ScanTimeout: f.scanTimeout,
		OnEvent: func(scanID, repoID uint, name, data string) {
			broker.Publish(web.Event{Name: name, Data: data, ScanID: scanID, RepoID: repoID})
		},
	}
	w.Register(q)

	srv, err := web.New(gdb, q, log, broker, w)
	if err != nil {
		return err
	}

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

func loadSkills(log *slog.Logger, gdb *gorm.DB, dataDir string, dirs skillDirs, repo string, fullClone bool) error {
	for _, d := range dirs {
		n, err := skills.LoadDirectory(gdb, log, d, "local")
		if err != nil {
			return fmt.Errorf("load skills from %s: %w", d, err)
		}
		log.Info("loaded skills", "source", d, "count", n)
	}
	if repo != "" {
		dst := filepath.Join(dataDir, "skills-cache", hashPath(repo))
		ctx, cancel := context.WithTimeout(context.Background(), skillsCloneTimeout)
		defer cancel()
		if err := skills.CloneOrPull(ctx, repo, dst, fullClone); err != nil {
			return fmt.Errorf("clone skills repo: %w", err)
		}
		n, err := skills.LoadDirectory(gdb, log, dst, "remote")
		if err != nil {
			return fmt.Errorf("load skills from %s: %w", repo, err)
		}
		log.Info("loaded skills", "source", repo, "count", n)
	}
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
