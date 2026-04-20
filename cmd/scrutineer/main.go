package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gorm.io/gorm"

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

func run(log *slog.Logger) error {
	var (
		addr    = flag.String("addr", "127.0.0.1:8080", "listen address")
		dataDir = flag.String("data", "./data", "data directory (db + workspaces)")
		effort      = flag.String("effort", "high", "claude effort")
		noDocker    = flag.Bool("no-docker", false, "disable containerised runner even if docker is available")
		runnerImage = flag.String("runner-image", "scrutineer-runner", "docker image for per-job containers")
		skillsRepo  = flag.String("skills-repo", "", "clone skills from this git https URL on startup")
	)
	var skillLocal skillDirs
	flag.Var(&skillLocal, "skills", "directory to load SKILL.md files from (repeatable)")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, dataPermSecure); err != nil {
		return err
	}
	_ = os.Chmod(*dataDir, dataPermSecure)

	gdb, err := db.Open(filepath.Join(*dataDir, "scrutineer.db"))
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	db.BackfillFindings(gdb)
	db.BackfillFindingRepository(gdb)
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

	q, err := queue.New(sqldb, log)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}

	if err := loadSkills(log, gdb, *dataDir, skillLocal, *skillsRepo); err != nil {
		return err
	}

	broker := web.NewBroker()

	var runner worker.SkillRunner
	if !*noDocker && worker.DockerAvailable() {
		log.Info("docker detected, using containerised runner", "image", *runnerImage)
		runner = worker.DockerRunner{Image: *runnerImage, Effort: *effort}
	} else {
		log.Info("docker not available or disabled, using local runner (no isolation)")
		runner = worker.LocalClaude{Effort: *effort}
	}

	w := &worker.Worker{
		DB:      gdb,
		Log:     log,
		DataDir: filepath.Join(*dataDir, "work"),
		APIBase: "http://" + *addr + "/api",
		Runner:  runner,
		OnEvent: func(scanID, repoID uint, name, data string) {
			broker.Publish(web.Event{Name: name, Data: data, ScanID: scanID, RepoID: repoID})
		},
	}
	w.Register(q)

	srv, err := web.New(gdb, q, log, broker)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go q.Start(ctx)

	httpSrv := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: shutdownTimeout}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()

	log.Info("listening", "addr", "http://"+*addr)
	if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loadSkills(log *slog.Logger, gdb *gorm.DB, dataDir string, dirs skillDirs, repo string) error {
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
		if err := skills.CloneOrPull(ctx, repo, dst); err != nil {
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

func hashPath(s string) string {
	r := strings.NewReplacer("/", "_", ":", "_", "?", "_", "&", "_", "=", "_")
	return r.Replace(s)
}
