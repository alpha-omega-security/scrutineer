package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
)

const (
	dataPermSecure  = 0o700
	shutdownTimeout = 5 * time.Second
)

//go:embed default_spec.md
var defaultSpec string

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
		effort  = flag.String("effort", "high", "claude effort")
		spec    = flag.String("spec", "", "path to audit spec (default: built-in)")
	)
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

	specText := defaultSpec
	if *spec != "" {
		b, err := os.ReadFile(*spec)
		if err != nil {
			return fmt.Errorf("read spec: %w", err)
		}
		specText = string(b)
	}

	broker := web.NewBroker()

	w := &worker.Worker{
		DB:      gdb,
		Log:     log,
		DataDir: filepath.Join(*dataDir, "work"),
		Spec:    specText,
		Runner:  worker.LocalClaude{Effort: *effort},
		OnEvent: func(scanID, repoID uint, name, data string) {
			broker.Publish(web.Event{Name: name, Data: data, ScanID: scanID, RepoID: repoID})
		},
	}
	w.Register(q)

	srv, err := web.New(gdb, q, log, specText, broker)
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
