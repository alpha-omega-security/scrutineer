// Command scrutineer-desktop runs the scrutineer web server on a random
// localhost port and opens it in the OS-native webview, so it behaves
// like a standalone desktop app. Closing the window shuts the server
// down. It uses the local (non-docker) runner and the same ./data and
// ./skills layout as cmd/scrutineer; for flags, config files, or the
// docker runner, use cmd/scrutineer instead.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	webview "github.com/webview/webview_go"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/skills"
	"scrutineer/internal/web"
	"scrutineer/internal/worker"
)

const (
	dataDir         = "./data"
	skillsDir       = "./skills"
	effort          = "high"
	dataPerm        = 0o700
	windowWidth     = 1400
	windowHeight    = 900
	shutdownTimeout = 5 * time.Second
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	if err := os.MkdirAll(dataDir, dataPerm); err != nil {
		return err
	}
	_ = os.Chmod(dataDir, dataPerm)
	// Module-boundary sentinel so go tooling on the parent repo never
	// walks into cloned scan workspaces under data/work/.
	_ = os.WriteFile(filepath.Join(dataDir, "go.mod"), []byte("module scrutineer/data\n"), dataPerm)

	gdb, err := db.Open(filepath.Join(dataDir, "scrutineer.db"))
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

	q, err := queue.New(sqldb, log, queue.DefaultWorkerConcurrency)
	if err != nil {
		return fmt.Errorf("queue: %w", err)
	}

	if _, err := os.Stat(skillsDir); err == nil {
		n, err := skills.LoadDirectory(gdb, log, skillsDir, "local")
		if err != nil {
			return fmt.Errorf("load skills: %w", err)
		}
		log.Info("loaded skills", "source", skillsDir, "count", n)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	addr := ln.Addr().String()

	broker := web.NewBroker()
	w := &worker.Worker{
		DB:      gdb,
		Log:     log,
		DataDir: filepath.Join(dataDir, "work"),
		APIBase: "http://" + addr + "/api",
		Runner:  worker.LocalClaude{Effort: effort},
		OnEvent: func(scanID, repoID uint, name, data string) {
			broker.Publish(web.Event{Name: name, Data: data, ScanID: scanID, RepoID: repoID})
		},
	}
	w.Register(q)

	srv, err := web.New(gdb, q, log, broker, w)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.Start(ctx)

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: shutdownTimeout}
	go func() { _ = httpSrv.Serve(ln) }()
	log.Info("listening", "addr", "http://"+addr)

	wv := webview.New(false)
	defer wv.Destroy()
	wv.SetTitle("Scrutineer")
	wv.SetSize(windowWidth, windowHeight, webview.HintNone)
	wv.Navigate("http://" + addr)
	wv.Run()

	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer scancel()
	return httpSrv.Shutdown(sctx)
}
