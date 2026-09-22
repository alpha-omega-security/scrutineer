package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"scrutineer/internal/config"
	"scrutineer/internal/testutil"
)

func TestPostgresServerProcess(t *testing.T) {
	path := os.Getenv("SCRUTINEER_TEST_SERVER_CONFIG")
	if path == "" {
		t.Skip("server subprocess")
	}
	flag.CommandLine = flag.NewFlagSet("scrutineer", flag.ExitOnError)
	os.Args = []string{"scrutineer", "-config", path}
	main()
}

func TestPostgresServer(t *testing.T) {
	dsn := testutil.PostgresDSN(t)
	dir := t.TempDir()
	addr := freeAddr(t)
	cfg := config.Config{
		Addr: addr, Data: filepath.Join(dir, "data"), NoContainer: new(true),
		EcosystemsEnrichment: new(false),
		Database:             config.DatabaseConfig{Driver: "postgres", DSN: dsn},
	}
	body, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqldb.Close() }()
	for range 2 {
		testPostgresServerStart(t, path, addr, sqldb)
	}
	if _, err := os.Stat(filepath.Join(cfg.Data, "scrutineer.db")); !os.IsNotExist(err) {
		t.Fatalf("Postgres instance created a SQLite file: %v", err)
	}
}

func testPostgresServerStart(t *testing.T, path, addr string, sqldb *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logFile, err := os.CreateTemp(t.TempDir(), "server-*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPostgresServerProcess$")
	cmd.Env = append(os.Environ(), "SCRUTINEER_TEST_SERVER_CONFIG="+path)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cancel()
		if t.Failed() {
			log, _ := os.ReadFile(logFile.Name())
			t.Logf("server output:\n%s", log)
		}
	}()
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := "http://" + addr
	if err := waitPostgresServer(ctx, client, base, done); err != nil {
		t.Fatal(err)
	}
	resp, err := client.PostForm(base+"/settings/concurrency", url.Values{"concurrency": {"2"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save setting: status %d", resp.StatusCode)
	}
	var value string
	if err := sqldb.QueryRow("SELECT value FROM settings WHERE key = 'concurrency'").Scan(&value); err != nil || value != "2" {
		t.Fatalf("persisted concurrency = %q, error = %v", value, err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server shutdown: %v", err)
	}
}

func waitPostgresServer(ctx context.Context, client *http.Client, base string, done <-chan error) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			return fmt.Errorf("server exited before listening: %v", err)
		case <-ticker.C:
			resp, err := client.Get(base + "/repositories")
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil && resp.StatusCode == http.StatusOK && strings.Contains(string(body), "Repositories") {
				return nil
			}
		}
	}
}

func TestDatabaseCommandsRejectPostgres(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("database: {driver: postgres, dsn: 'host=localhost dbname=example'}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"backup", "restore"} {
		args := []string{command, "-config", path}
		if command == "restore" {
			args = append(args, "-from", "unused.db")
		}
		handled, err := dispatch(args, io.Discard)
		if !handled || err == nil || !strings.Contains(err.Error(), "SQLite-only") {
			t.Fatalf("%s: handled=%v error=%v", command, handled, err)
		}
	}
}
