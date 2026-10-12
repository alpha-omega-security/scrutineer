package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"scrutineer/internal/web"
)

func TestLoadOperatorTokenCreatesThenReuses(t *testing.T) {
	dir := t.TempDir()

	token, created, err := loadOperatorToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !created || len(token) != 64 {
		t.Fatalf("first run: created=%v token=%q, want a new 64-char token", created, token)
	}
	info, err := os.Stat(filepath.Join(dir, operatorTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Errorf("perm %o, want 600", perm)
	}

	again, created, err := loadOperatorToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	if created || again != token {
		t.Errorf("second run: created=%v token=%q, want the stored %q", created, again, token)
	}
}

func TestLoadOperatorTokenRejectsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, operatorTokenFile), []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOperatorToken(dir); err == nil {
		t.Fatal("empty token file accepted")
	}
}

func TestLoadOperatorTokenSurfacesReadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, operatorTokenFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOperatorToken(dir); err == nil {
		t.Fatal("directory at the token path accepted")
	}
}

func TestOperatorLoginURL(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:8080": "http://127.0.0.1:8080/login?token=t",
		"0.0.0.0:8080":   "http://127.0.0.1:8080/login?token=t",
		"[::]:8080":      "http://127.0.0.1:8080/login?token=t",
		":8080":          "http://127.0.0.1:8080/login?token=t",
		"[::1]:9000":     "http://[::1]:9000/login?token=t",
		"bogus":          "/login?token=t",
	} {
		if got := operatorLoginURL(addr, "t"); got != want {
			t.Errorf("%s: got %q, want %q", addr, got, want)
		}
	}
}

func TestConfigureOperatorTokenPrintsLoginEveryStart(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	f := &flags{dataDir: "data", addr: "127.0.0.1:8080"}
	if err := os.Mkdir("data", 0o700); err != nil {
		t.Fatal(err)
	}

	var first bytes.Buffer
	srv := &web.Server{}
	if err := configureOperatorToken(srv, f, slog.New(slog.NewTextHandler(&first, nil))); err != nil {
		t.Fatal(err)
	}
	if srv.OperatorToken == "" || !strings.Contains(first.String(), "/login?token="+srv.OperatorToken) {
		t.Fatalf("first start: token %q, log %q, want the login link", srv.OperatorToken, first.String())
	}

	var second bytes.Buffer
	again := &web.Server{}
	if err := configureOperatorToken(again, f, slog.New(slog.NewTextHandler(&second, nil))); err != nil {
		t.Fatal(err)
	}
	if again.OperatorToken != srv.OperatorToken || !strings.Contains(second.String(), "/login?token="+srv.OperatorToken) {
		t.Errorf("second start: token %q, log %q, want the stored token and its login link", again.OperatorToken, second.String())
	}
	if !filepath.IsAbs(again.OperatorTokenFile) || !strings.Contains(second.String(), again.OperatorTokenFile) {
		t.Errorf("token file %q, log %q, want an absolute path in both", again.OperatorTokenFile, second.String())
	}
}
