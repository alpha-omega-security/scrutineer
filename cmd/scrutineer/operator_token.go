package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"scrutineer/internal/web"
)

const operatorTokenFile = "operator-token"

// loadOperatorToken returns the token stored under dataDir, creating it on
// first run. created reports whether this call wrote it.
func loadOperatorToken(dataDir string) (token string, created bool, err error) {
	path := filepath.Join(dataDir, operatorTokenFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		token = strings.TrimSpace(string(raw))
		if token == "" {
			return "", false, fmt.Errorf("operator token file %s is empty, delete it to generate a new token", path)
		}
		return token, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", false, err
	}
	token = web.NewAPIToken()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, dbFilePerm)
	if err != nil {
		return "", false, err
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		_ = f.Close()
		return "", false, err
	}
	return token, true, f.Close()
}

func configureOperatorToken(srv *web.Server, f *flags, log *slog.Logger) error {
	token, created, err := loadOperatorToken(f.dataDir)
	if err != nil {
		return fmt.Errorf("operator token: %w", err)
	}
	path := filepath.Join(f.dataDir, operatorTokenFile)
	// Absolute so a start from another directory, which reads a different
	// ./data, shows which file it used.
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	srv.OperatorToken = token
	srv.OperatorTokenFile = path
	// Printed on every start: the same token is in the 0600 file, and a
	// browser that lost its cookie has no other way back in.
	msg := "operator token; open this link to sign in"
	if created {
		msg = "operator token created; open this link to sign in"
	}
	log.Info(msg, "login", operatorLoginURL(f.addr, token), "file", path)
	return nil
}

// operatorLoginURL points at a loopback Host even when the server binds a
// wildcard address, since the Host check refuses anything else.
func operatorLoginURL(addr, token string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "/login?token=" + token
	}
	return "http://" + net.JoinHostPort(loopbackIfWildcard(host), port) + "/login?token=" + token
}
