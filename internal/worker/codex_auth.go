package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CodexAccountAuthHost is used only by file-backed ChatGPT auth. The
// pinned Codex CLI refreshes subscription tokens at auth.openai.com; API-key
// runs do not need this additional destination.
const (
	CodexAccountAuthHost = "auth.openai.com"
	codexAuthFileMode    = os.FileMode(0o600)
)

// CodexAccountAuth is a ChatGPT account credential shared by Codex scans.
// Codex refreshes auth.json in place, so every runner must mount the same file
// read-write. The semaphore keeps that rotating credential in a single
// serialized job stream while the rest of CODEX_HOME remains private to each
// scan.
type CodexAccountAuth struct {
	Path string
	sem  chan struct{}
}

// NewCodexAccountAuth returns shared account-auth state for a ContainerRunner.
func NewCodexAccountAuth(path string) *CodexAccountAuth {
	if path == "" {
		return nil
	}
	return &CodexAccountAuth{Path: path, sem: make(chan struct{}, 1)}
}

// acquire serializes access to the rotating credential, honours cancellation
// while another job owns it, and revalidates the file immediately before use.
func (a *CodexAccountAuth) acquire(ctx context.Context) (func(), error) {
	if a == nil {
		return func() {}, nil
	}
	if err := ctx.Err(); err != nil {
		return func() {}, err
	}
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
	if err := ValidateCodexAuthFile(a.Path); err != nil {
		<-a.sem
		return func() {}, err
	}
	return func() { <-a.sem }, nil
}

type codexAuthFile struct {
	AuthMode string `json:"auth_mode"`
	Tokens   *struct {
		RefreshToken string `json:"refresh_token"`
	} `json:"tokens"`
}

// ValidateCodexAuthFile checks the minimum properties needed for a durable
// ChatGPT login without ever returning credential material in an error.
func ValidateCodexAuthFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect codex.auth_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("codex.auth_file is not a regular file: %s", path)
	}
	if info.Mode().Perm() != codexAuthFileMode {
		// Codex rewrites this file on every refresh, so a mode change is as
		// likely to be the CLI's doing as the operator's; name the fix.
		return fmt.Errorf("codex.auth_file permissions are %04o; require exactly 0600 (chmod 600 %s)", info.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read codex.auth_file: %w", err)
	}
	var auth codexAuthFile
	if err := json.Unmarshal(data, &auth); err != nil {
		return fmt.Errorf("parse codex.auth_file: invalid JSON")
	}
	// Older Codex releases infer ChatGPT mode from tokens and omit auth_mode;
	// current releases write it explicitly. Accept both shapes, but never an
	// explicitly different mode.
	if auth.AuthMode != "" && auth.AuthMode != "chatgpt" {
		return fmt.Errorf("codex.auth_file auth_mode is %q; require %q", auth.AuthMode, "chatgpt")
	}
	if auth.Tokens == nil || strings.TrimSpace(auth.Tokens.RefreshToken) == "" {
		return fmt.Errorf("codex.auth_file has no ChatGPT refresh token")
	}
	return nil
}
