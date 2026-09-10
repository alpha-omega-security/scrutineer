package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validCodexAuthJSON = `{"auth_mode":"chatgpt","tokens":{"refresh_token":"refresh"}}`

func writeCodexAuthFile(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.json")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateCodexAuthFile(t *testing.T) {
	if err := ValidateCodexAuthFile(writeCodexAuthFile(t, validCodexAuthJSON, 0o600)); err != nil {
		t.Fatalf("valid auth file: %v", err)
	}
	legacy := `{"tokens":{"refresh_token":"refresh"}}`
	if err := ValidateCodexAuthFile(writeCodexAuthFile(t, legacy, 0o600)); err != nil {
		t.Fatalf("legacy inferred ChatGPT auth file: %v", err)
	}

	tests := []struct {
		name string
		body string
		mode os.FileMode
		want string
	}{
		{"invalid JSON", `{`, 0o600, "invalid JSON"},
		{"API key mode", `{"auth_mode":"apikey","tokens":{"refresh_token":"refresh"}}`, 0o600, `require "chatgpt"`},
		{"missing tokens", `{"auth_mode":"chatgpt"}`, 0o600, "no ChatGPT refresh token"},
		{"missing refresh", `{"auth_mode":"chatgpt","tokens":{}}`, 0o600, "no ChatGPT refresh token"},
		{"read-only mode", validCodexAuthJSON, 0o400, "require exactly 0600 (chmod 600 "},
		{"exposed mode", validCodexAuthJSON, 0o644, "require exactly 0600 (chmod 600 "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCodexAuthFile(writeCodexAuthFile(t, tc.body, tc.mode))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestValidateCodexAuthFileRejectsDirectory(t *testing.T) {
	err := ValidateCodexAuthFile(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("error = %v", err)
	}
}

func TestCodexAccountAuthAcquireSerializes(t *testing.T) {
	auth := NewCodexAccountAuth(writeCodexAuthFile(t, validCodexAuthJSON, 0o600))
	unlock, err := auth.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	attempting := make(chan struct{})
	acquired := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		close(attempting)
		unlock, err := auth.acquire(context.Background())
		if err != nil {
			errCh <- err
			return
		}
		defer unlock()
		close(acquired)
	}()
	<-attempting
	select {
	case <-acquired:
		t.Fatal("second account-auth user acquired the lock concurrently")
	case <-time.After(20 * time.Millisecond):
	}
	unlock()
	select {
	case <-acquired:
	case err := <-errCh:
		t.Fatalf("second account-auth user failed to acquire the released credential: %v", err)
	case <-time.After(time.Second):
		t.Fatal("second account-auth user did not acquire the released lock")
	}
}

func TestCodexAccountAuthAcquireHonorsCancellation(t *testing.T) {
	auth := NewCodexAccountAuth(writeCodexAuthFile(t, validCodexAuthJSON, 0o600))
	unlock, err := auth.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	attempting := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(attempting)
		release, err := auth.acquire(ctx)
		if err == nil {
			release()
		}
		result <- err
	}()
	<-attempting
	select {
	case err := <-result:
		t.Fatalf("blocked acquire returned before cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled acquire error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked acquire did not observe cancellation")
	}
	unlock()

	// A waiter that returned on cancellation must not acquire after the current
	// owner releases the credential.
	if _, err := auth.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled acquire error = %v, want context.Canceled", err)
	}
}

func TestCodexAccountAuthAcquireRevalidatesCredential(t *testing.T) {
	path := writeCodexAuthFile(t, validCodexAuthJSON, 0o600)
	auth := NewCodexAccountAuth(path)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.acquire(context.Background()); err == nil || !strings.Contains(err.Error(), "require exactly 0600") {
		t.Fatalf("acquire after permission change error = %v", err)
	}

	// A failed validation must release the semaphore for a corrected file.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	unlock, err := auth.acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire after correcting permissions: %v", err)
	}
	unlock()
}
