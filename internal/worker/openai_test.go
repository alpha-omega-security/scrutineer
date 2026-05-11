package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolWriteFile_createsParentDirs(t *testing.T) {
	root := t.TempDir()
	o := OpenAIRunner{}
	result := o.toolWriteFile(root, "sub/dir/file.txt", "hello")
	if result != "ok" {
		t.Fatalf("toolWriteFile = %q, want ok", result)
	}
	got, err := os.ReadFile(filepath.Join(root, "sub/dir/file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q", got)
	}
	info, _ := os.Stat(filepath.Join(root, "sub"))
	if perm := info.Mode().Perm(); perm != dirPerm {
		t.Errorf("dir perm = %o, want %o", perm, dirPerm)
	}
}

func TestToolWriteFile_filePerm(t *testing.T) {
	root := t.TempDir()
	o := OpenAIRunner{}
	o.toolWriteFile(root, "f.txt", "x")
	info, _ := os.Stat(filepath.Join(root, "f.txt"))
	if perm := info.Mode().Perm(); perm != filePerm {
		t.Errorf("file perm = %o, want %o", perm, filePerm)
	}
}

func TestToolWriteFile_pathEscape(t *testing.T) {
	root := t.TempDir()
	o := OpenAIRunner{}
	result := o.toolWriteFile(root, "../escape.txt", "bad")
	if !strings.Contains(result, "error: path escapes workspace") {
		t.Errorf("expected path escape error, got %q", result)
	}
}

func TestToolWriteFile_mkdirError(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "blocker"), []byte("x"), filePerm)
	o := OpenAIRunner{}
	got := o.toolWriteFile(root, "blocker/sub/file.txt", "data")
	if !strings.Contains(got, "error:") {
		t.Errorf("expected error, got %q", got)
	}
}

func TestToolReadFile(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "test.txt"), []byte("content"), filePerm)
	o := OpenAIRunner{}
	got := o.toolReadFile(root, "test.txt")
	if got != "content" {
		t.Errorf("toolReadFile = %q", got)
	}
}

func TestToolReadFile_pathEscape(t *testing.T) {
	root := t.TempDir()
	o := OpenAIRunner{}
	got := o.toolReadFile(root, "../../etc/passwd")
	if !strings.Contains(got, "error: path escapes workspace") {
		t.Errorf("expected path escape error, got %q", got)
	}
}

func TestToolReadFile_notFound(t *testing.T) {
	root := t.TempDir()
	o := OpenAIRunner{}
	got := o.toolReadFile(root, "nope.txt")
	if !strings.Contains(got, "error:") {
		t.Errorf("expected error, got %q", got)
	}
}

func TestToolListDir(t *testing.T) {
	root := t.TempDir()
	_ = os.Mkdir(filepath.Join(root, "subdir"), dirPerm)
	_ = os.WriteFile(filepath.Join(root, "file.txt"), []byte("x"), filePerm)
	o := OpenAIRunner{}
	got := o.toolListDir(root, ".")
	if !strings.Contains(got, "subdir/") {
		t.Errorf("missing subdir/ in %q", got)
	}
	if !strings.Contains(got, "file.txt") {
		t.Errorf("missing file.txt in %q", got)
	}
}

func TestToolListDir_pathEscape(t *testing.T) {
	root := t.TempDir()
	o := OpenAIRunner{}
	got := o.toolListDir(root, "../../")
	if !strings.Contains(got, "error: path escapes workspace") {
		t.Errorf("expected path escape error, got %q", got)
	}
}

func TestToolListDir_notFound(t *testing.T) {
	o := OpenAIRunner{}
	got := o.toolListDir(t.TempDir(), "nope")
	if !strings.Contains(got, "error:") {
		t.Errorf("expected error, got %q", got)
	}
}

func TestToolWebFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "fetched content")
	}))
	defer srv.Close()

	o := OpenAIRunner{}
	got := o.toolWebFetch(context.Background(), srv.URL)
	if got != "fetched content" {
		t.Errorf("toolWebFetch = %q", got)
	}
}

func TestToolWebFetch_emptyURL(t *testing.T) {
	o := OpenAIRunner{}
	got := o.toolWebFetch(context.Background(), "")
	if got != "error: empty url" {
		t.Errorf("got %q", got)
	}
}

func TestToolWebFetch_badURL(t *testing.T) {
	o := OpenAIRunner{}
	got := o.toolWebFetch(context.Background(), "http://192.0.2.1:1/nope")
	if !strings.Contains(got, "error:") {
		t.Errorf("expected error, got %q", got)
	}
}

func TestCallAPI_success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("auth header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		resp := oaiResponse{
			Choices: []oaiChoice{{Message: oaiMessage{Role: "assistant", Content: "hi"}, FinishReason: "stop"}},
			Usage:   &oaiUsage{PromptTokens: 10, CompletionTokens: 5},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	o := OpenAIRunner{BaseURL: srv.URL, APIKey: "test-key"}
	msgs := []oaiMessage{{Role: "user", Content: "hello"}}
	got, err := o.callAPI(context.Background(), "test-model", msgs)
	if err != nil {
		t.Fatalf("callAPI error: %v", err)
	}
	if got.Choices[0].Message.Content != "hi" {
		t.Errorf("content = %q", got.Choices[0].Message.Content)
	}
	if got.Usage.PromptTokens != 10 {
		t.Errorf("prompt tokens = %d", got.Usage.PromptTokens)
	}
}

func TestCallAPI_httpError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	o := OpenAIRunner{BaseURL: srv.URL, APIKey: "k"}
	_, err := o.callAPI(context.Background(), "m", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error = %q, want HTTP 429", err)
	}
}

func TestCallAPI_invalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "not json")
	}))
	defer srv.Close()

	o := OpenAIRunner{BaseURL: srv.URL}
	_, err := o.callAPI(context.Background(), "m", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "decode response") {
		t.Errorf("error = %q", err)
	}
}

func TestCallAPI_noAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected auth header: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(oaiResponse{Choices: []oaiChoice{{Message: oaiMessage{Content: "ok"}}}})
	}))
	defer srv.Close()

	o := OpenAIRunner{BaseURL: srv.URL}
	_, err := o.callAPI(context.Background(), "m", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteTool_dispatch(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "a.txt"), []byte("data"), filePerm)

	o := OpenAIRunner{}
	ctx := context.Background()

	cases := []struct {
		name, args string
		contains   string
	}{
		{"read_file", `{"path":"a.txt"}`, "data"},
		{"write_file", `{"path":"b.txt","content":"new"}`, "ok"},
		{"list_directory", `{"path":"."}`, "a.txt"},
		{"run_command", `{"command":"echo dispatch"}`, "dispatch"},
		{"web_fetch", `{"url":""}`, "error: empty url"},
		{"unknown_tool", `{}`, "unknown tool"},
	}
	for _, tc := range cases {
		got := o.executeTool(ctx, root, tc.name, tc.args)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("executeTool(%q) = %q, want containing %q", tc.name, got, tc.contains)
		}
	}
}

func TestToolRunCommand(t *testing.T) {
	root := t.TempDir()
	o := OpenAIRunner{}
	got := o.toolRunCommand(context.Background(), root, "echo hello")
	if !strings.Contains(got, "hello") {
		t.Errorf("toolRunCommand = %q", got)
	}
}

func TestToolRunCommand_empty(t *testing.T) {
	o := OpenAIRunner{}
	got := o.toolRunCommand(context.Background(), t.TempDir(), "")
	if got != "error: empty command" {
		t.Errorf("got %q", got)
	}
}

func TestToolRunCommand_failure(t *testing.T) {
	o := OpenAIRunner{}
	got := o.toolRunCommand(context.Background(), t.TempDir(), "false")
	if !strings.Contains(got, "exit") {
		t.Errorf("expected exit error, got %q", got)
	}
}
