package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
)

func TestPrepareLocalSrc(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(srcDir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "pkg", "doc.go"), []byte("package pkg\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	workRoot := t.TempDir()
	if err := prepareLocalSrc(srcDir, workRoot, func(Event) {}); err != nil {
		t.Fatalf("prepareLocalSrc: %v", err)
	}
	for _, rel := range []string{"src/main.go", "src/pkg/doc.go"} {
		if _, err := os.Stat(filepath.Join(workRoot, rel)); err != nil {
			t.Errorf("expected %s under workRoot: %v", rel, err)
		}
	}
}

func TestPrepareLocalSrcRejectsNonDir(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "f.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := prepareLocalSrc(file, t.TempDir(), func(Event) {}); err == nil {
		t.Fatal("expected error on non-directory source")
	}
}

func TestPrepareLocalSrcWithoutGitDir(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	workRoot := t.TempDir()
	if err := prepareLocalSrc(srcDir, workRoot, func(Event) {}); err != nil {
		t.Fatalf("dir with no .git should still be copied: %v", err)
	}
	if commit := gitHead(filepath.Join(workRoot, "src")); commit != "" {
		t.Errorf("gitHead on non-git dir = %q, want empty string (Scan.Commit will be blank)", commit)
	}
}

func TestPrepareLocalSrcFollowsSymlinkRoot(t *testing.T) {
	realDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(realDir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	workRoot := t.TempDir()
	if err := prepareLocalSrc(link, workRoot, func(Event) {}); err != nil {
		t.Fatalf("prepareLocalSrc on symlink root: %v", err)
	}

	if _, err := os.Stat(filepath.Join(workRoot, "src", "main.go")); err != nil {
		t.Errorf("expected src/main.go after copying through symlink root: %v", err)
	}
}

func TestPrepareLocalSrcRejectsMissing(t *testing.T) {
	if err := prepareLocalSrc("/does/not/exist/scrutineer-test", t.TempDir(), func(Event) {}); err == nil {
		t.Fatal("expected error on missing source")
	}
}

// fetchRef checkout of a branch/tag/SHA/empty and parseRemoteHeads are
// tested upstream in github.com/git-pkgs/clone (ensure_test.go,
// remote_test.go); the equivalent scrutineer tests were removed when the
// implementation moved there.

func TestListRemoteBranchesRejectsNonHTTPS(t *testing.T) {
	for _, u := range []string{"file:///etc", "git@github.com:foo/bar", "http://x/y", ""} {
		if _, err := ListRemoteBranches(context.Background(), u); err == nil {
			t.Errorf("ListRemoteBranches(%q) should reject non-https", u)
		}
	}
}

func TestValidateGitURL(t *testing.T) {
	good := []string{
		"https://github.com/splitrb/split",
		"https://gitlab.com/foo/bar.git",
	}
	for _, u := range good {
		if err := validateGitURL(u); err != nil {
			t.Errorf("should allow %q: %v", u, err)
		}
	}

	bad := []string{
		"http://github.com/foo/bar",
		"git@github.com:foo/bar.git",
		"ssh://git@host/repo",
		"file:///etc/passwd",
		"--upload-pack=/bin/sh",
		"-c core.fsmonitor=evil",
		"ext::sh -c evil",
		"",
	}
	for _, u := range bad {
		if err := validateGitURL(u); err == nil {
			t.Errorf("should reject %q", u)
		}
	}
}

func TestValidateGitRef(t *testing.T) {
	good := []string{
		"",
		"main",
		"master",
		"release/1.0",
		"v1.2.3",
		"feature/abc_def-1",
		"users/alice/topic.branch",
	}
	for _, r := range good {
		if err := ValidateGitRef(r); err != nil {
			t.Errorf("should allow %q: %v", r, err)
		}
	}

	bad := []string{
		"-upload-pack=/bin/sh",
		"--all",
		"foo..bar",
		"../etc/passwd",
		"branch with space",
		"branch;rm -rf /",
		"branch\nmain",
		"head@{0}",
		"refs/heads/main^",
		"branch~1",
	}
	for _, r := range bad {
		if err := ValidateGitRef(r); err == nil {
			t.Errorf("should reject %q", r)
		}
	}
}

// TestCloneOrFetchRejectsBadRefBeforeNetwork pins the contract that a bad
// ref short-circuits cloneOrFetch before any git invocation runs. The dst
// has no .git directory, so without the validation gate the function would
// fall through to `git clone` and try to reach example.invalid.
func TestCloneOrFetchRejectsBadRefBeforeNetwork(t *testing.T) {
	dst := t.TempDir()
	err := cloneOrFetch(context.Background(), gitRetry{}, "https://example.invalid/repo", dst, false, "--upload-pack=/bin/sh", func(Event) {
		t.Errorf("emit must not be called when validation rejects the ref")
	})
	if err == nil {
		t.Fatal("expected error for bad ref")
	}
	if !strings.Contains(err.Error(), "invalid ref") {
		t.Errorf("error %q should mention invalid ref", err)
	}
}

// TestCloneOrFetchRejectsBadURL keeps the URL gate covered through the
// same entry point so a future refactor that re-orders the validators
// trips this test rather than silently changing the order users see.
func TestCloneOrFetchRejectsBadURL(t *testing.T) {
	err := cloneOrFetch(context.Background(), gitRetry{}, "ssh://git@example.invalid/repo", t.TempDir(), false, "main", func(Event) {})
	if err == nil {
		t.Fatal("expected error for non-https URL")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error %q should mention https requirement", err)
	}
}

// TestEnsureCloneWrapsValidationError confirms that ensureClone preserves
// the wrap-as-RepoUnreachableError pattern when the inner cloneOrFetch
// rejects bad input. The outer code branches on this error type to flip
// repositories into the unreachable state, so it must keep working
// regardless of which validator failed.
func TestEnsureCloneWrapsValidationError(t *testing.T) {
	_, err := ensureClone(context.Background(), db.Repository{URL: "https://example.invalid/repo"}, t.TempDir(), false, "--all", func(Event) {})
	if err == nil {
		t.Fatal("expected error for bad ref")
	}
	var ru *RepoUnreachableError
	if !errors.As(err, &ru) {
		t.Fatalf("error %T = %v, want *RepoUnreachableError wrapping the validation failure", err, err)
	}
	if !strings.Contains(ru.Error(), "invalid ref") {
		t.Errorf("RepoUnreachableError.Error() = %q, should mention invalid ref", ru.Error())
	}
}
