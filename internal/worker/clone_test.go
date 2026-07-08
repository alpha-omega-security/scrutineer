package worker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/testutil"
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

// TestFetchRefChecksOutRequestedRef exercises the cache-reuse path: a
// single-branch shallow cache cloned at the default branch must still be
// able to check out a different branch, a tag, a raw commit SHA, and back
// to the default — the breakage that motivated fetching by name and
// resetting to FETCH_HEAD. The SHA case also backs the first-clone path,
// which now resolves a ref through fetchRef instead of `git clone --branch`.
func TestFetchRefChecksOutRequestedRef(t *testing.T) {
	origin := t.TempDir()
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = testutil.GitEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(origin, "f"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git(origin, "init", "-q", "-b", "main", ".")
	git(origin, "config", "user.email", "t@t.t")
	git(origin, "config", "user.name", "t")
	git(origin, "config", "commit.gpgsign", "false")
	// Let the origin serve an unadvertised commit by SHA; without this a
	// `git fetch origin <sha>` for a non-tip commit is refused.
	git(origin, "config", "uploadpack.allowAnySHA1InWant", "true")
	write("a")
	git(origin, "add", "f")
	git(origin, "commit", "-qm", "a")
	firstSHA := git(origin, "rev-parse", "HEAD")
	git(origin, "checkout", "-q", "-b", "feature")
	write("c")
	git(origin, "commit", "-qam", "c")
	featureSHA := git(origin, "rev-parse", "HEAD")
	git(origin, "checkout", "-q", "main")
	write("b")
	git(origin, "commit", "-qam", "b")
	git(origin, "tag", "-m", "v1", "v1")
	mainSHA := git(origin, "rev-parse", "HEAD")
	tagSHA := git(origin, "rev-parse", "v1^{commit}")

	// Mimic the per-URL cache: a shallow single-branch clone of the default.
	cache := t.TempDir()
	git(cache, "clone", "-q", "--depth", "1", "--branch", "main", "file://"+origin, ".")

	ctx := context.Background()
	noop := func(Event) {}
	cases := []struct{ ref, want string }{
		{"feature", featureSHA}, // a non-default branch absent from the cache
		{"v1", tagSHA},          // a tag
		{firstSHA, firstSHA},    // a raw commit SHA — what `git clone --branch` rejects
		{"", mainSHA},           // empty ref -> default branch
	}
	for _, c := range cases {
		if err := fetchRef(ctx, cache, c.ref, false, noop); err != nil {
			t.Fatalf("fetchRef(%q): %v", c.ref, err)
		}
		if got := git(cache, "rev-parse", "HEAD"); got != c.want {
			t.Errorf("after fetchRef(%q): HEAD = %s, want %s", c.ref, got, c.want)
		}
	}

	if err := fetchRef(ctx, cache, "does-not-exist", false, noop); err == nil {
		t.Error("fetchRef on a nonexistent ref should error")
	}
}

func TestParseRemoteHeads(t *testing.T) {
	out := "deadbeef\trefs/heads/main\n" +
		"cafebabe\trefs/heads/7.2\n" +
		"cafebabe\trefs/heads/7.2\n" + // duplicate ref
		"00000000\trefs/heads/6.4\n" +
		"feedface\trefs/tags/v1\n" // not a head, must be ignored
	if got, want := parseRemoteHeads(out), []string{"6.4", "7.2", "main"}; !slices.Equal(got, want) {
		t.Errorf("parseRemoteHeads = %v, want %v", got, want)
	}
	for _, in := range []string{"", "garbage with no tab", "  \n  "} {
		if got := parseRemoteHeads(in); len(got) != 0 {
			t.Errorf("parseRemoteHeads(%q) = %v, want empty", in, got)
		}
	}
}

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
	err := cloneOrFetch(context.Background(), "https://example.invalid/repo", dst, false, "--upload-pack=/bin/sh", func(Event) {
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
	err := cloneOrFetch(context.Background(), "ssh://git@example.invalid/repo", t.TempDir(), false, "main", func(Event) {})
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
