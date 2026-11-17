package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/git-pkgs/clone"

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
	err := cloneOrFetch(context.Background(), gitRetry{}, "https://example.invalid/repo", dst, false, "--upload-pack=/bin/sh", submoduleOptions{}, func(Event) {
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
	err := cloneOrFetch(context.Background(), gitRetry{}, "ssh://git@example.invalid/repo", t.TempDir(), false, "main", submoduleOptions{}, func(Event) {})
	if err == nil {
		t.Fatal("expected error for non-https URL")
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("error %q should mention https requirement", err)
	}
}

// newPrivateSubmoduleOrigin serves an origin whose vendor/private submodule
// points at submoduleURL, which is never reachable without credentials. It
// returns the origin's URL and directory.
func newPrivateSubmoduleOrigin(t *testing.T, submoduleURL string, extraConfig ...string) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	originDir := t.TempDir()
	testGit(t, originDir, "init", "--quiet", "-b", "main")
	testGit(t, originDir, "config", "-f", ".gitmodules", "submodule.private.path", "vendor/private")
	testGit(t, originDir, "config", "-f", ".gitmodules", "submodule.private.url", submoduleURL)
	testGit(t, originDir, "add", ".gitmodules")
	testGit(t, originDir, "update-index", "--add", "--cacheinfo",
		"160000,0123456789abcdef0123456789abcdef01234567,vendor/private")
	testGit(t, originDir, "commit", "--quiet", "-m", "private submodule")

	url := "https://clone.test/private-submodule"
	config := append([]string{
		"url.file://" + originDir + ".insteadOf", url,
		"protocol.file.allow", "always",
	}, extraConfig...)
	for i := 0; i < len(config); i += 2 {
		t.Setenv(fmt.Sprintf("GIT_CONFIG_KEY_%d", i/2), config[i])
		t.Setenv(fmt.Sprintf("GIT_CONFIG_VALUE_%d", i/2), config[i+1])
	}
	t.Setenv("GIT_CONFIG_COUNT", fmt.Sprint(len(config)/2))
	t.Setenv("GIT_ALLOW_PROTOCOL", "https:file")
	return url, originDir
}

func TestPrepareRepoSrcLogsMissingSubmodule(t *testing.T) {
	url, _ := newPrivateSubmoduleOrigin(t, "https://127.0.0.1:1/example/private.git")

	w := &Worker{DataDir: shortTempDir(t)}
	var events []string
	if _, err := w.prepareRepoSrcWithOptions(
		context.Background(), url, "", t.TempDir(), RepoSrcOptions{RecurseSubmodules: true},
		func(e Event) { events = append(events, FormatEvent(e)) },
	); err != nil {
		t.Fatalf("prepare with submodules: %v", err)
	}
	log := strings.Join(events, "\n")
	want := "submodule vendor/private not fetched: fetch failed (https://127.0.0.1:1/example/private.git)"
	if !strings.Contains(log, want) {
		t.Errorf("scan log missing %q:\n%s", want, log)
	}
	if strings.Contains(log, "best effort") {
		t.Errorf("scan log still marks the submodule step best effort:\n%s", log)
	}
}

func TestPrepareRepoSrcDoesNotCopyStaleSubmoduleCheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	libraryDir := t.TempDir()
	testGit(t, libraryDir, "init", "--quiet", "-b", "main")
	if err := os.WriteFile(filepath.Join(libraryDir, "lib.c"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, libraryDir, "add", "lib.c")
	testGit(t, libraryDir, "commit", "--quiet", "-m", "old")

	const libraryURL = "https://clone.test/library"
	url, originDir := newPrivateSubmoduleOrigin(t, libraryURL, "url.file://"+libraryDir+".insteadOf", libraryURL)
	setGitlink := func(commit string) {
		testGit(t, originDir, "update-index", "--cacheinfo", "160000,"+commit+",vendor/private")
		testGit(t, originDir, "commit", "--quiet", "-m", "point submodule at "+commit)
	}
	setGitlink(testGit(t, libraryDir, "rev-parse", "HEAD"))

	w := &Worker{DataDir: shortTempDir(t)}
	options := RepoSrcOptions{RecurseSubmodules: true}
	first := t.TempDir()
	if _, err := w.prepareRepoSrcWithOptions(context.Background(), url, "", first, options, func(Event) {}); err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	if _, err := os.Stat(filepath.Join(first, "src", "vendor", "private", "lib.c")); err != nil {
		t.Fatalf("submodule not checked out: %v", err)
	}

	setGitlink("0123456789abcdef0123456789abcdef01234567")
	second := t.TempDir()
	if _, err := w.prepareRepoSrcWithOptions(context.Background(), url, "", second, options, func(Event) {}); err != nil {
		t.Fatalf("second prepare: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(second, "src", "vendor", "private"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("scan copy holds the submodule's previous checkout: %d entries", len(entries))
	}
}

func TestPrepareRepoSrcUsesCredentialHelperOnlyForTrustedSubmodules(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	for _, test := range []struct {
		credentialURLs []string
		wantHelper     bool
	}{
		{nil, false},
		{[]string{server.URL + "/other"}, false},
		{[]string{server.URL + "/example"}, true},
	} {
		marker := filepath.Join(t.TempDir(), "helper-called")
		t.Setenv("SCRUTINEER_TEST_HELPER_MARKER", filepath.ToSlash(marker))
		url, _ := newPrivateSubmoduleOrigin(t, server.URL+"/example/private.git",
			"credential.helper", `!f() { echo "$1" >> "$SCRUTINEER_TEST_HELPER_MARKER"; }; f`,
			"http.sslVerify", "false",
		)

		w := &Worker{DataDir: shortTempDir(t), SubmoduleCredentialURLs: test.credentialURLs}
		var events []string
		if _, err := w.prepareRepoSrcWithOptions(
			context.Background(), url, "", t.TempDir(), RepoSrcOptions{RecurseSubmodules: true},
			func(e Event) { events = append(events, FormatEvent(e)) },
		); err != nil {
			t.Fatalf("credential URLs %q: prepare with submodules: %v", test.credentialURLs, err)
		}
		_, err := os.Stat(marker)
		if called := err == nil; called != test.wantHelper {
			t.Errorf("credential URLs %q: helper called = %v, want %v\n%s",
				test.credentialURLs, called, test.wantHelper, strings.Join(events, "\n"))
		}
		if !slices.ContainsFunc(events, func(e string) bool { return strings.Contains(e, "vendor/private not fetched") }) {
			t.Errorf("credential URLs %q: missing submodule not logged:\n%s", test.credentialURLs, strings.Join(events, "\n"))
		}
	}
}

func TestSubmoduleIssueText(t *testing.T) {
	for _, test := range []struct {
		issue clone.SubmoduleIssue
		want  string
	}{
		{
			clone.SubmoduleIssue{Path: "a", URL: "https://h/a.git", Reason: clone.SubmoduleIssueFetchFailed, Output: "fatal: denied"},
			"submodule a not fetched: fetch failed (https://h/a.git)\nfatal: denied",
		},
		{
			clone.SubmoduleIssue{Path: "a/b", Reason: clone.SubmoduleIssueDepthLimit},
			"submodule a/b not fetched: nested deeper than the submodule depth limit",
		},
		{
			clone.SubmoduleIssue{Path: "c", URL: "https://h/c.git", Reason: clone.SubmoduleIssueModuleLimit},
			"submodule c not fetched: over the submodule count limit (https://h/c.git)",
		},
	} {
		if got := submoduleIssueText(test.issue); got != test.want {
			t.Errorf("submoduleIssueText(%+v) = %q, want %q", test.issue, got, test.want)
		}
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
