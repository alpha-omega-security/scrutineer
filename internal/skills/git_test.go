package skills

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/git-pkgs/clone"

	"scrutineer/internal/testutil"
)

func TestParseRepoSpec(t *testing.T) {
	cases := []struct {
		name, in, wantURL, wantRef string
		wantErr                    bool
	}{
		{"shorthand no ref", "org/skills", "https://github.com/org/skills", "", false},
		{"shorthand tag", "org/skills@v0.3.1", "https://github.com/org/skills", "v0.3.1", false},
		{"shorthand sha", "org/skills@deadbeefcafe", "https://github.com/org/skills", "deadbeefcafe", false},
		{"shorthand branch with slash", "org/skills@feature/foo", "https://github.com/org/skills", "feature/foo", false},
		{"https no ref", "https://github.com/org/skills", "https://github.com/org/skills", "", false},
		{"https with tag", "https://github.com/org/skills@v0.3.1", "https://github.com/org/skills", "v0.3.1", false},
		{"https with credential no ref", "https://token@github.com/org/skills", "", "", true},
		{"https with credential and ref", "https://token@github.com/org/skills@v1.0", "", "", true},
		{"https slash-bearing ref not supported", "https://gitlab.com/org/skills@refs/heads/main", "https://gitlab.com/org/skills@refs/heads/main", "", false},
		{"trims whitespace", "  org/skills@main  ", "https://github.com/org/skills", "main", false},
		{"empty", "", "", "", true},
		{"missing repo half", "org", "", "", true},
		{"too many segments", "org/skills/extra", "", "", true},
		{"trailing slash", "org/skills/", "", "", true},
		{"non-https scheme", "git://host/path", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			url, ref, err := ParseRepoSpec(c.in)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if err != nil {
				return
			}
			if url != c.wantURL || ref != c.wantRef {
				t.Errorf("got (%q,%q) want (%q,%q)", url, ref, c.wantURL, c.wantRef)
			}
		})
	}
}

func TestParseRepoSpec_rejectsUserinfoWithoutEcho(t *testing.T) {
	const secret = "private-skills-token"
	_, _, err := ParseRepoSpec("https://user:" + secret + "@github.com/org/skills")
	if err == nil {
		t.Fatal("expected URL userinfo to be rejected")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("parser error leaked repository credential: %v", err)
	}
}

// initOrigin builds a bare repo whose default branch has two commits with a
// tag at the first one, and maps an https:// URL to it via git's
// url.insteadOf so CloneOrPull's https-only validation passes while the
// clone stays local. Returns (https URL, sha of first commit, sha of HEAD,
// tag name). protocol.file.allow is forced to always because clone.Ensure
// sets GIT_PROTOCOL_FROM_USER=0 to harden production clones, which would
// otherwise reject the resolved file:// transport.
func initOrigin(t *testing.T) (origin, taggedSHA, headSHA, tag string) {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "origin.git")
	work := filepath.Join(root, "work")
	mustRun(t, "", "init", "--quiet", "--bare", "-b", "main", bare)
	mustRun(t, "", "init", "--quiet", "-b", "main", work)
	mustRun(t, work, "config", "user.email", "t@t")
	mustRun(t, work, "config", "user.name", "t")
	mustRun(t, work, "commit", "--quiet", "--allow-empty", "-m", "first")
	taggedSHA = strings.TrimSpace(mustRun(t, work, "rev-parse", "HEAD"))
	mustRun(t, work, "tag", "-a", "v0.3.1", "-m", "v0.3.1")
	mustRun(t, work, "commit", "--quiet", "--allow-empty", "-m", "second")
	headSHA = strings.TrimSpace(mustRun(t, work, "rev-parse", "HEAD"))
	mustRun(t, work, "remote", "add", "origin", bare)
	mustRun(t, work, "push", "--quiet", "origin", "main", "v0.3.1")
	// Bare repos need HEAD set so origin/HEAD resolves on clone.
	mustRun(t, "", "-C", bare, "symbolic-ref", "HEAD", "refs/heads/main")

	origin = "https://skills.test/origin"
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "url.file://"+bare+".insteadOf")
	t.Setenv("GIT_CONFIG_VALUE_0", origin)
	t.Setenv("GIT_CONFIG_KEY_1", "protocol.file.allow")
	t.Setenv("GIT_CONFIG_VALUE_1", "always")
	// clone v0.1.1 sets GIT_ALLOW_PROTOCOL=https on every remote op unless
	// the caller has already set it; the fixture routes through file://.
	t.Setenv("GIT_ALLOW_PROTOCOL", "https:file")
	return origin, taggedSHA, headSHA, "v0.3.1"
}

func mustRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = testutil.GitEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %s: %v", args, out, err)
	}
	return string(out)
}

func TestCloneOrPull_noRefUsesDefaultBranch(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	origin, _, headSHA, _ := initOrigin(t)
	dst := filepath.Join(t.TempDir(), "dst")
	got, err := CloneOrPull(context.Background(), origin, "", dst, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != headSHA {
		t.Errorf("sha = %q, want HEAD %q", got, headSHA)
	}
}

func TestCloneOrPull_pinsTagToResolvedSHA(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	origin, taggedSHA, headSHA, tag := initOrigin(t)
	dst := filepath.Join(t.TempDir(), "dst")
	// fullClone=true so the tag fetch always works regardless of how the
	// initial clone hydrated refs.
	got, err := CloneOrPull(context.Background(), origin, tag, dst, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != taggedSHA {
		t.Errorf("sha = %q, want tagged %q (HEAD is %q)", got, taggedSHA, headSHA)
	}
}

func TestCloneOrPull_unknownRefErrors(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	origin, _, _, _ := initOrigin(t)
	dst := filepath.Join(t.TempDir(), "dst")
	_, err := CloneOrPull(context.Background(), origin, "no-such-ref", dst, true, "")
	if err == nil {
		t.Fatal("expected error for unknown ref")
	}
}

func TestCloneOrPull_secondCallReusesClone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	origin, _, headSHA, _ := initOrigin(t)
	dst := filepath.Join(t.TempDir(), "dst")
	if _, err := CloneOrPull(context.Background(), origin, "", dst, true, ""); err != nil {
		t.Fatal(err)
	}
	// Second call must hit the fetch path (.git exists already).
	if _, err := os.Stat(filepath.Join(dst, ".git")); err != nil {
		t.Fatalf(".git missing: %v", err)
	}
	got, err := CloneOrPull(context.Background(), origin, "", dst, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != headSHA {
		t.Errorf("sha = %q, want %q", got, headSHA)
	}
}

func TestCloneOrPull_rejectsNonHTTPS(t *testing.T) {
	_, err := CloneOrPull(context.Background(), "git://host/path", "", t.TempDir(), false, "")
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected https rejection, got %v", err)
	}
}

func TestCloneOrPull_tokenUsesAskPassWithoutArgvLeak(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("withSkillsRepoToken writes a #!/bin/sh GIT_ASKPASS; Windows cannot exec it")
	}
	const token = "private-skills-token"
	var (
		askpassPath string
		askpassOut  string
		script      string
		gotArgs     []string
		askpassMode os.FileMode
	)
	retry := clone.Retry{
		Attempts: 1,
		Run: func(_ context.Context, _ string, env []string, args ...string) (string, error) {
			gotArgs = append([]string{}, args...)
			var tokenEnv string
			for _, value := range env {
				if strings.HasPrefix(value, "GIT_ASKPASS=") {
					askpassPath = strings.TrimPrefix(value, "GIT_ASKPASS=")
				}
				if strings.HasPrefix(value, skillsRepoTokenEnv+"=") {
					tokenEnv = value
				}
			}
			if askpassPath == "" || tokenEnv != skillsRepoTokenEnv+"="+token {
				return "", fmt.Errorf("missing askpass environment: %q", env)
			}
			body, err := os.ReadFile(askpassPath)
			if err != nil {
				return "", err
			}
			info, err := os.Stat(askpassPath)
			if err != nil {
				return "", err
			}
			askpassMode = info.Mode().Perm()
			script = string(body)
			cmd := exec.Command(askpassPath, "Password for https://skills.test")
			cmd.Env = env
			out, err := cmd.Output()
			askpassOut = strings.TrimSpace(string(out))
			if err != nil {
				return "", err
			}
			return "", errors.New("stop after inspecting git invocation")
		},
	}

	dst := filepath.Join(t.TempDir(), "skills-cache", "checkout")
	_, err := cloneOrPullWithRetry(context.Background(), retry,
		"https://skills.test/org/private-skills", "", dst, false, token)
	if err == nil {
		t.Fatal("expected the inspecting runner to stop the clone")
	}
	if strings.Contains(strings.Join(gotArgs, " "), token) {
		t.Fatalf("token leaked into git argv: %q", gotArgs)
	}
	if len(gotArgs) < 2 || gotArgs[0] != "-c" || gotArgs[1] != "credential.helper=" {
		t.Fatalf("git argv does not disable ambient credential helpers: %q", gotArgs)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("token leaked into clone error: %v", err)
	}
	if askpassOut != token {
		t.Errorf("askpass output = %q, want configured token", askpassOut)
	}
	if filepath.Dir(askpassPath) != filepath.Dir(dst) {
		t.Errorf("askpass directory = %q, want skills cache %q", filepath.Dir(askpassPath), filepath.Dir(dst))
	}
	if strings.Contains(script, token) {
		t.Fatal("temporary askpass script contains the token")
	}
	if askpassMode != askpassPerm && runtime.GOOS != "windows" {
		t.Errorf("askpass mode = %o, want 700", askpassMode)
	}
	if _, statErr := os.Stat(askpassPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("askpass file was not removed: %v", statErr)
	}
}

func TestWithSkillsRepoToken_excludesLocalGitCommands(t *testing.T) {
	const token = "private-skills-token"
	var gotEnv []string
	retry, cleanup, err := withSkillsRepoToken(clone.Retry{
		Run: func(_ context.Context, _ string, env []string, _ ...string) (string, error) {
			gotEnv = append([]string{}, env...)
			return "", nil
		},
	}, token, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := retry.Run(context.Background(), "", nil, "rev-parse", "HEAD"); err != nil {
		t.Fatal(err)
	}
	for _, value := range gotEnv {
		if strings.Contains(value, token) || strings.HasPrefix(value, "GIT_ASKPASS=") {
			t.Fatalf("local git command received authentication environment: %q", gotEnv)
		}
	}
}

func TestCloneOrPull_rejectsMultilineToken(t *testing.T) {
	const token = "first-line\nsecond-line"
	_, err := cloneOrPullWithRetry(context.Background(), clone.Retry{},
		"https://skills.test/org/private-skills", "", t.TempDir(), false, token)
	if err == nil || !strings.Contains(err.Error(), "single line") {
		t.Fatalf("expected single-line token rejection, got %v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("token leaked into validation error: %v", err)
	}
}

// Transient-retry, DestReset, and per-operation retry counts are tested
// upstream in github.com/git-pkgs/clone; the fake-runner tests that
// exercised the same behaviour through cloneOrPullWithRetry were removed
// when the implementation moved there.
