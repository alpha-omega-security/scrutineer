package skills

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
		{"https with credential no ref", "https://token@github.com/org/skills", "https://token@github.com/org/skills", "", false},
		{"https with credential and ref", "https://token@github.com/org/skills@v1.0", "https://token@github.com/org/skills", "v1.0", false},
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

// initOrigin builds a bare repo whose default branch has two commits with a
// tag at the first one. Returns (origin URL using file://, sha of first
// commit, sha of HEAD, tag name). Also allows file:// transport for the
// duration of the test, CloneOrPull sets GIT_PROTOCOL_FROM_USER=0 to harden
// production clones, which would otherwise reject file://.
func initOrigin(t *testing.T) (origin, taggedSHA, headSHA, tag string) {
	t.Helper()
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "protocol.file.allow")
	t.Setenv("GIT_CONFIG_VALUE_0", "always")
	root := t.TempDir()
	origin = filepath.Join(root, "origin.git")
	work := filepath.Join(root, "work")
	mustRun(t, "", "init", "--quiet", "--bare", "-b", "main", origin)
	mustRun(t, "", "init", "--quiet", "-b", "main", work)
	mustRun(t, work, "config", "user.email", "t@t")
	mustRun(t, work, "config", "user.name", "t")
	mustRun(t, work, "commit", "--quiet", "--allow-empty", "-m", "first")
	taggedSHA = strings.TrimSpace(mustRun(t, work, "rev-parse", "HEAD"))
	mustRun(t, work, "tag", "-a", "v0.3.1", "-m", "v0.3.1")
	mustRun(t, work, "commit", "--quiet", "--allow-empty", "-m", "second")
	headSHA = strings.TrimSpace(mustRun(t, work, "rev-parse", "HEAD"))
	mustRun(t, work, "remote", "add", "origin", origin)
	mustRun(t, work, "push", "--quiet", "origin", "main", "v0.3.1")
	// Bare repos need HEAD set so origin/HEAD resolves on clone.
	mustRun(t, "", "-C", origin, "symbolic-ref", "HEAD", "refs/heads/main")
	return "file://" + origin, taggedSHA, headSHA, "v0.3.1"
}

func mustRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = testGitEnv()
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
	got, err := cloneOrPull(context.Background(), origin, "", dst, false)
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
	got, err := cloneOrPull(context.Background(), origin, tag, dst, true)
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
	_, err := cloneOrPull(context.Background(), origin, "no-such-ref", dst, true)
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
	if _, err := cloneOrPull(context.Background(), origin, "", dst, true); err != nil {
		t.Fatal(err)
	}
	// Second call must hit the fetch path (.git exists already).
	if _, err := os.Stat(filepath.Join(dst, ".git")); err != nil {
		t.Fatalf(".git missing: %v", err)
	}
	got, err := cloneOrPull(context.Background(), origin, "", dst, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != headSHA {
		t.Errorf("sha = %q, want %q", got, headSHA)
	}
}

func TestCloneOrPull_rejectsNonHTTPS(t *testing.T) {
	_, err := CloneOrPull(context.Background(), "git://host/path", "", t.TempDir(), false)
	if err == nil || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected https rejection, got %v", err)
	}
}
