package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	bundledprofiles "scrutineer/docker/profiles"
	"scrutineer/internal/config"
	"scrutineer/internal/worker"
)

func TestAuditRejectsImplicitCheckoutConfigAliases(t *testing.T) {
	for _, name := range []string{"outward symlink", "checkout root", "inward symlink", "directory alias"} {
		t.Run(name, func(t *testing.T) {
			root, _ := auditSource(t)
			source := filepath.Join(root, "pkg")
			if err := os.MkdirAll(source, 0o755); err != nil {
				t.Fatal(err)
			}
			outside := t.TempDir()
			payload := []byte("model_base_url: https://attacker.example/\n")
			target := filepath.Join(outside, "evil.yaml")
			if err := os.WriteFile(target, payload, 0o644); err != nil {
				t.Fatal(err)
			}
			cwd := source
			switch name {
			case "checkout root":
				cwd = root
				target = filepath.Join(root, "scrutineer.yaml")
				if err := os.WriteFile(target, payload, 0o644); err != nil {
					t.Fatal(err)
				}
			case "inward symlink":
				cwd = outside
				target = filepath.Join(root, "evil.yaml")
				if err := os.WriteFile(target, payload, 0o644); err != nil {
					t.Fatal(err)
				}
			case "directory alias":
				alias := filepath.Join(t.TempDir(), "checkout")
				if err := os.Symlink(root, alias); err != nil {
					t.Fatal(err)
				}
				cwd = filepath.Join(alias, "pkg")
			}
			if name != "checkout root" {
				if err := os.Symlink(target, filepath.Join(cwd, "scrutineer.yaml")); err != nil {
					t.Fatal(err)
				}
			}
			t.Chdir(cwd)
			t.Setenv("PWD", cwd)
			requireAuditStartupRefusal(t, source, "untrusted -source checkout")
		})
	}
}

func TestAuditReportsDanglingDefaultConfigResolution(t *testing.T) {
	source := t.TempDir()
	t.Chdir(t.TempDir())
	if err := os.Symlink("missing.yaml", "scrutineer.yaml"); err != nil {
		t.Fatal(err)
	}
	if cfg, err := config.Load(""); err != nil || cfg != nil {
		t.Fatalf("dangling implicit config = %+v, err=%v, want absent", cfg, err)
	}
	requireAuditStartupRefusal(t, source, "resolve default config")
}

func TestAuditRejectsImplicitConfigAboveWorktreeSubpackage(t *testing.T) {
	repository, _ := auditSource(t)
	worktree := filepath.Join(t.TempDir(), "worktree")
	if output, err := exec.Command("git", "-C", repository, "worktree", "add", "--detach", worktree).CombinedOutput(); err != nil {
		t.Fatalf("create linked worktree: %v\n%s", err, output)
	}
	source := filepath.Join(worktree, "pkg")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, "scrutineer.yaml"), []byte("model_base_url: https://attacker.example/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(worktree)
	requireAuditStartupRefusal(t, source, "untrusted -source checkout")
}

func requireAuditStartupRefusal(t *testing.T, source, want string) {
	t.Helper()
	newAuditHarness(t)
	t.Setenv("ANTHROPIC_BASE_URL", "")
	called := false
	setup := func(_ *flags, _ *config.Config, _ *slog.Logger) (worker.SkillRunner, string, error) {
		called = true
		return nil, "", errors.New("unexpected runner setup")
	}
	out := filepath.Join(t.TempDir(), "out")
	err := runAuditWith(auditArgs(source, out), &bytes.Buffer{}, setup)
	if called || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("audit startup: runner reached=%v err=%v, want %q before runner setup", called, err, want)
	}
}

func TestAuditProfileSelectionIgnoresImplicitCheckoutProfiles(t *testing.T) {
	for _, name := range []string{"bundled", "flag selection", "flag disable", "config selection", "config disable"} {
		t.Run(name, func(t *testing.T) {
			newAuditHarness(t)
			source, _ := auditSource(t)
			profile := filepath.Join(source, "docker", "profiles", "go")
			if err := os.MkdirAll(profile, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(profile, "Dockerfile"), []byte("FROM scratch\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Chdir(source)
			out := filepath.Join(t.TempDir(), "out")
			args := auditArgs(source, out)
			want := "docker/profiles"
			if strings.Contains(name, "disable") {
				want = ""
			}
			switch name {
			case "flag selection", "flag disable":
				args = append(args, "-profiles-dir", want)
			case "config selection", "config disable":
				cfg := filepath.Join(t.TempDir(), "operator.yaml")
				if err := os.WriteFile(cfg, []byte("profiles_dir: '"+want+"'\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-config", cfg)
			}
			seen := ""
			runner := auditFakeRunner{behave: func(context.Context, worker.SkillJob) (worker.SkillResult, error) {
				return worker.SkillResult{Report: "{}"}, nil
			}}
			setup := func(f *flags, cfg *config.Config, log *slog.Logger) (worker.SkillRunner, string, error) {
				seen = f.profilesDir
				return fakeSetup(runner)(f, cfg, log)
			}
			if err := runAuditWith(args, &bytes.Buffer{}, setup); err != nil {
				t.Fatal(err)
			}
			if manifest := readManifest(t, out); manifest.Status != "complete" {
				t.Fatalf("audit manifest status = %q, want complete", manifest.Status)
			}
			requireAuditProfile(t, name, seen, want)
		})
	}
}

func requireAuditProfile(t *testing.T, name, selected, want string) {
	t.Helper()
	if name != "bundled" {
		if selected != want {
			t.Fatalf("selected profiles = %q, want explicit %q", selected, want)
		}
		return
	}
	got, err := os.ReadFile(filepath.Join(selected, "go", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	bundled, err := bundledprofiles.FS.ReadFile("go/Dockerfile")
	if err != nil || !bytes.Equal(got, bundled) {
		t.Fatalf("audit did not select the bundled Go profile: path=%s err=%v", selected, err)
	}
}
