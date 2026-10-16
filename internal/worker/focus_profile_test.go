package worker

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMatchFocusProfile(t *testing.T) {
	for _, tt := range []struct{ name, report, want string }{
		{"JS inside PHP", `{"languages":[{"name":"JavaScript"}],"package_managers":[{"name":"Composer"}]}`, "node"},
		{"TypeScript", `{"languages":[{"name":"TypeScript"}]}`, "node"},
		{"PHP source", `{"languages":[{"name":"PHP"}]}`, "php"},
		{"PHP extension", `{"languages":[{"name":"PHP"}],"tools":{"native_extension":[{"name":"phpize"}]}}`, "php-ext"},
		{"JS inside PHP extension", `{"languages":[{"name":"JavaScript"}],"tools":{"native_extension":[{"name":"phpize"}]}}`, "node"},
		{"Ruby extension", `{"languages":[{"name":"Ruby"}],"tools":{"native_extension":[{"name":"mkmf"}]}}`, "ruby-ext"},
		{"data before Python", `{"languages":[{"name":"JSON","category":"data"},{"name":"Python","category":"language"}]}`, "python"},
		{"unknown", `{"languages":[{"name":"Unknown"}]}`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchFocusProfile([]byte(tt.report)); got.Name != tt.want {
				t.Fatalf("profile = %q, want %q", got.Name, tt.want)
			}
		})
	}
}

func TestCopyFocusFilesKeepsScopeAndSource(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	for _, path := range []string{"composer.json", "packages/client/src/action.ts", "packages/server/src/action.ts", ".git/config"} {
		full := filepath.Join(src, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("original"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(src, "composer.json"), filepath.Join(src, "packages/client/src/link.ts")); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyFocusFiles(t.Context(), src, dst, "packages/client", []string{"packages/**", ".git/**"}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dst, "packages/client/src/action.ts")); err != nil || string(data) != "original" {
		t.Fatalf("copied source = %q, %v", data, err)
	}
	for _, path := range []string{"composer.json", "packages/server/src/action.ts", ".git/config", "packages/client/src/link.ts"} {
		if _, err := os.Lstat(filepath.Join(dst, path)); !os.IsNotExist(err) {
			t.Errorf("unexpected copied %s: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(src, "composer.json")); err != nil {
		t.Fatalf("original manifest removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(src, "packages/server/src/action.ts")); err != nil {
		t.Fatalf("original sibling removed: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := copyFocusFiles(ctx, src, dst, "", []string{"**"}); err == nil {
		t.Fatal("cancelled copy succeeded")
	}
}

func TestRunSkillRejectsInvalidFocus(t *testing.T) {
	runner := ContainerRunner{ProfilesDir: t.TempDir(), Harness: dockerNoopHarness{}}
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := runner.RunSkill(t.Context(), SkillJob{WorkRoot: work, SrcReady: true, FocusArea: `{"name":"escape","paths":["../secret"],"surface":"input"}`}, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "profile focus area") {
		t.Fatalf("error = %v", err)
	}
}

func TestCopyFocusFilesRejectsEscapingSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	work, outside := t.TempDir(), t.TempDir()
	src := filepath.Join(work, "src")
	if err := os.WriteFile(filepath.Join(outside, "secret.js"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, src); err != nil {
		t.Fatal(err)
	}
	if err := copyFocusFiles(t.Context(), src, t.TempDir(), "", []string{"**"}); err == nil {
		t.Fatal("copied source outside the workspace")
	}
}
