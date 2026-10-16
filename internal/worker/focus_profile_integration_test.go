package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFocusPHPExtension(t *testing.T, image string) {
	t.Helper()
	work := t.TempDir()
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string]string{
		"config.m4":   "PHP_ARG_ENABLE(example, whether to enable example, [ --enable-example Enable example])\nPHP_NEW_EXTENSION(example, example.c, $ext_shared)\n",
		"example.c":   "#include <php.h>\nPHP_FUNCTION(example) {}\n",
		"example.php": "<?php example();\n",
		"test.php":    "<?php example();\n",
	} {
		if err := os.WriteFile(filepath.Join(src, path), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := ContainerRunner{
		Image: image, Runtime: ContainerRuntime{Bin: "docker"}, ProfilesDir: filepath.Join("..", "..", "docker", "profiles"),
		Harness: isolationHarness{stubHarness: stubHarness{guide: "PROFILE.md"}, script: "set -eu; test -f src/config.m4; php-config --configure-options > result.txt"},
	}
	result, err := runner.RunSkill(t.Context(), SkillJob{WorkRoot: work, SrcReady: true, Name: "extension-probe", OutputFile: "result.txt", RequiresProfile: "php-ext",
		FocusArea: `{"name":"extension","paths":["**"],"surface":"extension API"}`}, func(e Event) {
		if e.Text != "" {
			t.Log(e.Text)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != "php-ext" {
		t.Fatalf("profile = %q, want php-ext", result.Profile)
	}
	output, err := os.ReadFile(filepath.Join(work, "result.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, option := range []string{"--enable-debug", "--enable-address-sanitizer", "--enable-undefined-sanitizer"} {
		if !strings.Contains(string(output), option) {
			t.Errorf("PHP configure options %q missing %s", output, option)
		}
	}
}

func TestIntegration_FocusProfile(t *testing.T) {
	image := os.Getenv("SCRUTINEER_TEST_RUNNER_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_RUNNER_IMAGE for container profile checks")
	}
	t.Run("PHP extension", func(t *testing.T) { testFocusPHPExtension(t, image) })
	work := t.TempDir()
	for path, content := range map[string]string{
		"composer.json":                      `{"name":"example/backend","require":{"php":"*"}}`,
		"Classes/Controller.php":             "<?php echo 'server';\n",
		"package.json":                       `{"private":true,"workspaces":["packages/*"]}`,
		"packages/utils-redux/package.json":  `{"name":"@example/utils-redux","private":true}`,
		"packages/utils-redux/src/action.js": "console.log('focus-runtime-ok');\n",
	} {
		full := filepath.Join(work, "src", path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runner := ContainerRunner{
		Image: image, Runtime: ContainerRuntime{Bin: "docker"}, ProfilesDir: filepath.Join("..", "..", "docker", "profiles"),
		Harness: isolationHarness{stubHarness: stubHarness{guide: "PROFILE.md"}, script: "set -eu; test -f src/composer.json; test -f src/Classes/Controller.php; node src/packages/utils-redux/src/action.js > result.txt"},
	}
	result, err := runner.RunSkill(t.Context(), SkillJob{WorkRoot: work, SrcReady: true, Name: "focus-probe", OutputFile: "result.txt",
		FocusArea: `{"name":"Redux actions","paths":["packages/utils-redux/src/**"],"surface":"actions"}`}, func(e Event) {
		if e.Text != "" {
			t.Log(e.Text)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != "node" {
		t.Fatalf("profile = %q, want node", result.Profile)
	}
	output, err := os.ReadFile(filepath.Join(work, "result.txt"))
	if err != nil || strings.TrimSpace(string(output)) != "focus-runtime-ok" {
		t.Fatalf("runtime output = %q, %v", output, err)
	}
	for _, tt := range []struct{ name, paths, want string }{
		{"PHP directory", "Classes/**", "php"},
		{"no matching files", "missing/**", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := runner.focusProfile(t.Context(), filepath.Join(work, "src"), "", []string{tt.paths})
			if err != nil || profile.Name != tt.want {
				t.Fatalf("profile = %q, %v; want %q", profile.Name, err, tt.want)
			}
		})
	}
	t.Run("explicit default override", func(t *testing.T) {
		override := runner
		override.Harness = isolationHarness{script: "set -eu; test -f src/Classes/Controller.php; printf 'override-ok' > override.txt"}
		result, err := override.RunSkill(t.Context(), SkillJob{WorkRoot: work, SrcReady: true, Name: "override-probe", OutputFile: "override.txt",
			Profile: "default", FocusArea: `{"name":"Redux actions","paths":["packages/utils-redux/src/**"],"surface":"actions"}`}, func(e Event) {
			if strings.Contains(e.Text, "profile: focus") {
				t.Errorf("explicit override triggered focus detection: %s", e.Text)
			}
		})
		if err != nil || result.Profile != "" {
			t.Fatalf("profile = %q, %v; want default", result.Profile, err)
		}
		if output, err := os.ReadFile(filepath.Join(work, "override.txt")); err != nil || string(output) != "override-ok" {
			t.Fatalf("override output = %q, %v", output, err)
		}
	})
}
