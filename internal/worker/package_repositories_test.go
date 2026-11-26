package worker

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPackageRepositoryEnv(t *testing.T) {
	got := PackageRepositoryEnv(map[string]string{
		"pypi":     "https://pkgs.example.com/pypi/simple/",
		"npm":      "https://pkgs.example.com/npm/",
		"go":       "https://pkgs.example.com/go",
		"pub":      "https://pkgs.example.com/pub",
		"hex":      "https://pkgs.example.com/hex",
		"rubygems": "https://pkgs.example.com/gem/",
		"maven":    "https://pkgs.example.com/maven/",
		"unknown":  "https://ignored.example.com/",
	})
	want := []string{
		"BUNDLE_USER_CONFIG=/package-repositories/bundler/config",
		"BUN_CONFIG_REGISTRY=https://pkgs.example.com/npm/",
		"GOPROXY=https://pkgs.example.com/go",
		"HEX_MIRROR=https://pkgs.example.com/hex",
		"MAVEN_ARGS=--global-settings /package-repositories/maven/settings.xml",
		"PIP_INDEX_URL=https://pkgs.example.com/pypi/simple/",
		"PUB_HOSTED_URL=https://pkgs.example.com/pub",
		"UV_DEFAULT_INDEX=https://pkgs.example.com/pypi/simple/",
		"YARN_NPM_REGISTRY_SERVER=https://pkgs.example.com/npm/",
		"npm_config_registry=https://pkgs.example.com/npm/",
	}
	if !slices.Equal(got, want) {
		t.Errorf("PackageRepositoryEnv = %v, want %v", got, want)
	}
	for _, e := range got {
		if strings.Contains(e, "BUNDLE_MIRROR") {
			t.Errorf("unexpected mirror env entry %q", e)
		}
	}
	if env := PackageRepositoryEnv(nil); len(env) != 0 {
		t.Errorf("empty input produced %v", env)
	}
}

func TestBuildContainerBaseArgs_PackageEnv(t *testing.T) {
	d := ContainerRunner{PackageEnv: []string{"npm_config_registry=https://pkgs.example.com/npm/"}}
	args := d.buildContainerBaseArgs("/work/abs", hardenedNet{}, "/work")
	found := false
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-e" && args[i+1] == "npm_config_registry=https://pkgs.example.com/npm/" {
			found = true
		}
	}
	if !found {
		t.Errorf("PackageEnv missing from args: %v", args)
	}

	for _, a := range (ContainerRunner{}).buildContainerBaseArgs("/work/abs", hardenedNet{}, "/work") {
		if strings.HasPrefix(a, "npm_config_registry=") {
			t.Errorf("unexpected package env without PackageEnv: %q", a)
		}
		if strings.Contains(a, PackageConfigMountDir) {
			t.Errorf("unexpected package config mount without PackageConfigDir: %q", a)
		}
	}
}

func hasArgPair(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

func TestPackageRepositorySettings_RubyGemsMountsBundlerConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "package-repositories")
	env, configDir, err := PackageRepositorySettings(dir, map[string]string{
		"rubygems": "https://pkgs.example.com/gem/",
		"npm":      "https://pkgs.example.com/npm/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if configDir != dir {
		t.Fatalf("configDir = %q, want %q", configDir, dir)
	}
	want := "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://pkgs.example.com/gem/\"\n"
	got, err := os.ReadFile(filepath.Join(dir, "bundler", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("bundler config = %q, want %q", got, want)
	}

	d := ContainerRunner{PackageEnv: env, PackageConfigDir: configDir}
	args := d.buildContainerBaseArgs("/work/abs", hardenedNet{}, "/work")
	if !hasArgPair(args, "-v", dir+":"+PackageConfigMountDir+":ro") {
		t.Errorf("config mount missing from args: %v", args)
	}
	const envEntry = "BUNDLE_USER_CONFIG=/package-repositories/bundler/config"
	if !hasArgPair(args, "-e", envEntry) {
		t.Errorf("BUNDLE_USER_CONFIG missing from args: %v", args)
	}

	path := strings.TrimPrefix(envEntry, "BUNDLE_USER_CONFIG=")
	host := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(path, PackageConfigMountDir)))
	onHost, err := os.ReadFile(host)
	if err != nil {
		t.Fatalf("env path does not map to a written file: %v", err)
	}
	if string(onHost) != want {
		t.Errorf("mapped file = %q, want %q", onHost, want)
	}
}

func TestPackageRepositorySettings_MavenMountsGlobalSettings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "package-repositories")
	env, configDir, err := PackageRepositorySettings(dir, map[string]string{
		"maven":    "https://pkgs.example.com/maven/",
		"rubygems": "https://pkgs.example.com/gem/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if configDir != dir {
		t.Fatalf("configDir = %q, want %q", configDir, dir)
	}
	want := `<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <mirrors>
    <mirror>
      <id>scrutineer-package-repository</id>
      <mirrorOf>central</mirrorOf>
      <url>https://pkgs.example.com/maven/</url>
    </mirror>
  </mirrors>
</settings>
`
	got, err := os.ReadFile(filepath.Join(dir, "maven", "settings.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("maven settings = %q, want %q", got, want)
	}

	d := ContainerRunner{PackageEnv: env, PackageConfigDir: configDir}
	args := d.buildContainerBaseArgs("/work/abs", hardenedNet{}, "/work")
	mount := dir + ":" + PackageConfigMountDir + ":ro"
	if !hasArgPair(args, "-v", mount) {
		t.Errorf("config mount missing from args: %v", args)
	}
	if n := strings.Count(strings.Join(args, "\x00"), ":"+PackageConfigMountDir+":ro"); n != 1 {
		t.Errorf("found %d config mounts, want 1: %v", n, args)
	}
	const prefix = "--global-settings "
	const envEntry = "MAVEN_ARGS=" + prefix + "/package-repositories/maven/settings.xml"
	if !hasArgPair(args, "-e", envEntry) {
		t.Errorf("MAVEN_ARGS missing from args: %v", args)
	}

	path := strings.TrimPrefix(envEntry, "MAVEN_ARGS="+prefix)
	host := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(path, PackageConfigMountDir)))
	onHost, err := os.ReadFile(host)
	if err != nil {
		t.Fatalf("env path does not map to a written file: %v", err)
	}
	if string(onHost) != want {
		t.Errorf("mapped file = %q, want %q", onHost, want)
	}
}

func TestMavenMirrorSettingsEscapesURL(t *testing.T) {
	got := string(mavenMirrorSettings("https://maven.example.org/repo?a=1&b=2"))
	if !strings.Contains(got, "<url>https://maven.example.org/repo?a=1&amp;b=2</url>") {
		t.Errorf("url not escaped: %s", got)
	}
}

func TestPackageRepositorySettings_NoFileEcosystems(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "package-repositories")
	if err := os.MkdirAll(filepath.Join(dir, "bundler"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundler", "config"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	env, configDir, err := PackageRepositorySettings(dir, map[string]string{"npm": "https://pkgs.example.com/npm/"})
	if err != nil {
		t.Fatal(err)
	}
	if configDir != "" {
		t.Errorf("configDir = %q, want empty", configDir)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("dir should be removed, stat err = %v", err)
	}
	if !slices.Contains(env, "npm_config_registry=https://pkgs.example.com/npm/") {
		t.Errorf("npm env missing: %v", env)
	}
	args := ContainerRunner{PackageEnv: env, PackageConfigDir: configDir}.buildContainerBaseArgs("/work/abs", hardenedNet{}, "/work")
	for _, a := range args {
		if strings.Contains(a, PackageConfigMountDir) {
			t.Errorf("unexpected package config mount: %q", a)
		}
	}
}
