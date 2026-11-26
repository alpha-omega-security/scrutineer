package worker

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// PackageConfigMountDir is where the host's package manager config directory
// is mounted read-only in every scan container.
const PackageConfigMountDir = "/package-repositories"

// Package config files are owner-only, like other host state the runner
// writes.
const (
	packageConfigDirPerm  = 0o700
	packageConfigFilePerm = 0o600
)

// packageRepositoryVars maps an ecosystem name from package_repositories to
// the environment variables its package managers read.
var packageRepositoryVars = map[string][]string{
	"npm":  {"npm_config_registry", "YARN_NPM_REGISTRY_SERVER", "BUN_CONFIG_REGISTRY"},
	"pypi": {"PIP_INDEX_URL", "UV_DEFAULT_INDEX"},
	// No ",direct" suffix so a miss never falls back to the public upstream.
	"go":  {"GOPROXY"},
	"pub": {"PUB_HOSTED_URL"},
	"hex": {"HEX_MIRROR"},
}

// packageConfigFile is a package manager config file written on the host for
// one ecosystem. path is relative to the config directory (slash separated),
// env names the variable that points the package manager at the mounted file,
// envPrefix is placed before the mounted path in the variable's value (empty
// when the value is the bare path) and render builds the file from the
// repository URL.
type packageConfigFile struct {
	path      string
	env       string
	envPrefix string
	render    func(url string) []byte
}

var packageConfigFiles = map[string]packageConfigFile{
	// Bundler reads its user config from BUNDLE_USER_CONFIG. A config file is
	// used because the mirror key contains ':' and '/', which dash drops from
	// the environment.
	"rubygems": {path: "bundler/config", env: "BUNDLE_USER_CONFIG", render: bundlerMirrorConfig},
	// Global settings rather than user settings, so a project's own -s file or
	// ~/.m2/settings.xml still applies on top.
	"maven": {path: "maven/settings.xml", env: "MAVEN_ARGS", envPrefix: "--global-settings ", render: mavenMirrorSettings},
}

// mavenMirrorSettings renders a Maven settings file that mirrors central to
// the repository URL.
func mavenMirrorSettings(url string) []byte {
	var esc bytes.Buffer
	_ = xml.EscapeText(&esc, []byte(url)) // writing to a bytes.Buffer cannot fail
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <mirrors>
    <mirror>
      <id>scrutineer-package-repository</id>
      <mirrorOf>central</mirrorOf>
      <url>` + esc.String() + `</url>
    </mirror>
  </mirrors>
</settings>
`)
}

// bundlerMirrorConfig renders the file Bundler 2.6 writes for
// "bundle config set --global mirror.https://rubygems.org <url>". The key
// stays unquoted: Bundler 4 quotes it but Bundler 2.6 ignores a quoted key,
// while both read this form. Config validation rejects quotes, backslashes
// and whitespace, so the URL needs no escaping.
func bundlerMirrorConfig(url string) []byte {
	return []byte("---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"" + url + "\"\n")
}

// PackageRepositoryEnv returns sorted KEY=VALUE entries that point package
// managers at the given repository URLs, keyed by ecosystem name. Unknown
// ecosystems are ignored.
func PackageRepositoryEnv(repos map[string]string) []string {
	var env []string
	for eco, url := range repos {
		for _, name := range packageRepositoryVars[eco] {
			env = append(env, name+"="+url)
		}
		if f, ok := packageConfigFiles[eco]; ok {
			env = append(env, f.env+"="+f.envPrefix+PackageConfigMountDir+"/"+f.path)
		}
	}
	slices.Sort(env)
	return env
}

// PackageRepositorySettings returns the scan container settings for repos:
// sorted KEY=VALUE env entries plus the host directory to mount read-only at
// PackageConfigMountDir. dir is recreated from scratch so files from an
// earlier configuration never linger. configDir is empty when no ecosystem
// needs a file. dir is then removed.
func PackageRepositorySettings(dir string, repos map[string]string) (env []string, configDir string, err error) {
	if err := os.RemoveAll(dir); err != nil {
		return nil, "", fmt.Errorf("reset package config dir: %w", err)
	}
	var ecos []string
	for _, eco := range slices.Sorted(maps.Keys(repos)) {
		if _, ok := packageConfigFiles[eco]; ok {
			ecos = append(ecos, eco)
		}
	}
	if len(ecos) == 0 {
		return PackageRepositoryEnv(repos), "", nil
	}
	for _, eco := range ecos {
		f := packageConfigFiles[eco]
		host := filepath.Join(dir, filepath.FromSlash(f.path))
		if err := os.MkdirAll(filepath.Dir(host), packageConfigDirPerm); err != nil {
			return nil, "", fmt.Errorf("write %s package config: %w", eco, err)
		}
		if err := os.WriteFile(host, f.render(repos[eco]), packageConfigFilePerm); err != nil {
			return nil, "", fmt.Errorf("write %s package config: %w", eco, err)
		}
	}
	return PackageRepositoryEnv(repos), dir, nil
}
