package worker

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// PackageConfigMountDir is where the host's package manager config directory
// is mounted read-only in every scan container.
const PackageConfigMountDir = "/package-repositories"

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
// env names the variable that points the package manager at the mounted file
// and render builds the file from the repository URL.
type packageConfigFile struct {
	path   string
	env    string
	render func(url string) []byte
}

var packageConfigFiles = map[string]packageConfigFile{
	// Bundler reads its user config from BUNDLE_USER_CONFIG. A config file is
	// used because the mirror key contains ':' and '/', which dash drops from
	// the environment.
	"rubygems": {path: "bundler/config", env: "BUNDLE_USER_CONFIG", render: bundlerMirrorConfig},
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
			env = append(env, f.env+"="+PackageConfigMountDir+"/"+f.path)
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
		if err := os.MkdirAll(filepath.Dir(host), 0o700); err != nil {
			return nil, "", fmt.Errorf("write %s package config: %w", eco, err)
		}
		if err := os.WriteFile(host, f.render(repos[eco]), 0o600); err != nil {
			return nil, "", fmt.Errorf("write %s package config: %w", eco, err)
		}
	}
	return PackageRepositoryEnv(repos), dir, nil
}
