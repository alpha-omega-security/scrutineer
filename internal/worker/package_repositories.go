package worker

import "slices"

// packageRepositoryVars maps an ecosystem name from package_repositories to
// the environment variables its package managers read.
var packageRepositoryVars = map[string][]string{
	"npm":  {"npm_config_registry", "YARN_NPM_REGISTRY_SERVER", "BUN_CONFIG_REGISTRY"},
	"pypi": {"PIP_INDEX_URL", "UV_DEFAULT_INDEX"},
	// No ",direct" suffix so a miss never falls back to the public upstream.
	"go":  {"GOPROXY"},
	"pub": {"PUB_HOSTED_URL"},
	"hex": {"HEX_MIRROR"},
	// Bundler reads this mirror for the default rubygems.org source. The
	// trailing slash in the name is required.
	"rubygems": {"BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/"},
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
	}
	slices.Sort(env)
	return env
}
