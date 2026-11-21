package worker

import (
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
		"unknown":  "https://ignored.example.com/",
	})
	want := []string{
		"BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/=https://pkgs.example.com/gem/",
		"BUN_CONFIG_REGISTRY=https://pkgs.example.com/npm/",
		"GOPROXY=https://pkgs.example.com/go",
		"HEX_MIRROR=https://pkgs.example.com/hex",
		"PIP_INDEX_URL=https://pkgs.example.com/pypi/simple/",
		"PUB_HOSTED_URL=https://pkgs.example.com/pub",
		"UV_DEFAULT_INDEX=https://pkgs.example.com/pypi/simple/",
		"YARN_NPM_REGISTRY_SERVER=https://pkgs.example.com/npm/",
		"npm_config_registry=https://pkgs.example.com/npm/",
	}
	if !slices.Equal(got, want) {
		t.Errorf("PackageRepositoryEnv = %v, want %v", got, want)
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
	}
}
