package config

import (
	"slices"
	"strings"
	"testing"
)

func TestPackageRepositoriesResolvePreset(t *testing.T) {
	got := PackageRepositories{GitPkgsProxy: "https://pkgs.example.com/"}.Resolve()
	want := map[string]string{
		"npm":      "https://pkgs.example.com/npm/",
		"pypi":     "https://pkgs.example.com/pypi/simple/",
		"go":       "https://pkgs.example.com/go",
		"pub":      "https://pkgs.example.com/pub",
		"rubygems": "https://pkgs.example.com/gem/",
		"maven":    "https://pkgs.example.com/maven/",
	}
	if len(got) != len(want) {
		t.Fatalf("Resolve = %v, want %v", got, want)
	}
	if _, ok := got["hex"]; ok {
		t.Errorf("preset set hex = %q, Hex must only come from an explicit key", got["hex"])
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestPackageRepositoriesResolveExplicitWins(t *testing.T) {
	got := PackageRepositories{GitPkgsProxy: "https://pkgs.example.com", NPM: "https://npm.example.org/"}.Resolve()
	if got["npm"] != "https://npm.example.org/" {
		t.Errorf("npm = %q, explicit value must win", got["npm"])
	}
	if got["pypi"] != "https://pkgs.example.com/pypi/simple/" {
		t.Errorf("pypi = %q, preset must still apply", got["pypi"])
	}
}

func TestPackageRepositoriesResolveRubyGemsExplicitWins(t *testing.T) {
	got := PackageRepositories{GitPkgsProxy: "https://pkgs.example.com", RubyGems: "https://gems.example.org/"}.Resolve()
	if got["rubygems"] != "https://gems.example.org/" {
		t.Errorf("rubygems = %q, explicit value must win", got["rubygems"])
	}
}

func TestPackageRepositoriesResolveMavenExplicitWins(t *testing.T) {
	got := PackageRepositories{GitPkgsProxy: "https://pkgs.example.com", Maven: "https://maven.example.org/"}.Resolve()
	if got["maven"] != "https://maven.example.org/" {
		t.Errorf("maven = %q, explicit value must win", got["maven"])
	}
}

func TestPackageRepositoriesResolveEmpty(t *testing.T) {
	if got := (PackageRepositories{}).Resolve(); len(got) != 0 {
		t.Errorf("Resolve = %v, want empty", got)
	}
	if got := (PackageRepositories{}).Hosts(); len(got) != 0 {
		t.Errorf("Hosts = %v, want empty", got)
	}
}

func TestPackageRepositoriesResolveOnlyExplicit(t *testing.T) {
	got := PackageRepositories{Hex: "https://hex.example.com"}.Resolve()
	if len(got) != 1 || got["hex"] != "https://hex.example.com" {
		t.Errorf("Resolve = %v", got)
	}
}

func TestPackageRepositoriesHosts(t *testing.T) {
	got := PackageRepositories{
		GitPkgsProxy: "https://Pkgs.Example.com:8443",
		NPM:          "https://npm.example.org/",
		Go:           "https://pkgs.example.com/goproxy",
	}.Hosts()
	want := []string{"npm.example.org", "pkgs.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("Hosts = %v, want %v", got, want)
	}
}

func TestPackageRepositoriesHostPorts(t *testing.T) {
	got := PackageRepositories{
		GitPkgsProxy: "https://Pkgs.Example.com:8443",
		NPM:          "https://npm.example.org/",
		Hex:          "https://[2001:db8::1]/hex",
	}.HostPorts()
	want := []string{"[2001:db8::1]:443", "npm.example.org:443", "pkgs.example.com:8443"}
	if !slices.Equal(got, want) {
		t.Errorf("HostPorts = %v, want %v", got, want)
	}
}

func TestValidatePackageRepositories(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    PackageRepositories
		want string
	}{
		{"valid", PackageRepositories{GitPkgsProxy: "https://pkgs.example.com", NPM: "HTTPS://npm.example.org/x"}, ""},
		{"empty", PackageRepositories{}, ""},
		{"public ip", PackageRepositories{NPM: "https://8.8.8.8/npm"}, ""},
		{"http", PackageRepositories{NPM: "http://npm.example.org"}, "package_repositories.npm: "},
		{"relative", PackageRepositories{PyPI: "npm.example.org/simple"}, "package_repositories.pypi: "},
		{"no host", PackageRepositories{Go: "https:///path"}, "package_repositories.go: "},
		{"userinfo", PackageRepositories{Pub: "https://user:pw@pub.example.org"}, "credentials are not supported"},
		{"rubygems http", PackageRepositories{RubyGems: "http://gems.example.org"}, "package_repositories.rubygems: "},
		{"maven http", PackageRepositories{Maven: "http://maven.example.org"}, "package_repositories.maven: "},
		{"query", PackageRepositories{Hex: "https://hex.example.org?token=x"}, "package_repositories.hex: "},
		{"fragment", PackageRepositories{GitPkgsProxy: "https://pkgs.example.com#x"}, "package_repositories.git_pkgs_proxy: "},
		{"list separator", PackageRepositories{Go: "https://go.example.org/a,direct"}, "package_repositories.go: "},
		{"quote", PackageRepositories{RubyGems: `https://gems.example.org/a"b/`}, "must not contain quotes"},
		{"backslash", PackageRepositories{RubyGems: `https://gems.example.org/a\b/`}, "must not contain quotes"},
		{"whitespace", PackageRepositories{RubyGems: "https://gems.example.org/a b/"}, "package_repositories.rubygems: "},
		{"localhost", PackageRepositories{NPM: "https://localhost:4873"}, "egress proxy cannot reach"},
		{"localhost subdomain", PackageRepositories{NPM: "https://npm.localhost"}, "egress proxy cannot reach"},
		{"host gateway", PackageRepositories{NPM: "https://host.docker.internal"}, "egress proxy cannot reach"},
		{"loopback ip", PackageRepositories{NPM: "https://127.0.0.1"}, "egress proxy cannot reach"},
		{"private ip", PackageRepositories{NPM: "https://10.1.2.3"}, "egress proxy cannot reach"},
		{"link-local ip", PackageRepositories{NPM: "https://169.254.169.254"}, "egress proxy cannot reach"},
		{"unspecified ip", PackageRepositories{NPM: "https://0.0.0.0"}, "egress proxy cannot reach"},
		{"ipv6 loopback", PackageRepositories{NPM: "https://[::1]"}, "egress proxy cannot reach"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePackageRepositories(tc.p)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadPackageRepositories(t *testing.T) {
	cfg, err := Load(write(t, "package_repositories:\n  git_pkgs_proxy: https://pkgs.example.com\n  npm: https://npm.example.org/\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.PackageRepositories.Resolve()
	if got["npm"] != "https://npm.example.org/" || got["go"] != "https://pkgs.example.com/go" {
		t.Errorf("Resolve = %v", got)
	}
	if _, err := Load(write(t, "package_repositories:\n  npm: http://npm.example.org\n")); err == nil {
		t.Error("Load accepted an http package repository")
	}
}
