package config

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/alpha-omega-security/harness/egress"
)

// PackageRepositories points scan runner package managers at existing package
// repositories or caching proxies. GitPkgsProxy derives the npm, PyPI, Go, pub,
// RubyGems and Maven URLs from one git-pkgs/proxy base URL. Hex is never derived
// because the proxy strips signatures from cooldown-filtered releases. An
// explicit per-ecosystem URL wins over the derived one. URLs must be https
// and carry no credentials.
type PackageRepositories struct {
	GitPkgsProxy string `yaml:"git_pkgs_proxy"`
	NPM          string `yaml:"npm"`
	PyPI         string `yaml:"pypi"`
	Go           string `yaml:"go"`
	Pub          string `yaml:"pub"`
	Hex          string `yaml:"hex"`
	RubyGems     string `yaml:"rubygems"`
	Maven        string `yaml:"maven"`
}

// Resolve returns the repository URL per ecosystem ("npm", "pypi", "go",
// "pub", "hex", "rubygems", "maven"). Empty entries are omitted.
func (p PackageRepositories) Resolve() map[string]string {
	out := map[string]string{}
	if base := strings.TrimRight(p.GitPkgsProxy, "/"); base != "" {
		out["npm"] = base + "/npm/"
		out["pypi"] = base + "/pypi/simple/"
		out["go"] = base + "/go"
		out["pub"] = base + "/pub"
		out["rubygems"] = base + "/gem/"
		out["maven"] = base + "/maven/"
	}
	for eco, v := range map[string]string{"npm": p.NPM, "pypi": p.PyPI, "go": p.Go, "pub": p.Pub, "hex": p.Hex, "rubygems": p.RubyGems, "maven": p.Maven} {
		if v != "" {
			out[eco] = v
		}
	}
	return out
}

// Hosts returns the sorted, deduplicated lowercase hostnames of every
// resolved repository URL.
func (p PackageRepositories) Hosts() []string {
	return p.collectHosts(false)
}

// HostPorts returns the sorted, deduplicated lowercase host:port pairs of
// every resolved repository URL, with 443 when the URL has no port. These are
// the grants a --hardened egress policy needs.
func (p PackageRepositories) HostPorts() []string {
	return p.collectHosts(true)
}

func (p PackageRepositories) collectHosts(withPort bool) []string {
	var hosts []string
	for _, raw := range p.Resolve() {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if withPort {
			port := u.Port()
			if port == "" {
				port = "443"
			}
			host = net.JoinHostPort(host, port)
		}
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}

// ValidatePackageRepositories checks every configured URL. Scan containers
// reach repositories through the egress proxy, which denies loopback and
// private addresses, so URLs that could never work are rejected up front.
func ValidatePackageRepositories(p PackageRepositories) error {
	for _, f := range []struct{ key, val string }{
		{"git_pkgs_proxy", p.GitPkgsProxy},
		{"npm", p.NPM},
		{"pypi", p.PyPI},
		{"go", p.Go},
		{"pub", p.Pub},
		{"hex", p.Hex},
		{"rubygems", p.RubyGems},
		{"maven", p.Maven},
	} {
		if f.val == "" {
			continue
		}
		if err := validatePackageRepositoryURL(f.val); err != nil {
			return fmt.Errorf("package_repositories.%s: %w", f.key, err)
		}
	}
	return nil
}

func validatePackageRepositoryURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if !u.IsAbs() || !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("must be an absolute https URL")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("must include a host")
	}
	if u.User != nil {
		return fmt.Errorf("credentials are not supported in the URL, keep them out of the config file")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("must not include a query string")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("must not include a fragment")
	}
	if strings.ContainsAny(raw, ",|") {
		return fmt.Errorf("must not contain ',' or '|', which GOPROXY reads as list separators")
	}
	// Bundler versions disagree on escapes in their config file, so the URL is
	// written there verbatim and must not need any.
	if strings.ContainsAny(raw, "\"\\") || strings.ContainsFunc(raw, unicode.IsSpace) {
		return fmt.Errorf("must not contain quotes, backslashes or whitespace, percent-encode them")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || host == egress.HostGatewayAlias {
		return fmt.Errorf("host %q is a local address the scan egress proxy cannot reach", host)
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()) {
		return fmt.Errorf("host %q is a loopback, private or link-local address the scan egress proxy cannot reach", host)
	}
	return nil
}
