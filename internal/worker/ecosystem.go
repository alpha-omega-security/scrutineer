package worker

import "strings"

// normalizeEcosystem canonicalises the ecosystem string for a package row.
// Upstream sources (packages.ecosyste.ms, git-pkgs manifest scans) are
// inconsistent: the same logical ecosystem can arrive as "rubygems" or "gem",
// "go" or "golang", and frequently as an empty string when the upstream
// record is incomplete. The Packages tab displays this value directly and
// builds its filter dropdown from the distinct set, so any variance becomes
// visible as either empty badges or duplicate filter entries.
//
// Resolution order: the explicit field, then the PURL type segment, then a
// registry-host fallback. Synonyms collapse onto the canonical name that the
// rest of the system already uses ("rubygems", "go", "npm", …).
func normalizeEcosystem(ecosystem, purl, registryURL string) string {
	if e := canonicalEcosystem(ecosystem); e != "" {
		return e
	}
	if e := canonicalEcosystem(purlEcosystem(purl)); e != "" {
		return e
	}
	return canonicalEcosystem(registryEcosystem(registryURL))
}

// purlEcosystem returns the type segment of a Package URL: "pkg:gem/foo"
// becomes "gem". Empty string for non-PURL inputs.
func purlEcosystem(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return rest
}

// registryEcosystem maps the host of a registry URL to a canonical ecosystem
// name. Returns "" for hosts we don't recognise.
func registryEcosystem(registryURL string) string {
	if registryURL == "" {
		return ""
	}
	host := registryURL
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(strings.TrimPrefix(host, "www."))
	switch host {
	case "rubygems.org", "gem.coop":
		return "rubygems"
	case "npmjs.com", "registry.npmjs.org":
		return "npm"
	case "pypi.org":
		return "pypi"
	case "pkg.go.dev", "proxy.golang.org":
		return "go"
	case "crates.io":
		return "cargo"
	case "packagist.org":
		return "packagist"
	case "hex.pm":
		return "hex"
	case "nuget.org", "www.nuget.org":
		return "nuget"
	case "search.maven.org", "central.sonatype.com", "repo.maven.apache.org":
		return "maven"
	case "launchpad.net":
		return "ubuntu"
	}
	return ""
}

// ecosystemAliases maps known synonyms onto the canonical name used by the
// existing data set. The canonical names match what packages.ecosyste.ms
// emits when it does populate the field.
var ecosystemAliases = map[string]string{
	"gem":       "rubygems",
	"gems":      "rubygems",
	"rubygems":  "rubygems",
	"go":        "go",
	"golang":    "go",
	"npm":       "npm",
	"node":      "npm",
	"pypi":      "pypi",
	"python":    "pypi",
	"pip":       "pypi",
	"cargo":     "cargo",
	"crates":    "cargo",
	"crate":     "cargo",
	"packagist": "packagist",
	"composer":  "packagist",
	"hex":       "hex",
	"nuget":     "nuget",
	"maven":     "maven",
	"deb":       "deb",
	"ubuntu":    "ubuntu",
	"debian":    "debian",
	"apk":       "apk",
	"alpine":    "apk",
}

func canonicalEcosystem(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if c, ok := ecosystemAliases[s]; ok {
		return c
	}
	return s
}
