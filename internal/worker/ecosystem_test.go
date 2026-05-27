package worker

import "testing"

func TestNormalizeEcosystem(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		purl      string
		registry  string
		want      string
	}{
		{"explicit canonical", "rubygems", "", "", "rubygems"},
		{"explicit synonym gem", "gem", "", "", "rubygems"},
		{"explicit synonym golang", "golang", "", "", "go"},
		{"explicit case insensitive", "  NPM  ", "", "", "npm"},

		{"purl fallback gem", "", "pkg:gem/foo@1.0", "", "rubygems"},
		{"purl fallback golang", "", "pkg:golang/example.com/foo", "", "go"},
		{"purl fallback npm scoped", "", "pkg:npm/@scope/pkg@1", "", "npm"},

		{"registry fallback rubygems.org", "", "", "https://rubygems.org/gems/faker", "rubygems"},
		{"registry fallback npmjs.com", "", "", "https://www.npmjs.com/package/foo", "npm"},
		{"registry fallback pkg.go.dev", "", "", "https://pkg.go.dev/github.com/x/y", "go"},
		{"registry fallback launchpad", "", "", "https://launchpad.net/ubuntu/+source/ruby-faker", "ubuntu"},
		{"registry fallback gem.coop", "", "", "https://gem.coop/gems/foo", "rubygems"},
		{"registry fallback pypi", "", "", "https://pypi.org/project/x/", "pypi"},

		{"explicit wins over purl", "npm", "pkg:gem/foo", "", "npm"},
		{"purl wins over registry", "", "pkg:npm/foo", "https://rubygems.org/gems/foo", "npm"},

		{"unknown passes through", "exoticpkg", "", "", "exoticpkg"},
		{"all empty stays empty", "", "", "", ""},
		{"unknown registry stays empty", "", "", "https://example.com/x", ""},
		{"malformed purl ignored", "", "not-a-purl", "https://rubygems.org/gems/x", "rubygems"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeEcosystem(tc.ecosystem, tc.purl, tc.registry)
			if got != tc.want {
				t.Errorf("normalizeEcosystem(%q, %q, %q) = %q, want %q",
					tc.ecosystem, tc.purl, tc.registry, got, tc.want)
			}
		})
	}
}
