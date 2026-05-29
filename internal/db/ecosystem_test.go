package db

import "testing"

func TestEcosystemType(t *testing.T) {
	cases := []struct {
		name, purl, eco, want string
	}{
		// PURL present: the parsed type wins, even over a conflicting string.
		{"purl gem", "pkg:gem/foo@1.0", "", "gem"},
		{"purl golang", "pkg:golang/github.com/x/y@v1", "go", "golang"},
		{"purl npm scoped", "pkg:npm/@scope/pkg@1", "", "npm"},
		{"purl wins over ecosystem", "pkg:gem/foo", "npm", "gem"},

		// No PURL: the ecosystem string normalised to its PURL type.
		{"eco rubygems", "", "rubygems", "gem"},
		{"eco gem", "", "gem", "gem"},
		{"eco go", "", "go", "golang"},
		{"eco golang", "", "golang", "golang"},
		{"eco composer", "", "composer", "composer"},
		{"eco packagist", "", "packagist", "composer"},
		{"eco npm uppercase", "", "NPM", "npm"},

		// Residual alias: the two source vocabularies converge on one type.
		{"eco github-actions", "", "github-actions", "githubactions"},
		{"eco actions", "", "actions", "githubactions"},
		{"eco brew", "", "brew", "brew"},
		{"eco homebrew", "", "homebrew", "brew"},
		{"eco swift", "", "swift", "swift"},
		{"eco swiftpm", "", "swiftpm", "swift"},
		{"eco nix", "", "nix", "nix"},
		{"eco nixpkgs", "", "nixpkgs", "nix"},

		// Unhappy paths.
		{"invalid purl falls back to eco", "not-a-purl", "npm", "npm"},
		{"empty purl and eco", "", "", ""},
		{"unknown ecosystem passes through", "", "exoticpkg", "exoticpkg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EcosystemType(tc.purl, tc.eco); got != tc.want {
				t.Errorf("EcosystemType(%q, %q) = %q, want %q", tc.purl, tc.eco, got, tc.want)
			}
		})
	}
}

// TestEcosystemKeyReconcilesSources guards the DependencyFindings join: it
// matches a Dependency row to a Package row by the key ecosystemKey produces.
// git-pkgs (Dependency) and ecosyste.ms (Package) spell some ecosystems
// differently, so without a PURL the key must still collapse both spellings
// onto the same value: otherwise the join silently drops these libraries.
func TestEcosystemKeyReconcilesSources(t *testing.T) {
	cases := []struct{ name, gitPkgs, ecosystems string }{
		{"rubygems", "gem", "rubygems"},
		{"go", "golang", "go"},
		{"packagist", "composer", "packagist"},
		{"github actions", "github-actions", "actions"},
		{"homebrew", "brew", "homebrew"},
		{"swift", "swift", "swiftpm"},
		{"nix", "nix", "nixpkgs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			depEco, _, _ := ecosystemKey("", tc.gitPkgs, "pkg")
			pkgEco, _, _ := ecosystemKey("", tc.ecosystems, "pkg")
			if depEco != pkgEco {
				t.Errorf("git-pkgs %q and ecosyste.ms %q produce divergent keys %q vs %q",
					tc.gitPkgs, tc.ecosystems, depEco, pkgEco)
			}
		})
	}
}

// TestEcosystemKeyPURL checks the namespace/name split used by the join when a
// PURL is present on both sides.
func TestEcosystemKeyPURL(t *testing.T) {
	eco, ns, name := ecosystemKey("pkg:golang/github.com/gorilla/mux@v1.8.0", "go", "github.com/gorilla/mux")
	if eco != "golang" || ns != "github.com/gorilla" || name != "mux" {
		t.Errorf("got (%q, %q, %q), want (golang, github.com/gorilla, mux)", eco, ns, name)
	}
}

// TestDependencyFindingsPURLJoin exercises the primary path end to end: a
// Dependency and a Package both carrying a namespaced golang PURL join through
// the parsed PURL, and it guards the packages.p_url column→field mapping.
func TestDependencyFindingsPURLJoin(t *testing.T) {
	gdb, err := Open("file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	sqldb, _ := gdb.DB()
	defer func() { _ = sqldb.Close() }()

	app := Repository{URL: "https://example.com/app", Name: "app"}
	lib := Repository{URL: "https://example.com/mux", Name: "mux"}
	gdb.Create(&app)
	gdb.Create(&lib)

	const muxPURL = "pkg:golang/github.com/gorilla/mux@v1.8.0"
	gdb.Create(&Dependency{RepositoryID: app.ID, Name: "github.com/gorilla/mux", Ecosystem: "go", PURL: muxPURL, ManifestPath: "go.mod", DependencyType: "runtime"})
	gdb.Create(&Package{RepositoryID: lib.ID, Name: "github.com/gorilla/mux", Ecosystem: "go", PURL: muxPURL})

	scan := Scan{RepositoryID: lib.ID, Kind: "skill", Status: ScanDone}
	gdb.Create(&scan)
	gdb.Create(&Finding{ScanID: scan.ID, RepositoryID: lib.ID, Title: "path traversal", Severity: "High", Status: FindingNew})

	rows, err := DependencyFindings(gdb, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%d want=1 (namespaced PURL join): %+v", len(rows), rows)
	}
	if rows[0].Title != "path traversal" || rows[0].LibRepoURL != "https://example.com/mux" {
		t.Errorf("unexpected row %+v", rows[0])
	}
}

// TestEcosystemKeyFallbackMatchesPURL guards the mixed-source join: a package
// recorded with a PURL on one source and only an ecosystem string on the other
// must still produce the same (type, namespace, name) key. The no-PURL fallback
// must reconstruct the namespace split and case-folding exactly as parsing the
// real PURL would: for the raw ecosyste.ms "actions" spelling, for the
// canonical "githubactions" type the parser actually stores, and for a
// mixed-case golang path that purl.Parse lowercases.
func TestEcosystemKeyFallbackMatchesPURL(t *testing.T) {
	cases := []struct{ name, eco, pkgName, purlStr string }{
		{"golang", "go", "github.com/gorilla/mux", "pkg:golang/github.com/gorilla/mux@v1.8.0"},
		{"golang mixed case", "go", "github.com/Sirupsen/logrus", "pkg:golang/github.com/Sirupsen/logrus@v1.0.0"},
		{"npm scoped", "npm", "@scope/pkg", "pkg:npm/@scope/pkg@1.0.0"},
		{"composer", "composer", "monolog/monolog", "pkg:composer/monolog/monolog@3.0.0"},
		{"github actions raw eco", "actions", "actions/checkout", "pkg:githubactions/actions/checkout@v4"},
		{"github actions stored type", "githubactions", "actions/checkout", "pkg:githubactions/actions/checkout@v4"},
		{"swift stored type", "swift", "github.com/apple/swift-nio", "pkg:swift/github.com/apple/swift-nio@2.0.0"},
		{"swift raw eco", "swiftpm", "github.com/apple/swift-nio", "pkg:swift/github.com/apple/swift-nio@2.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			we, wn, wp := ecosystemKey(tc.purlStr, "", "")
			ge, gn, gp := ecosystemKey("", tc.eco, tc.pkgName)
			if we != ge || wn != gn || wp != gp {
				t.Errorf("fallback (%q,%q,%q) != parsed PURL (%q,%q,%q)", ge, gn, gp, we, wn, wp)
			}
		})
	}
}

// TestEcosystemKeyReconcilesPURLTypeSpellings guards issue #256's primary path
// (both sources carry a PURL) when the two vocabularies spell the PURL type
// differently: ecosyste.ms's "pkg:swiftpm/..."/"pkg:actions/..." must reduce to
// the same key as git-pkgs's "pkg:swift/..."/"pkg:githubactions/...".
func TestEcosystemKeyReconcilesPURLTypeSpellings(t *testing.T) {
	cases := []struct{ name, ecosystemsPURL, gitPkgsPURL string }{
		{"homebrew", "pkg:homebrew/openssl@3.0", "pkg:brew/openssl@3.0"},
		{"github actions", "pkg:actions/actions/checkout@v4", "pkg:githubactions/actions/checkout@v4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ee, en, ep := ecosystemKey(tc.ecosystemsPURL, "", "")
			ge, gn, gp := ecosystemKey(tc.gitPkgsPURL, "", "")
			if ee != ge || en != gn || ep != gp {
				t.Errorf("ecosyste.ms (%q,%q,%q) != git-pkgs (%q,%q,%q)", ee, en, ep, ge, gn, gp)
			}
		})
	}
}

// TestDependencyFindingsMixedPURL covers the case issue #255 documents: a
// namespaced package recorded with a PURL on one source and without one on the
// other (model-authored rows omit it) must still join, in either direction. The
// rows are seeded the way the parsers store them: Ecosystem set via
// EcosystemType, so a github-actions row carries the canonical "githubactions"
// type, the value the join must reconcile back to a splittable spelling.
func TestDependencyFindingsMixedPURL(t *testing.T) {
	// seed creates a dep and a package for the same library, each row's
	// Ecosystem derived from its (purl, rawEco) the way the parsers do.
	seed := func(t *testing.T, name, depRawEco, depPURL, pkgRawEco, pkgPURL string) int {
		t.Helper()
		gdb, err := Open("file::memory:")
		if err != nil {
			t.Fatal(err)
		}
		sqldb, _ := gdb.DB()
		defer func() { _ = sqldb.Close() }()

		app := Repository{URL: "https://example.com/app", Name: "app"}
		lib := Repository{URL: "https://example.com/lib", Name: "lib"}
		gdb.Create(&app)
		gdb.Create(&lib)

		gdb.Create(&Dependency{RepositoryID: app.ID, Name: name, Ecosystem: EcosystemType(depPURL, depRawEco), PURL: depPURL, ManifestPath: "m", DependencyType: "runtime"})
		gdb.Create(&Package{RepositoryID: lib.ID, Name: name, Ecosystem: EcosystemType(pkgPURL, pkgRawEco), PURL: pkgPURL})

		scan := Scan{RepositoryID: lib.ID, Kind: "skill", Status: ScanDone}
		gdb.Create(&scan)
		gdb.Create(&Finding{ScanID: scan.ID, RepositoryID: lib.ID, Title: "x", Severity: "High", Status: FindingNew})

		rows, err := DependencyFindings(gdb, app.ID)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}

	cases := []struct{ name, pkgName, gitPkgsEco, ecosystemsEco, purl string }{
		{"golang", "github.com/gorilla/mux", "go", "go", "pkg:golang/github.com/gorilla/mux@v1.8.0"},
		{"npm scoped", "@scope/pkg", "npm", "npm", "pkg:npm/@scope/pkg@1.0.0"},
		{"composer", "monolog/monolog", "composer", "packagist", "pkg:composer/monolog/monolog@3.0.0"},
		{"github actions", "actions/checkout", "github-actions", "actions", "pkg:githubactions/actions/checkout@v4"},
		{"swift", "github.com/apple/swift-nio", "swift", "swiftpm", "pkg:swift/github.com/apple/swift-nio@2.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// git-pkgs dependency carries the PURL, ecosyste.ms package omits it.
			if n := seed(t, tc.pkgName, tc.gitPkgsEco, tc.purl, tc.ecosystemsEco, ""); n != 1 {
				t.Errorf("dependency has PURL, package does not: rows=%d want=1", n)
			}
			// ...and the reverse.
			if n := seed(t, tc.pkgName, tc.gitPkgsEco, "", tc.ecosystemsEco, tc.purl); n != 1 {
				t.Errorf("package has PURL, dependency does not: rows=%d want=1", n)
			}
		})
	}
}
