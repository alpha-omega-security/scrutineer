package worker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestProfileByName(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		isKnown bool
		isNamed bool
	}{
		{"", "", true, false},
		{"default", "", true, false},
		{"unknown", "", false, false},
	}
	// Every registered profile resolves to itself and is known/named.
	// Deriving these from builtinProfiles keeps this table out of the
	// conflict path when a profile is added.
	for _, p := range builtinProfiles {
		tests = append(tests, struct {
			name    string
			want    string
			isKnown bool
			isNamed bool
		}{p.Name, p.Name, true, true})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProfileByName(tt.name)
			if got.Name != tt.want {
				t.Errorf("ProfileByName(%q).Name = %q, want %q", tt.name, got.Name, tt.want)
			}
			if KnownProfile(tt.name) != tt.isKnown {
				t.Errorf("KnownProfile(%q) = %v, want %v", tt.name, !tt.isKnown, tt.isKnown)
			}
			if IsNamedProfile(tt.name) != tt.isNamed {
				t.Errorf("IsNamedProfile(%q) = %v, want %v", tt.name, !tt.isNamed, tt.isNamed)
			}
		})
	}
}

// briefJSON builds a minimal brief output for TestMatchProfile. Each entry
// is "category:name"; briefPackageManager and briefLanguage go into the
// top-level arrays, everything else under tools[category].
func briefJSON(entries ...string) string {
	type det struct {
		Name string `json:"name"`
	}
	var out struct {
		PackageManagers []det            `json:"package_managers"`
		Languages       []det            `json:"languages"`
		Tools           map[string][]det `json:"tools"`
	}
	out.Tools = map[string][]det{}
	for _, e := range entries {
		cat, name, _ := strings.Cut(e, ":")
		switch cat {
		case briefPackageManager:
			out.PackageManagers = append(out.PackageManagers, det{name})
		case briefLanguage:
			out.Languages = append(out.Languages, det{name})
		default:
			out.Tools[cat] = append(out.Tools[cat], det{name})
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestMatchProfile(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		// package_manager routes
		{"composer matches php", briefJSON("package_manager:Composer"), "php"},
		{"composer case-insensitive", briefJSON("package_manager:composer"), "php"},
		{"bundler matches ruby", briefJSON("package_manager:Bundler"), "ruby"},
		{"bundler case-insensitive", briefJSON("package_manager:bundler"), "ruby"},
		{"npm matches node", briefJSON("package_manager:npm"), "node"},
		{"pnpm matches node", briefJSON("package_manager:pnpm"), "node"},
		{"yarn matches node", briefJSON("package_manager:Yarn"), "node"},
		{"bun matches node", briefJSON("package_manager:Bun"), "node"},
		{"npm case-insensitive", briefJSON("package_manager:NPM"), "node"},
		{"pip matches python", briefJSON("package_manager:pip"), "python"},
		{"poetry matches python", briefJSON("package_manager:Poetry"), "python"},
		{"uv matches python case-insensitive", briefJSON("package_manager:UV"), "python"},
		{"pdm matches python", briefJSON("package_manager:PDM"), "python"},
		{"setuptools matches python", briefJSON("package_manager:setuptools"), "python"},
		{"go modules matches go", briefJSON("package_manager:Go Modules"), "go"},
		{"go modules case-insensitive", briefJSON("package_manager:go modules"), "go"},
		{"maven matches java", briefJSON("package_manager:Maven"), "java"},
		{"gradle matches java", briefJSON("package_manager:Gradle"), "java"},
		{"gradle case-insensitive", briefJSON("package_manager:gradle"), "java"},
		{"nuget matches dotnet", briefJSON("package_manager:NuGet"), "dotnet"},
		{"dotnet CLI matches dotnet", briefJSON("package_manager:dotnet CLI"), "dotnet"},
		{"nuget case-insensitive", briefJSON("package_manager:nuget"), "dotnet"},
		{"mix matches beam", briefJSON("package_manager:Mix"), "beam"},
		{"rebar3 matches beam", briefJSON("package_manager:rebar3"), "beam"},
		{"mix case-insensitive", briefJSON("package_manager:mix"), "beam"},
		{"cargo matches rust", briefJSON("package_manager:Cargo"), "rust"},
		{"SwiftPM matches swift", briefJSON("package_manager:Swift Package Manager"), "swift"},
		{"cpanm matches perl", briefJSON("package_manager:cpanm"), "perl"},

		// registry order: first match in builtinProfiles wins, not brief order
		{"composer + bundler picks php (registry order)", briefJSON("package_manager:Composer", "package_manager:Bundler"), "php"},
		{"bundler + composer still picks php (registry order, not brief order)", briefJSON("package_manager:Bundler", "package_manager:Composer"), "php"},
		{"composer before node when both present", briefJSON("package_manager:npm", "package_manager:Composer"), "php"},

		// native_extension category (from brief v0.9.3)
		{"phpize selects php-ext", briefJSON("native_extension:phpize"), "php-ext"},
		{"phpize wins over composer (registry order)", briefJSON("package_manager:Composer", "native_extension:phpize"), "php-ext"},
		{"mkmf selects ruby-ext", briefJSON("native_extension:mkmf"), "ruby-ext"},
		{"mkmf wins over bundler (registry order)", briefJSON("package_manager:Bundler", "native_extension:mkmf"), "ruby-ext"},
		{"setuptools Extension selects python-ext", briefJSON("native_extension:setuptools Extension"), "python-ext"},
		{"setuptools Extension wins over pip", briefJSON("package_manager:pip", "native_extension:setuptools Extension"), "python-ext"},
		{"setuptools Extension case-insensitive", briefJSON("native_extension:SETUPTOOLS EXTENSION"), "python-ext"},
		// node-gyp is detected by brief but there is no node-ext profile yet;
		// falls through to node via the package manager.
		{"node-gyp with npm falls through to node", briefJSON("package_manager:npm", "native_extension:node-gyp"), "node"},

		// build category
		{"Rails selects ruby-rails", briefJSON("package_manager:Bundler", "build:Rails"), "ruby-rails"},
		{"Rails without bundler still selects ruby-rails", briefJSON("build:Rails"), "ruby-rails"},
		{
			// A Rails app that also ships a native extension matches both
			// ruby-rails and ruby-ext; ruby-ext wins on registry order, and
			// since ruby-ext also carries Brakeman (a superset of ruby-rails)
			// that no longer drops Rails SAST.
			"ruby-ext beats ruby-rails when both match (registry order)",
			briefJSON("package_manager:Bundler", "build:Rails", "native_extension:mkmf"),
			"ruby-ext",
		},
		{"Rake alone does not select ruby-rails", briefJSON("package_manager:Bundler", "build:Rake"), "ruby"},
		{"CMake selects c-cpp", briefJSON("build:CMake"), "c-cpp"},
		{"Make selects c-cpp", briefJSON("build:Make"), "c-cpp"},
		{"Autotools selects c-cpp", briefJSON("build:Autotools"), "c-cpp"},
		{"Meson selects c-cpp", briefJSON("build:Meson"), "c-cpp"},

		// language fallbacks
		{"Perl language matches perl (belt-and-braces for a *.pl-only dist)", briefJSON("language:Perl"), "perl"},
		{"C language matches c-cpp", briefJSON("language:C"), "c-cpp"},
		{"C++ language matches c-cpp", briefJSON("language:C++"), "c-cpp"},
		{"Swift language matches swift (Xcode-project-only checkout)", briefJSON("language:Swift"), "swift"},
		{
			// A Swift package that vendors C sources or a Makefile must
			// still route to swift, not c-cpp.
			"SwiftPM + Make + C picks swift over c-cpp",
			briefJSON("package_manager:Swift Package Manager", "build:Make", "language:C"),
			"swift",
		},
		{
			// A CPAN dist that also commits a generated Makefile must still
			// route to perl, not c-cpp: registry order and the cpanm/Perl
			// selectors both come first.
			"cpanm + Make picks perl over c-cpp (registry order)",
			briefJSON("package_manager:cpanm", "language:Perl", "build:Make"),
			"perl",
		},
		{
			// A Bundler repo that also has a Makefile (common for gem
			// build tasks) must not fall through to c-cpp.
			"bundler + Make picks ruby over c-cpp",
			briefJSON("package_manager:Bundler", "build:Make", "language:Ruby"),
			"ruby",
		},

		// no-match cases
		{"unknown ecosystem falls back to default", briefJSON("package_manager:CocoaPods"), ""},
		{"empty brief output falls back to default", briefJSON(), ""},
		{"unrelated tool category is ignored", briefJSON("test:RSpec"), ""},

		// malformed / degraded input
		{"invalid json is tolerated", `not json`, ""},
		{"null package_managers is tolerated (perl via language)", `{"package_managers":null,"languages":[{"name":"Perl"}]}`, "perl"},
		{"null tools is tolerated", `{"package_managers":[{"name":"Bundler"}],"tools":null}`, "ruby"},
		{"nil brief output falls back to default", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchProfile([]byte(tt.json))
			if got.Name != tt.want {
				t.Errorf("matchProfile = %q, want %q (json=%s)", got.Name, tt.want, tt.json)
			}
		})
	}
}

// TestMatchProfile_everyProfileReachable derives one positive case per
// registered profile from its own Detect entry, so a new profile is
// exercised without a hand-added table row.
func TestMatchProfile_everyProfileReachable(t *testing.T) {
	for _, p := range builtinProfiles {
		if len(p.Detect) == 0 || len(p.Detect[0].Names) == 0 {
			t.Fatalf("profile %q has empty Detect (registrySanity should have caught this)", p.Name)
		}
		d := p.Detect[0]
		got := matchProfile([]byte(briefJSON(d.Category + ":" + d.Names[0])))
		// The match may be a more-specific earlier profile (e.g. asking for
		// package_manager:Bundler when ruby-ext precedes ruby is impossible
		// since ruby-ext keys on native_extension), so this asserts the
		// input reaches p or something before it, never the default.
		if got.Name == "" {
			t.Errorf("profile %q: %s:%s matched nothing", p.Name, d.Category, d.Names[0])
		}
	}
}

func TestImageTag_contentAddressed(t *testing.T) {
	df := []byte("FROM x\nRUN echo a\n")
	a := imageTag("php", df, "runner:1", "sha256:aaa")
	b := imageTag("php", df, "runner:1", "sha256:aaa")
	c := imageTag("php", []byte("FROM x\nRUN echo b\n"), "runner:1", "sha256:aaa")
	d := imageTag("php", df, "runner:2", "sha256:aaa")
	moved := imageTag("php", df, "runner:1", "sha256:bbb")
	unresolved := imageTag("php", df, "runner:1", "")

	if a != b {
		t.Errorf("same contents, runner, and digest should yield same tag: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different contents should yield different tag, both %q", a)
	}
	if a == d {
		t.Errorf("different runner image should yield different tag, both %q", a)
	}
	// The runner ref is unchanged (still runner:1) but its resolved base
	// digest moved, so the tag must change and force a rebuild.
	if a == moved {
		t.Errorf("a moved base digest under the same ref should yield a different tag, both %q", a)
	}
	// An unresolved digest falls back to keying on the ref alone, which must
	// not collide with the resolved tag.
	if a == unresolved {
		t.Errorf("resolved digest should differ from the unresolved fallback, both %q", a)
	}
	if !strings.HasPrefix(a, "scrutineer-profile-php:") {
		t.Errorf("tag %q does not have expected prefix", a)
	}
}

func TestResolveBaseDigest_fallsBackToEmpty(t *testing.T) {
	// An empty ref short-circuits without shelling out to the runtime.
	if got := resolveBaseDigest(context.Background(), ContainerRuntime{}, ""); got != "" {
		t.Errorf("empty ref: got %q, want empty", got)
	}
	// A cancelled context aborts the runtime call before it runs, standing in
	// for any resolution failure (offline, local-only ref, buildx missing);
	// the function must fall back to "" so imageTag keys on the ref alone.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := resolveBaseDigest(ctx, ContainerRuntime{}, "ghcr.io/example/runner:latest"); got != "" {
		t.Errorf("cancelled ctx: got %q, want empty", got)
	}
}

func TestLockForTag_sameTagSameMutex(t *testing.T) {
	a := lockForTag("scrutineer-profile-test:abc")
	b := lockForTag("scrutineer-profile-test:abc")
	c := lockForTag("scrutineer-profile-test:xyz")

	if a != b {
		t.Errorf("same tag must yield same mutex")
	}
	if a == c {
		t.Errorf("different tag must yield distinct mutex")
	}
}

func TestEnsureImage_defaultReturnsRunnerImage(t *testing.T) {
	var emitted int
	img, err := Profile{}.EnsureImage(context.Background(), ContainerRuntime{}, "", "default-runner:latest", func(Event) { emitted++ })
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}
	if img != "default-runner:latest" {
		t.Errorf("got %q, want default runner image", img)
	}
	if emitted != 0 {
		t.Errorf("default profile emitted %d events, want 0", emitted)
	}
}

func TestEnsureImage_noProfilesDir(t *testing.T) {
	var emitted int
	_, err := Profile{Name: "php"}.EnsureImage(context.Background(), ContainerRuntime{}, "", "default:latest", func(Event) { emitted++ })
	if err == nil {
		t.Fatal("expected ErrNoProfilesDir, got nil")
	}
	if emitted != 0 {
		t.Errorf("ErrNoProfilesDir path emitted %d events, want 0", emitted)
	}
}

func TestEnsureImage_missingDockerfile(t *testing.T) {
	dir := t.TempDir()
	var emitted int
	_, err := Profile{Name: "php"}.EnsureImage(context.Background(), ContainerRuntime{}, dir, "default:latest", func(Event) { emitted++ })
	if err == nil {
		t.Fatal("expected error for missing dockerfile, got nil")
	}
	if emitted != 0 {
		t.Errorf("missing-dockerfile path emitted %d events, want 0", emitted)
	}
}

func TestEnsureImage_unknownBaseProfile(t *testing.T) {
	dir := t.TempDir()
	var emitted int
	// A BaseProfile that names no registered profile is a registry bug, not a
	// runtime one: EnsureImage errors out before touching the runtime (there is
	// no base image to build FROM). TestBuiltinProfiles_registrySanity guards
	// the real registry against this; here we lock the runtime behaviour.
	_, err := Profile{Name: "ruby-rails", BaseProfile: "nope"}.EnsureImage(
		context.Background(), ContainerRuntime{}, dir, "runner:latest", func(Event) { emitted++ })
	if err == nil {
		t.Fatal("expected error for unknown base profile, got nil")
	}
	if !strings.Contains(err.Error(), "unknown base profile") {
		t.Errorf("error = %v, want it to mention the unknown base profile", err)
	}
	if emitted != 0 {
		t.Errorf("unknown-base path emitted %d events, want 0", emitted)
	}
}

// TestBuiltinProfiles_registrySanity guards the invariants matchProfile
// and the validators rely on: every entry has a Name and a non-empty
// Detect (an empty Detect would never match, making the profile dead
// code), Names are unique, and no (category, name) selector appears in
// two profiles where the later one could never win. BaseProfile /
// FallbackProfile chains must resolve and be acyclic.
func TestBuiltinProfiles_registrySanity(t *testing.T) {
	names := map[string]bool{}
	for _, p := range builtinProfiles {
		if p.Name == "" {
			t.Error("profile with empty Name")
		}
		if len(p.Detect) == 0 {
			t.Errorf("profile %q has empty Detect", p.Name)
		}
		if names[p.Name] {
			t.Errorf("duplicate profile Name %q", p.Name)
		}
		names[p.Name] = true
	}
	assertProfileSelectorsUnique(t)
	// Every BaseProfile must name another registered profile, so the FROM
	// chain in EnsureImage resolves; a typo would otherwise silently build
	// FROM the runner via ProfileByName's default fallback.
	for _, p := range builtinProfiles {
		if p.BaseProfile == "" {
			continue
		}
		if p.BaseProfile == p.Name {
			t.Errorf("profile %q lists itself as BaseProfile", p.Name)
		}
		if !names[p.BaseProfile] {
			t.Errorf("profile %q has unknown BaseProfile %q", p.Name, p.BaseProfile)
		}
	}
	// Every FallbackProfile must name another registered profile, so the
	// degrade chain in resolveProfile resolves instead of silently dropping to
	// the guide-less default runner.
	for _, p := range builtinProfiles {
		if p.FallbackProfile == "" {
			continue
		}
		if p.FallbackProfile == p.Name {
			t.Errorf("profile %q lists itself as FallbackProfile", p.Name)
		}
		if !names[p.FallbackProfile] {
			t.Errorf("profile %q has unknown FallbackProfile %q", p.Name, p.FallbackProfile)
		}
	}
	// Neither chain may cycle. The self-checks above catch the direct A->A case;
	// assertProfileChainAcyclic walks the whole chain so a multi-hop A->B->A can't
	// slip through.
	assertProfileChainAcyclic(t, "BaseProfile", func(p Profile) string { return p.BaseProfile })
	assertProfileChainAcyclic(t, "FallbackProfile", func(p Profile) string { return p.FallbackProfile })
}

// assertProfileSelectorsUnique checks every BriefMatch is well-formed and no
// (category, name) selector is claimed by more than one profile: a later
// profile listing a selector an earlier one already owns can never win on
// that selector alone (first-match-wins), so a duplicate is either a typo or
// dead code. Kept out of TestBuiltinProfiles_registrySanity so its cognitive
// complexity stays under the linter's cap.
func assertProfileSelectorsUnique(t *testing.T) {
	t.Helper()
	selectors := map[[2]string]string{}
	for _, p := range builtinProfiles {
		for _, m := range p.Detect {
			if m.Category == "" || len(m.Names) == 0 {
				t.Errorf("profile %q has a BriefMatch with empty Category or Names", p.Name)
			}
			for _, n := range m.Names {
				key := [2]string{m.Category, strings.ToLower(n)}
				if prev, ok := selectors[key]; ok {
					t.Errorf("profile %q: selector %s:%s already claimed by %q (later profile unreachable via this selector)", p.Name, m.Category, n, prev)
				}
				selectors[key] = p.Name
			}
		}
	}
}

// assertProfileChainAcyclic walks the chain reached by next() from every
// registered profile and fails if a name repeats. A FallbackProfile cycle would
// spin resolveProfile's degrade loop (which also breaks on a repeat at runtime)
// and a BaseProfile cycle would recurse EnsureImage into a stack overflow, so an
// acyclic registry is the invariant both rely on. Kept out of the registry
// sanity test body so its cognitive complexity stays under the linter's cap.
func assertProfileChainAcyclic(t *testing.T, kind string, next func(Profile) string) {
	t.Helper()
	for _, start := range builtinProfiles {
		seen := map[string]bool{start.Name: true}
		for cur := start; next(cur) != ""; {
			n := next(cur)
			if seen[n] {
				t.Errorf("profile %q: %s chain cycles at %q", start.Name, kind, n)
				break
			}
			seen[n] = true
			cur = ProfileByName(n)
		}
	}
}

func TestRepoShipsProfileDockerfiles(t *testing.T) {
	wd, _ := os.Getwd()
	repoRoot := filepath.Join(wd, "..", "..")
	for _, p := range builtinProfiles {
		path := filepath.Join(repoRoot, "docker", "profiles", p.Name, "Dockerfile")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s profile Dockerfile to exist: %v", p.Name, err)
		}
	}
}

// TestProfileGuidesShip keeps the language profiles honest about the
// per-container PROFILE.md they advertise. The runtime treats PROFILE.md
// as optional (a profile without one simply gets no orientation injected
// at scan time), but every shipped profile documents specifics the agent
// needs to behave correctly, so the test requires one per registered
// profile. Iterating builtinProfiles rather than a hand-kept list keeps
// this test out of the conflict path when a profile is added.
func TestProfileGuidesShip(t *testing.T) {
	wd, _ := os.Getwd()
	repoRoot := filepath.Join(wd, "..", "..")
	for _, p := range builtinProfiles {
		guide := filepath.Join(repoRoot, "docker", "profiles", p.Name, "PROFILE.md")
		if _, err := os.Stat(guide); err != nil {
			t.Errorf("expected %s profile PROFILE.md to exist: %v", p.Name, err)
		}
	}
}

// TestProfileBuildArgs pins the runner-vs-chained build-arg wiring EnsureImage
// relies on, without a container runtime: a runner profile --pull's (only with
// a resolved digest) and passes RUNNER_IMAGE; a chained profile passes
// BASE_IMAGE (the base tag), never RUNNER_IMAGE, and never --pull's a
// locally-built base.
func TestProfileBuildArgs(t *testing.T) {
	join := func(a []string) string { return strings.Join(a, " ") }
	runner := Profile{Name: "ruby"}
	chained := Profile{Name: "ruby-rails", BaseProfile: "ruby"}

	a := join(profileBuildArgs(runner, "tag:1", "df", "ctx", "runner:latest", "deadbeef"))
	if !strings.Contains(a, "--pull") || !strings.Contains(a, "--build-arg RUNNER_IMAGE=runner:latest") {
		t.Errorf("runner+digest should --pull and pass RUNNER_IMAGE: %s", a)
	}
	b := join(profileBuildArgs(runner, "tag:1", "df", "ctx", "runner:latest", ""))
	if strings.Contains(b, "--pull") {
		t.Errorf("runner without a resolved digest must not --pull: %s", b)
	}
	c := join(profileBuildArgs(chained, "tag:2", "df", "ctx", "scrutineer-profile-ruby:abc", ""))
	if strings.Contains(c, "--pull") {
		t.Errorf("chained must not --pull a local base: %s", c)
	}
	if !strings.Contains(c, "--build-arg BASE_IMAGE=scrutineer-profile-ruby:abc") {
		t.Errorf("chained should pass BASE_IMAGE: %s", c)
	}
	if strings.Contains(c, "RUNNER_IMAGE=") {
		t.Errorf("chained must not pass RUNNER_IMAGE: %s", c)
	}
}

// TestBrakemanVersionParity keeps ruby-ext's Brakeman pin in lockstep with
// ruby-rails's. ruby-ext installs Brakeman too (it precedes ruby-rails in
// detection and must stay a superset), so the two ARG pins are the one bit of
// duplication the FROM-chain leaves; this catches silent drift.
func TestBrakemanVersionParity(t *testing.T) {
	wd, _ := os.Getwd()
	repoRoot := filepath.Join(wd, "..", "..")
	rails := brakemanVersion(t, filepath.Join(repoRoot, "docker", "profiles", "ruby-rails", "Dockerfile"))
	ext := brakemanVersion(t, filepath.Join(repoRoot, "docker", "profiles", "ruby-ext", "Dockerfile"))
	if rails == "" || ext == "" {
		t.Fatalf("BRAKEMAN_VERSION pin not found: ruby-rails=%q ruby-ext=%q", rails, ext)
	}
	if rails != ext {
		t.Errorf("BRAKEMAN_VERSION drift: ruby-rails=%q ruby-ext=%q (keep them in lockstep)", rails, ext)
	}
}

func brakemanVersion(t *testing.T, dockerfile string) string {
	t.Helper()
	b, err := os.ReadFile(dockerfile)
	if err != nil {
		t.Fatalf("read %s: %v", dockerfile, err)
	}
	m := regexp.MustCompile(`(?m)^ARG BRAKEMAN_VERSION=(\S+)`).FindSubmatch(b)
	if m == nil {
		return ""
	}
	return string(m[1])
}
