package worker

import (
	"context"
	"fmt"
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

const configM4Body = `dnl Minimal extension config
PHP_ARG_ENABLE([example], [whether to enable example], [--enable-example])
if test "$PHP_EXAMPLE" != "no"; then
  PHP_NEW_EXTENSION(example, example.c, $ext_shared)
fi
`

const configM4WithoutPHPArg = `dnl just a stray autoconf file
AC_INIT([thing], [1.0])
`

func writeConfigM4(t *testing.T, dir, contents string) {
	t.Helper()
	const configM4FileMode = 0o644
	path := filepath.Join(dir, "config.m4")
	if err := os.WriteFile(path, []byte(contents), configM4FileMode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const setupPyWithExtension = `from setuptools import setup, Extension
setup(ext_modules=[Extension("pkg._speedups", ["src/speedups.c"])])
`

const setupPyPurePython = `from setuptools import setup
setup(name="pkg", version="1.0", packages=["pkg"])
`

func writeSetupPy(t *testing.T, dir, contents string) {
	t.Helper()
	const setupPyFileMode = 0o644
	path := filepath.Join(dir, "setup.py")
	if err := os.WriteFile(path, []byte(contents), setupPyFileMode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeMarkerFile(t *testing.T, dir, name string) {
	t.Helper()
	const markerFileMode = 0o644
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x\n"), markerFileMode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeFileAt writes contents to a slash-separated path relative to dir,
// creating intermediate directories. Used for the ruby-ext markers, which
// live under ext/<name>/ rather than at the repo root.
func writeFileAt(t *testing.T, dir, rel, contents string) {
	t.Helper()
	const (
		fileMode = 0o644
		dirMode  = 0o755
	)
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(contents), fileMode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// gemspecWithExtensions declares spec.extensions — RubyGems' own marker that
// the gem builds native code. gemspecPureRuby mentions the word "extensions"
// only in prose, so the ".extensions" Contains check must NOT match it.
const gemspecWithExtensions = `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.version = "1.0.0"
  spec.extensions = ["ext/example/extconf.rb"]
end
`

const gemspecPureRuby = `Gem::Specification.new do |spec|
  spec.name = "example"
  spec.version = "1.0.0"
  spec.summary = "adds some useful extensions to core classes"
end
`

//nolint:maintidx // exhaustive table: one case per builtinProfiles entry plus precedence/fallback edges; splitting would scatter the coverage.
func TestMatchProfile(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		setup   func(t *testing.T, dir string)
		want    string
		noSrcOK bool // if true, srcDir is "" for this case
	}{
		{
			name: "composer matches php",
			json: `{"package_managers":[{"name":"Composer"}]}`,
			want: "php",
		},
		{
			name: "composer case-insensitive",
			json: `{"package_managers":[{"name":"composer"}]}`,
			want: "php",
		},
		{
			name: "bundler matches ruby",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			want: "ruby",
		},
		{
			name: "bundler case-insensitive",
			json: `{"package_managers":[{"name":"bundler"}]}`,
			want: "ruby",
		},
		{
			name: "first composer match wins",
			json: `{"package_managers":[{"name":"Composer"},{"name":"npm"}]}`,
			want: "php",
		},
		{
			name: "composer present even if not first",
			json: `{"package_managers":[{"name":"npm"},{"name":"Composer"}]}`,
			want: "php",
		},
		{
			name: "composer + bundler picks php (registry order)",
			json: `{"package_managers":[{"name":"Composer"},{"name":"Bundler"}]}`,
			want: "php",
		},
		{
			name: "bundler + composer still picks php (registry order, not brief order)",
			json: `{"package_managers":[{"name":"Bundler"},{"name":"Composer"}]}`,
			want: "php",
		},
		{
			name: "npm matches node",
			json: `{"package_managers":[{"name":"npm"}]}`,
			want: "node",
		},
		{
			name: "npm case-insensitive",
			json: `{"package_managers":[{"name":"NPM"}]}`,
			want: "node",
		},
		{
			name: "composer before node when both present (registry order)",
			json: `{"package_managers":[{"name":"npm"},{"name":"Composer"}]}`,
			want: "php",
		},
		{
			name: "pip matches python",
			json: `{"package_managers":[{"name":"pip"}]}`,
			want: "python",
		},
		{
			name: "poetry matches python (secondary ecosystem)",
			json: `{"package_managers":[{"name":"Poetry"}]}`,
			want: "python",
		},
		{
			name: "uv matches python case-insensitive",
			json: `{"package_managers":[{"name":"UV"}]}`,
			want: "python",
		},
		{
			name: "pdm matches python",
			json: `{"package_managers":[{"name":"PDM"}]}`,
			want: "python",
		},
		{
			name: "setup.py with Extension selects python-ext",
			json: `{"package_managers":[{"name":"pip"}]}`,
			setup: func(t *testing.T, dir string) {
				writeSetupPy(t, dir, setupPyWithExtension)
			},
			want: "python-ext",
		},
		{
			name: "setup.py with Extension matches python-ext even without a manager",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeSetupPy(t, dir, setupPyWithExtension)
			},
			want: "python-ext",
		},
		{
			name: "pure-python setup.py does not match python-ext, pip picks python",
			json: `{"package_managers":[{"name":"pip"}]}`,
			setup: func(t *testing.T, dir string) {
				writeSetupPy(t, dir, setupPyPurePython)
			},
			want: "python",
		},
		{
			name: "go modules matches go",
			json: `{"package_managers":[{"name":"Go Modules"}]}`,
			want: "go",
		},
		{
			name: "go modules case-insensitive",
			json: `{"package_managers":[{"name":"go modules"}]}`,
			want: "go",
		},
		{
			name: "maven matches java",
			json: `{"package_managers":[{"name":"Maven"}]}`,
			want: "java",
		},
		{
			name: "gradle matches java (secondary ecosystem)",
			json: `{"package_managers":[{"name":"Gradle"}]}`,
			want: "java",
		},
		{
			name: "gradle case-insensitive",
			json: `{"package_managers":[{"name":"gradle"}]}`,
			want: "java",
		},
		{
			name: "nuget matches dotnet",
			json: `{"package_managers":[{"name":"NuGet"}]}`,
			want: "dotnet",
		},
		{
			name: "nuget case-insensitive",
			json: `{"package_managers":[{"name":"nuget"}]}`,
			want: "dotnet",
		},
		{
			name: "mix matches beam",
			json: `{"package_managers":[{"name":"Mix"}]}`,
			want: "beam",
		},
		{
			name: "rebar3 matches beam (secondary ecosystem)",
			json: `{"package_managers":[{"name":"rebar3"}]}`,
			want: "beam",
		},
		{
			name: "mix case-insensitive",
			json: `{"package_managers":[{"name":"mix"}]}`,
			want: "beam",
		},
		{
			// brief reports package_managers:null for Perl, so the profile
			// is marker-only and the json carries no signal here.
			name: "Makefile.PL selects perl",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "Makefile.PL")
			},
			want: "perl",
		},
		{
			name: "Build.PL selects perl",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "Build.PL")
			},
			want: "perl",
		},
		{
			name: "cpanfile selects perl",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "cpanfile")
			},
			want: "perl",
		},
		{
			name: "dist.ini selects perl",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "dist.ini")
			},
			want: "perl",
		},
		{
			name: "META.json selects perl",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "META.json")
			},
			want: "perl",
		},
		{
			name: "META.yml selects perl",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "META.yml")
			},
			want: "perl",
		},
		{
			// A CPAN dist that also commits a generated Makefile must still
			// route to perl, not c-cpp -- registry order guarantees this.
			name: "Makefile.PL wins over a c-cpp build file",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "Makefile.PL")
				writeMarkerFile(t, dir, "Makefile")
			},
			want: "perl",
		},
		{
			// brief returns null (not []) for Perl projects; matchProfile
			// must tolerate the absent key and still match on markers.
			name: "perl marker matches when package_managers is null",
			json: `{"package_managers":null}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "cpanfile")
			},
			want: "perl",
		},
		{
			name: "CMakeLists.txt selects c-cpp (no package manager)",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "CMakeLists.txt")
			},
			want: "c-cpp",
		},
		{
			name: "Makefile selects c-cpp",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "Makefile")
			},
			want: "c-cpp",
		},
		{
			name: "meson.build selects c-cpp",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "meson.build")
			},
			want: "c-cpp",
		},
		{
			name: "language ecosystem wins over a c-cpp build file",
			json: `{"package_managers":[{"name":"Composer"}]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "Makefile")
			},
			want: "php",
		},
		{
			// rust is registered before the c-cpp fallback, so a Cargo
			// crate that also ships a Makefile (common for -sys crates and
			// build.rs-driven C builds) still routes to the rust profile.
			name: "cargo wins over a c-cpp build file",
			json: `{"package_managers":[{"name":"Cargo"}]}`,
			setup: func(t *testing.T, dir string) {
				writeMarkerFile(t, dir, "Makefile")
			},
			want: "rust",
		},
		{
			name: "cargo matches rust",
			json: `{"package_managers":[{"name":"Cargo"}]}`,
			want: "rust",
		},
		{
			name: "cargo case-insensitive",
			json: `{"package_managers":[{"name":"cargo"}]}`,
			want: "rust",
		},
		{
			name: "truly unknown manager falls back",
			json: `{"package_managers":[{"name":"Conan"}]}`,
			want: "",
		},
		{
			name: "empty manager list falls back",
			json: `{"package_managers":[]}`,
			want: "",
		},
		{
			name: "missing field falls back",
			json: `{}`,
			want: "",
		},
		{
			name: "invalid json falls back",
			json: `not json`,
			want: "",
		},
		{
			name: "config.m4 with PHP_ARG selects php-ext",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeConfigM4(t, dir, configM4Body)
			},
			want: "php-ext",
		},
		{
			name: "php-ext wins over php when both signals present",
			json: `{"package_managers":[{"name":"Composer"}]}`,
			setup: func(t *testing.T, dir string) {
				writeConfigM4(t, dir, configM4Body)
			},
			want: "php-ext",
		},
		{
			name: "config.m4 without PHP_ARG does not match php-ext",
			json: `{"package_managers":[{"name":"Composer"}]}`,
			setup: func(t *testing.T, dir string) {
				writeConfigM4(t, dir, configM4WithoutPHPArg)
			},
			want: "php", // composer marker still picks php
		},
		{
			name: "config.m4 without PHP_ARG and no composer falls back",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeConfigM4(t, dir, configM4WithoutPHPArg)
			},
			want: "",
		},
		{
			name: "gemspec with spec.extensions selects ruby-ext",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "example.gemspec", gemspecWithExtensions)
			},
			want: "ruby-ext",
		},
		{
			name: "ext/<name>/extconf.rb selects ruby-ext",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "ext/example/extconf.rb", "require 'mkmf'\ncreate_makefile('example')\n")
			},
			want: "ruby-ext",
		},
		{
			name: "nested ext/<name>/<sub>/extconf.rb selects ruby-ext (bounded walk)",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "ext/example/native/extconf.rb", "require 'mkmf'\n")
			},
			want: "ruby-ext",
		},
		{
			name: "root extconf.rb selects ruby-ext (older single-dir gems)",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "extconf.rb", "require 'mkmf'\n")
			},
			want: "ruby-ext",
		},
		{
			name: "ext/<name>/Cargo.toml naming rb-sys selects ruby-ext (Cargo-native)",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "ext/example/Cargo.toml", "[package]\nname = \"example\"\n\n[dependencies]\nrb-sys = \"0.9\"\n")
			},
			want: "ruby-ext",
		},
		{
			// A Cargo-native gem (ext/**/Cargo.toml names rb-sys) still beats
			// the rust profile even when brief only reports Cargo, because
			// ruby-ext precedes rust in the registry.
			name: "cargo-native gem naming rb-sys matches ruby-ext over rust",
			json: `{"package_managers":[{"name":"Cargo"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "ext/example/Cargo.toml", "[dependencies]\nrb-sys = \"0.9\"\n")
			},
			want: "ruby-ext",
		},
		{
			// A pure-Rust crate that merely has an ext/ dir with a nested
			// Cargo.toml (no rb-sys) must route to rust, not ruby-ext: ruby-ext
			// is not a superset of rust (no Miri), so the Cargo.toml marker is
			// gated on an rb-sys mention.
			name: "pure-rust ext/**/Cargo.toml does not match ruby-ext, cargo picks rust",
			json: `{"package_managers":[{"name":"Cargo"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "ext/vendored/Cargo.toml", "[package]\nname = \"vendored\"\n")
			},
			want: "rust",
		},
		{
			name: "ruby-ext matches without a package manager (brief unavailable)",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "ext/example/extconf.rb", "require 'mkmf'\n")
			},
			want: "ruby-ext",
		},
		{
			name: "pure-ruby gemspec mentioning 'extensions' in prose does not match ruby-ext",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "example.gemspec", gemspecPureRuby)
			},
			want: "ruby",
		},
		{
			name: "pure-ruby Bundler repo selects ruby",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "Gemfile", "source 'https://rubygems.org'\n")
			},
			want: "ruby",
		},
		{
			name: "config/application.rb selects ruby-rails",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "config/application.rb", "module App\n  class Application < Rails::Application\n  end\nend\n")
			},
			want: "ruby-rails",
		},
		{
			// A config/application.rb that doesn't name Rails::Application (a
			// coincidental path, any language) must not route to ruby-rails.
			name: "config/application.rb without Rails::Application does not match ruby-rails",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "config/application.rb", "# app config\nAPP_ROOT = __dir__\n")
			},
			want: "ruby", // Bundler still picks ruby; ruby-rails needs the Rails marker
		},
		{
			// A Rails app that also ships a native extension matches both
			// ruby-rails and ruby-ext; ruby-ext wins on registry order, and
			// since ruby-ext now also carries Brakeman (a superset of
			// ruby-rails) that no longer drops Rails SAST.
			name: "ruby-ext beats ruby-rails when a Rails app also ships a native ext (registry order)",
			json: `{"package_managers":[{"name":"Bundler"}]}`,
			setup: func(t *testing.T, dir string) {
				writeFileAt(t, dir, "config/application.rb", "class Application < Rails::Application; end\n")
				writeFileAt(t, dir, "ext/example/extconf.rb", "require 'mkmf'\n")
			},
			want: "ruby-ext",
		},
		{
			name:    "marker profile cannot match without srcDir",
			json:    `{"package_managers":[]}`,
			noSrcOK: true,
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := ""
			if !tt.noSrcOK {
				dir = t.TempDir()
			}
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			got := matchProfile([]byte(tt.json), dir)
			if got.Name != tt.want {
				t.Errorf("matchProfile = %q, want %q", got.Name, tt.want)
			}
		})
	}
}

// TestWalkMarkerPresent_bounded locks the Walk matcher's depth bound: an
// extconf.rb buried below markerWalkMaxDepth must not match (so a pathological
// tree can't turn every repo into a ruby-ext candidate), while one within the
// bound does.
func TestWalkMarkerPresent_bounded(t *testing.T) {
	m := ProfileMarker{Path: "ext/extconf.rb", Walk: true}

	deep := t.TempDir()
	rel := "ext/" + strings.Repeat("a/", markerWalkMaxDepth+2) + "extconf.rb"
	writeFileAt(t, deep, rel, "require 'mkmf'\n")
	if markerPresent(m, deep) {
		t.Errorf("extconf.rb below depth %d should not match", markerWalkMaxDepth)
	}

	shallow := t.TempDir()
	writeFileAt(t, shallow, "ext/example/extconf.rb", "require 'mkmf'\n")
	if !markerPresent(m, shallow) {
		t.Errorf("extconf.rb within depth bound should match")
	}
}

// TestWalkMarkerPresent_fileCapAborts locks the file-count bound: once more
// than maxFiles entries have been visited the walk aborts via SkipAll, so a
// target sorted after the filler (only reached past the cap) is not found;
// raising the cap by one finds it. Exercised through walkMarkerPresentBounded
// so it needs a handful of files, not markerWalkMaxFiles of them.
func TestWalkMarkerPresent_fileCapAborts(t *testing.T) {
	m := ProfileMarker{Path: "ext/extconf.rb", Walk: true}
	dir := t.TempDir()
	// Filler files ("a00.txt"..) sort before the target ("extconf.rb"), so the
	// target is visited only after all of them; WalkDir walks entries in
	// lexical order, so a cap at the filler count trips before the match.
	const filler = 5
	for i := 0; i < filler; i++ {
		writeFileAt(t, dir, fmt.Sprintf("ext/a%02d.txt", i), "x\n")
	}
	writeFileAt(t, dir, "ext/extconf.rb", "require 'mkmf'\n")

	if walkMarkerPresentBounded(m, dir, markerWalkMaxDepth, filler) {
		t.Errorf("walk should abort at the %d-file cap before reaching the target", filler)
	}
	if !walkMarkerPresentBounded(m, dir, markerWalkMaxDepth, filler+1) {
		t.Errorf("with the cap above the file count the target should be found")
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
// and the validators rely on: every entry must have a name and either an
// Ecosystem or at least one Marker, names must be unique, and ecosystems
// must be unique case-insensitively (a duplicate would silently make
// auto-detection resolve the wrong profile, with no other test failing).
// Marker-only profiles legitimately have no Ecosystem and are excluded
// from the ecosystem-uniqueness check. A profile that matches several
// ecosystems (e.g. python, java) lists them via Ecosystems; every one is
// checked for uniqueness against every other profile's.
func TestBuiltinProfiles_registrySanity(t *testing.T) {
	names := map[string]bool{}
	ecosystems := map[string]bool{}
	for _, p := range builtinProfiles {
		if p.Name == "" {
			t.Error("profile with empty Name")
		}
		ecos := p.allEcosystems()
		if len(ecos) == 0 && len(p.Markers) == 0 && len(p.AnyMarkers) == 0 {
			t.Errorf("profile %q has no Ecosystem, Markers, or AnyMarkers", p.Name)
		}
		if names[p.Name] {
			t.Errorf("duplicate profile Name %q", p.Name)
		}
		names[p.Name] = true
		for _, e := range ecos {
			eco := strings.ToLower(e)
			if ecosystems[eco] {
				t.Errorf("duplicate profile Ecosystem %q (case-insensitive)", e)
			}
			ecosystems[eco] = true
		}
	}
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
