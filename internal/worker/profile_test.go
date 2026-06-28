package worker

import (
	"context"
	"os"
	"path/filepath"
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
