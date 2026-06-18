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
		{"php", "php", true, true},
		{"php-ext", "php-ext", true, true},
		{"ruby", "ruby", true, true},
		{"node", "node", true, true},
		{"unknown", "", false, false},
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
			name: "truly unknown manager falls back",
			json: `{"package_managers":[{"name":"Cargo"}]}`,
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
	a := imageTag("php", []byte("FROM x\nRUN echo a\n"), "runner:1")
	b := imageTag("php", []byte("FROM x\nRUN echo a\n"), "runner:1")
	c := imageTag("php", []byte("FROM x\nRUN echo b\n"), "runner:1")
	d := imageTag("php", []byte("FROM x\nRUN echo a\n"), "runner:2")

	if a != b {
		t.Errorf("same contents and runner should yield same tag: %q vs %q", a, b)
	}
	if a == c {
		t.Errorf("different contents should yield different tag, both %q", a)
	}
	if a == d {
		t.Errorf("different runner image should yield different tag, both %q", a)
	}
	if !strings.HasPrefix(a, "scrutineer-profile-php:") {
		t.Errorf("tag %q does not have expected prefix", a)
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
	img, err := Profile{}.EnsureImage(context.Background(), "", "default-runner:latest", func(Event) { emitted++ })
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
	_, err := Profile{Name: "php"}.EnsureImage(context.Background(), "", "default:latest", func(Event) { emitted++ })
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
	_, err := Profile{Name: "php"}.EnsureImage(context.Background(), dir, "default:latest", func(Event) { emitted++ })
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
// Marker-only profiles legitimately have an empty Ecosystem and are
// excluded from the ecosystem-uniqueness check.
func TestBuiltinProfiles_registrySanity(t *testing.T) {
	names := map[string]bool{}
	ecosystems := map[string]bool{}
	for _, p := range builtinProfiles {
		if p.Name == "" {
			t.Error("profile with empty Name")
		}
		if p.Ecosystem == "" && len(p.Markers) == 0 {
			t.Errorf("profile %q has neither Ecosystem nor Markers", p.Name)
		}
		if names[p.Name] {
			t.Errorf("duplicate profile Name %q", p.Name)
		}
		names[p.Name] = true
		if p.Ecosystem == "" {
			continue
		}
		eco := strings.ToLower(p.Ecosystem)
		if ecosystems[eco] {
			t.Errorf("duplicate profile Ecosystem %q (case-insensitive)", p.Ecosystem)
		}
		ecosystems[eco] = true
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
// per-container PROFILE.md they advertise. PROFILE.md is optional in
// general (a profile without one simply gets no orientation injected at
// scan time); these profiles document specifics the agent needs to
// behave correctly, so missing them is a real regression.
func TestProfileGuidesShip(t *testing.T) {
	wd, _ := os.Getwd()
	repoRoot := filepath.Join(wd, "..", "..")
	for _, name := range []string{"php", "php-ext", "ruby", "node"} {
		guide := filepath.Join(repoRoot, "docker", "profiles", name, "PROFILE.md")
		if _, err := os.Stat(guide); err != nil {
			t.Errorf("expected %s profile PROFILE.md to exist: %v", name, err)
		}
	}
}
