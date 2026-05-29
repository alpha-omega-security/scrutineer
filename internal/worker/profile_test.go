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

func writeMarker(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
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
			name: "unknown manager falls back",
			json: `{"package_managers":[{"name":"npm"}]}`,
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
				writeMarker(t, dir, "config.m4", configM4Body)
			},
			want: "php-ext",
		},
		{
			name: "php-ext wins over php when both signals present",
			json: `{"package_managers":[{"name":"Composer"}]}`,
			setup: func(t *testing.T, dir string) {
				writeMarker(t, dir, "config.m4", configM4Body)
			},
			want: "php-ext",
		},
		{
			name: "config.m4 without PHP_ARG does not match php-ext",
			json: `{"package_managers":[{"name":"Composer"}]}`,
			setup: func(t *testing.T, dir string) {
				writeMarker(t, dir, "config.m4", configM4WithoutPHPArg)
			},
			want: "php", // composer marker still picks php
		},
		{
			name: "config.m4 without PHP_ARG and no composer falls back",
			json: `{"package_managers":[]}`,
			setup: func(t *testing.T, dir string) {
				writeMarker(t, dir, "config.m4", configM4WithoutPHPArg)
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
	img, err := Profile{}.EnsureImage(context.Background(), "", "default-runner:latest")
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}
	if img != "default-runner:latest" {
		t.Errorf("got %q, want default runner image", img)
	}
}

func TestEnsureImage_noProfilesDir(t *testing.T) {
	_, err := Profile{Name: "php"}.EnsureImage(context.Background(), "", "default:latest")
	if err == nil {
		t.Fatal("expected ErrNoProfilesDir, got nil")
	}
}

func TestEnsureImage_missingDockerfile(t *testing.T) {
	dir := t.TempDir()
	_, err := Profile{Name: "php"}.EnsureImage(context.Background(), dir, "default:latest")
	if err == nil {
		t.Fatal("expected error for missing dockerfile, got nil")
	}
}

func TestRepoShipsPHPDockerfile(t *testing.T) {
	wd, _ := os.Getwd()
	repoRoot := filepath.Join(wd, "..", "..")
	for _, profile := range []string{"php", "php-ext"} {
		path := filepath.Join(repoRoot, "docker", "profiles", profile, "Dockerfile")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected %s profile Dockerfile to exist: %v", profile, err)
		}
		guide := filepath.Join(repoRoot, "docker", "profiles", profile, "PROFILE.md")
		if _, err := os.Stat(guide); err != nil {
			t.Errorf("expected %s profile PROFILE.md to exist: %v", profile, err)
		}
	}
}
