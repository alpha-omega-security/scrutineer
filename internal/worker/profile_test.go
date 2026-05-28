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

func TestMatchProfile(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"composer matches php", `{"package_managers":[{"name":"Composer"}]}`, "php"},
		{"composer case-insensitive", `{"package_managers":[{"name":"composer"}]}`, "php"},
		{"first match wins over later", `{"package_managers":[{"name":"Composer"},{"name":"npm"}]}`, "php"},
		{"unknown manager falls back", `{"package_managers":[{"name":"npm"}]}`, ""},
		{"empty list falls back", `{"package_managers":[]}`, ""},
		{"missing field falls back", `{}`, ""},
		{"invalid json falls back", `not json`, ""},
		{"no first match but later is known", `{"package_managers":[{"name":"npm"},{"name":"Composer"}]}`, "php"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchProfile([]byte(tt.json))
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
	path := filepath.Join(repoRoot, "docker", "profiles", "php", "Dockerfile")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected php profile Dockerfile to exist: %v", err)
	}
}
