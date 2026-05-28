package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Profile selects a per-ecosystem runner image. The default profile
// (empty name) uses the runner image configured globally; named profiles
// build a Dockerfile under docker/profiles/<name>/ on demand and tag the
// resulting image with the sha of the Dockerfile contents.
type Profile struct {
	// Name matches the directory under docker/profiles/. Empty means
	// "use the default runner image, no per-profile build".
	Name string
	// Ecosystem is the `brief` package_managers[0].name that auto-selects
	// this profile. Matched case-insensitively.
	Ecosystem string
}

// IsDefault reports whether p falls back to the configured runner image
// instead of a profile-specific built one.
func (p Profile) IsDefault() bool { return p.Name == "" }

// builtinProfiles is the v1 registry. Add a new entry plus a Dockerfile
// under docker/profiles/<name>/ to expose a profile. Kept in code (not
// YAML) until a second/third profile lands and the duplication justifies
// the indirection.
var builtinProfiles = []Profile{
	{Name: "php", Ecosystem: "Composer"},
}

// ProfileByName returns the registered profile, or the default profile
// when name is empty / "default" / unknown. Unknown names fall back
// rather than erroring so an operator's typo does not block a scan; the
// override path that accepts user input validates separately.
func ProfileByName(name string) Profile {
	if name == "" || name == "default" {
		return Profile{}
	}
	for _, p := range builtinProfiles {
		if p.Name == name {
			return p
		}
	}
	return Profile{}
}

// KnownProfile reports whether name is an acceptable `?profile=` value:
// empty, "default", or a registered named profile. Use this to validate
// operator-supplied values before silently falling back to the default.
func KnownProfile(name string) bool {
	if name == "" || name == "default" {
		return true
	}
	return IsNamedProfile(name)
}

// IsNamedProfile reports whether name is a registered profile, excluding
// the default (which is the *absence* of a profile and cannot be the
// target of `requires_profile`).
func IsNamedProfile(name string) bool {
	for _, p := range builtinProfiles {
		if p.Name == name {
			return true
		}
	}
	return false
}

// matchProfile picks the registered profile whose Ecosystem matches the
// first package manager `brief` detected. Returns the zero profile when
// nothing matches.
func matchProfile(briefOut []byte) Profile {
	var brief struct {
		PackageManagers []struct {
			Name string `json:"name"`
		} `json:"package_managers"`
	}
	if err := json.Unmarshal(briefOut, &brief); err != nil {
		return Profile{}
	}
	for _, pm := range brief.PackageManagers {
		for _, p := range builtinProfiles {
			if strings.EqualFold(pm.Name, p.Ecosystem) {
				return p
			}
		}
	}
	return Profile{}
}

// DetectProfile runs `brief` against the cloned source inside the
// default runner image (which already ships brief) and returns the
// matching profile. Falls back to the zero profile on any error so a
// detection blip never blocks a scan.
func DetectProfile(ctx context.Context, runnerImage, srcDir string) Profile {
	absSrc, err := filepath.Abs(srcDir)
	if err != nil {
		return Profile{}
	}
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"--network", "none",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", absSrc+":/src:ro",
		"--entrypoint", "brief",
		runnerImage, "/src",
	)
	out, err := cmd.Output()
	if err != nil {
		return Profile{}
	}
	return matchProfile(out)
}

// ErrNoProfilesDir is returned by EnsureImage when the worker has no
// configured docker/profiles/ directory (e.g. tests, or a misconfigured
// deployment). The caller falls back to the default runner image.
var ErrNoProfilesDir = errors.New("profiles dir not configured")

// profileBuildLocks serialises `docker build` per image tag. Two scans
// that both detect the same profile must not race on the local image
// cache. One mutex per tag avoids serialising builds of distinct
// profiles.
var profileBuildLocks = struct {
	sync.Mutex
	m map[string]*sync.Mutex
}{m: map[string]*sync.Mutex{}}

func lockForTag(tag string) *sync.Mutex {
	profileBuildLocks.Lock()
	defer profileBuildLocks.Unlock()
	mu, ok := profileBuildLocks.m[tag]
	if !ok {
		mu = &sync.Mutex{}
		profileBuildLocks.m[tag] = mu
	}
	return mu
}

// imageTag returns the content-addressed tag for a profile's Dockerfile.
// The runner image ref is folded into the hash so a `--runner-image`
// bump invalidates profile images whose FROM resolved to the old base.
// Editing the Dockerfile produces a new tag, so the local cache is
// invalidated transparently. Old tags stay cached until the operator
// prunes them.
func imageTag(profileName string, dockerfile []byte, runnerImage string) string {
	h := sha256.New()
	h.Write(dockerfile)
	h.Write([]byte{0})
	h.Write([]byte(runnerImage))
	sum := h.Sum(nil)
	return fmt.Sprintf("scrutineer-profile-%s:%s", profileName, hex.EncodeToString(sum[:6]))
}

// EnsureImage builds the profile's Docker image if it is not in the
// local cache and returns the tag to pass to `docker run`. The
// `--build-arg RUNNER_IMAGE=...` is wired so the profile's FROM picks
// up whichever runner image the operator configured. Concurrency-safe:
// a per-tag mutex serialises duplicate builds.
func (p Profile) EnsureImage(ctx context.Context, profilesDir, runnerImage string) (string, error) {
	if p.IsDefault() {
		return runnerImage, nil
	}
	if profilesDir == "" {
		return "", ErrNoProfilesDir
	}
	dockerfile := filepath.Join(profilesDir, p.Name, "Dockerfile")
	contents, err := os.ReadFile(dockerfile)
	if err != nil {
		return "", fmt.Errorf("read profile dockerfile: %w", err)
	}
	tag := imageTag(p.Name, contents, runnerImage)

	mu := lockForTag(tag)
	mu.Lock()
	defer mu.Unlock()

	if imageExistsLocally(ctx, tag) {
		return tag, nil
	}
	buildArgs := []string{"build", "-t", tag, "-f", dockerfile}
	if runnerImage != "" {
		buildArgs = append(buildArgs, "--build-arg", "RUNNER_IMAGE="+runnerImage)
	}
	buildArgs = append(buildArgs, filepath.Join(profilesDir, p.Name))
	cmd := exec.CommandContext(ctx, "docker", buildArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker build %s: %w\n%s", tag, err, out)
	}
	return tag, nil
}

func imageExistsLocally(ctx context.Context, tag string) bool {
	return exec.CommandContext(ctx, "docker", "image", "inspect", tag).Run() == nil
}
