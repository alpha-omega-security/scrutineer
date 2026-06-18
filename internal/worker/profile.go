package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ProfileMarker refines profile selection beyond what brief reports.
// Path is relative to the cloned source root; Contains, when set, must
// also appear inside the file — used e.g. to distinguish a phpize
// config.m4 from any unrelated autoconf file.
type ProfileMarker struct {
	Path     string
	Contains string
}

// Profile selects a per-ecosystem runner image. The default profile
// (empty name) uses the runner image configured globally; named profiles
// build a Dockerfile under docker/profiles/<name>/ on demand and tag the
// resulting image with the sha of the Dockerfile contents.
type Profile struct {
	// Name matches the directory under docker/profiles/. Empty means
	// "use the default runner image, no per-profile build".
	Name string
	// Ecosystem is a `brief` package_managers[].name, matched
	// case-insensitively. Empty falls back to Markers — useful for
	// ecosystems brief cannot see (e.g. a PECL C extension repo without
	// composer.json).
	Ecosystem string
	Markers   []ProfileMarker
}

// IsDefault reports whether p falls back to the configured runner image
// instead of a profile-specific built one.
func (p Profile) IsDefault() bool { return p.Name == "" }

// builtinProfiles is the v1 registry. Order matters: first match wins,
// so more specific profiles (php-ext) come before their general
// counterparts (php). Add a new entry plus a Dockerfile under
// docker/profiles/<name>/ to expose a profile.
var builtinProfiles = []Profile{
	{
		Name: "php-ext",
		Markers: []ProfileMarker{
			{Path: "config.m4", Contains: "PHP_ARG_"},
		},
	},
	{Name: "php", Ecosystem: "Composer"},
	{Name: "ruby", Ecosystem: "Bundler"},
	{Name: "node", Ecosystem: "npm"},
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

func matchProfile(briefOut []byte, srcDir string) Profile {
	var brief struct {
		PackageManagers []struct {
			Name string `json:"name"`
		} `json:"package_managers"`
	}
	_ = json.Unmarshal(briefOut, &brief)
	pms := make([]string, 0, len(brief.PackageManagers))
	for _, pm := range brief.PackageManagers {
		pms = append(pms, pm.Name)
	}
	for _, p := range builtinProfiles {
		if !ecosystemMatch(p.Ecosystem, pms) {
			continue
		}
		if !markersMatch(p.Markers, srcDir) {
			continue
		}
		return p
	}
	return Profile{}
}

func ecosystemMatch(ecosystem string, pms []string) bool {
	if ecosystem == "" {
		return true
	}
	for _, pm := range pms {
		if strings.EqualFold(pm, ecosystem) {
			return true
		}
	}
	return false
}

func markersMatch(markers []ProfileMarker, srcDir string) bool {
	if len(markers) == 0 {
		return true
	}
	if srcDir == "" {
		return false
	}
	for _, m := range markers {
		full := filepath.Join(srcDir, m.Path)
		if m.Contains == "" {
			if _, err := os.Stat(full); err != nil {
				return false
			}
			continue
		}
		if !fileContains(full, m.Contains) {
			return false
		}
	}
	return true
}

// markerReadCap bounds Contains-substring scans so a hostile or
// runaway file can't stall detection.
const markerReadCap = 1 << 20

func fileContains(path, needle string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, markerReadCap))
	if err != nil {
		return false
	}
	return bytes.Contains(b, []byte(needle))
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
		// Marker-only profiles can still match when brief is unavailable.
		out = nil
	}
	return matchProfile(out, absSrc)
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
// a per-tag mutex serialises duplicate builds. emit is called only on
// a cache miss (before and after the docker build) so the scan log
// shows progress during a multi-minute first build.
func (p Profile) EnsureImage(ctx context.Context, profilesDir, runnerImage string, emit func(Event)) (string, error) {
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
	emit(Event{Kind: KindText, Text: "profile: building " + tag + " (first build can take several minutes)"})
	start := time.Now()
	buildArgs := []string{"build", "-t", tag, "-f", dockerfile}
	if runnerImage != "" {
		buildArgs = append(buildArgs, "--build-arg", "RUNNER_IMAGE="+runnerImage)
	}
	buildArgs = append(buildArgs, filepath.Join(profilesDir, p.Name))
	cmd := exec.CommandContext(ctx, "docker", buildArgs...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("docker build %s: %w\n%s", tag, err, out)
	}
	emit(Event{Kind: KindText, Text: "profile: built " + tag + " in " + time.Since(start).Round(time.Second).String()})
	return tag, nil
}

func imageExistsLocally(ctx context.Context, tag string) bool {
	return exec.CommandContext(ctx, "docker", "image", "inspect", tag).Run() == nil
}
