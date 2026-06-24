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
	// case-insensitively, for runtimes brief can see. A profile needs at
	// least one of Ecosystem/Ecosystems, Markers, or AnyMarkers: each
	// matcher treats an empty constraint as "no constraint", so an entry
	// with all of them empty would match every repo. The registry sanity
	// test rejects that. Markers/AnyMarkers cover ecosystems brief cannot
	// see (e.g. a PECL C extension repo without composer.json).
	Ecosystem string
	// Ecosystems lists additional `brief` package_managers[].name values
	// the profile also matches, for ecosystems one runtime serves under
	// several names (e.g. Python's pip / Poetry / Pipenv / uv / PDM, or the
	// JVM's Maven and Gradle). The profile matches if any of Ecosystem or
	// Ecosystems matches.
	Ecosystems []string
	// Markers must ALL be present (AND) for the profile to match. Use for a
	// precise signal, e.g. a config.m4 that contains PHP_ARG_.
	Markers []ProfileMarker
	// AnyMarkers match if at least ONE is present (OR). Use when a single
	// ecosystem has several equally-valid build-file signals and brief
	// reports no package manager for it — e.g. C/C++ projects built with
	// CMake, Make, autotools, or meson.
	AnyMarkers []ProfileMarker
}

// IsDefault reports whether p falls back to the configured runner image
// instead of a profile-specific built one.
func (p Profile) IsDefault() bool { return p.Name == "" }

// allEcosystems returns every brief package-manager name the profile
// matches: the singular Ecosystem (if set) plus any in Ecosystems.
func (p Profile) allEcosystems() []string {
	out := make([]string, 0, len(p.Ecosystems)+1)
	if p.Ecosystem != "" {
		out = append(out, p.Ecosystem)
	}
	out = append(out, p.Ecosystems...)
	return out
}

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
	{
		// Before python: a repo whose setup.py declares a C Extension is
		// shipping native code, so route it to the ASan/UBSan interpreter.
		Name: "python-ext",
		Markers: []ProfileMarker{
			{Path: "setup.py", Contains: "Extension("},
		},
	},
	{Name: "python", Ecosystems: []string{"pip", "Pipenv", "Poetry", "uv", "PDM"}},
	{Name: "go", Ecosystem: "Go Modules"},
	{Name: "java", Ecosystems: []string{"Maven", "Gradle"}},
	{Name: "dotnet", Ecosystem: "NuGet"},
	{Name: "beam", Ecosystems: []string{"Mix", "rebar3"}},
	{Name: "rust", Ecosystem: "Cargo"},
	{
		// Last: brief reports no package manager for C/C++, so this is a
		// fallback for repos that match no language ecosystem above but
		// carry a native build file. Language repos (which also often have
		// a Makefile) match their ecosystem first, so this only catches
		// repos that are actually native.
		Name: "c-cpp",
		AnyMarkers: []ProfileMarker{
			{Path: "CMakeLists.txt"},
			{Path: "Makefile"},
			{Path: "GNUmakefile"},
			{Path: "configure.ac"},
			{Path: "configure.in"},
			{Path: "meson.build"},
		},
	},
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
		if !ecosystemMatch(p.allEcosystems(), pms) {
			continue
		}
		if !markersMatch(p.Markers, srcDir) {
			continue
		}
		if !anyMarkersMatch(p.AnyMarkers, srcDir) {
			continue
		}
		return p
	}
	return Profile{}
}

func ecosystemMatch(ecosystems, pms []string) bool {
	if len(ecosystems) == 0 {
		return true
	}
	for _, e := range ecosystems {
		for _, pm := range pms {
			if strings.EqualFold(pm, e) {
				return true
			}
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

// anyMarkersMatch reports whether at least one marker is present (OR). An
// empty list matches (the profile imposes no AnyMarkers constraint); a
// non-empty list with no srcDir cannot match.
func anyMarkersMatch(markers []ProfileMarker, srcDir string) bool {
	if len(markers) == 0 {
		return true
	}
	if srcDir == "" {
		return false
	}
	for _, m := range markers {
		full := filepath.Join(srcDir, m.Path)
		if m.Contains == "" {
			if _, err := os.Stat(full); err == nil {
				return true
			}
			continue
		}
		if fileContains(full, m.Contains) {
			return true
		}
	}
	return false
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
// The runner image ref and its resolved registry digest are both folded
// into the hash: editing the Dockerfile, pointing --runner-image at a
// different ref, or a moved tag (the default :latest resolving to a new
// digest) each yield a new tag, so the local cache is invalidated
// transparently and the new image builds alongside the old. baseDigest is
// empty when the digest can't be resolved (offline, or a local-only ref);
// the tag then keys on the ref string alone, the behaviour before the
// digest was folded in. Old tags stay cached until the operator prunes
// them.
func imageTag(profileName string, dockerfile []byte, runnerImage, baseDigest string) string {
	h := sha256.New()
	h.Write(dockerfile)
	h.Write([]byte{0})
	h.Write([]byte(runnerImage))
	if baseDigest != "" {
		h.Write([]byte{0})
		h.Write([]byte(baseDigest))
	}
	sum := h.Sum(nil)
	return fmt.Sprintf("scrutineer-profile-%s:%s", profileName, hex.EncodeToString(sum[:6]))
}

// resolveBaseDigest returns a content fingerprint of runnerImage as it
// currently resolves in the registry, so a moved tag (notably the default
// :latest) produces a new profile tag and forces a rebuild against the new
// base instead of reusing a months-old cached profile image. It shells out
// to `docker buildx imagetools inspect --raw`, which fetches the canonical
// manifest bytes without pulling layers; buildx ships wherever `docker
// build` runs, so it is available on the profile-build path. Best-effort:
// returns "" when the registry is unreachable or the ref is local-only
// (e.g. scrutineer-runner:local), so imageTag falls back to keying on the
// ref string alone rather than blocking the scan.
func resolveBaseDigest(ctx context.Context, runnerImage string) string {
	if runnerImage == "" {
		return ""
	}
	out, err := exec.CommandContext(ctx, "docker", "buildx", "imagetools", "inspect", runnerImage, "--raw").Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
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
	baseDigest := resolveBaseDigest(ctx, runnerImage)
	tag := imageTag(p.Name, contents, runnerImage, baseDigest)

	mu := lockForTag(tag)
	mu.Lock()
	defer mu.Unlock()

	if imageExistsLocally(ctx, tag) {
		return tag, nil
	}
	emit(Event{Kind: KindText, Text: "profile: building " + tag + " (first build can take several minutes)"})
	start := time.Now()
	buildArgs := []string{"build"}
	if baseDigest != "" {
		// resolveBaseDigest found the runner in a registry and keyed the
		// tag on its remote digest; --pull makes BuildKit fetch that base
		// rather than reuse a stale locally cached :latest, so the layers
		// match the digest the tag is keyed on. Skipped when the digest
		// did not resolve (offline, or a local-only ref like
		// scrutineer-runner:local) so the build still works against the
		// local cache. See #477.
		buildArgs = append(buildArgs, "--pull")
	}
	buildArgs = append(buildArgs, "-t", tag, "-f", dockerfile)
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
