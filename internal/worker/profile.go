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
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ProfileMarker refines profile selection beyond what brief reports.
type ProfileMarker struct {
	// Path is the marker location relative to the cloned source root.
	// Its interpretation depends on Glob/Walk:
	//   - default: an exact path, tested with os.Stat.
	//   - Glob:    a filepath.Glob pattern (single-segment wildcards),
	//              e.g. "*.gemspec".
	//   - Walk:    "<root>/<basename>"; <basename> is searched for anywhere
	//              under <root> by a depth- and count-bounded walk, e.g.
	//              "ext/extconf.rb" finds an extconf.rb at any depth under
	//              ext/.
	Path string
	// Contains, when set, must also appear inside the matched file — used
	// e.g. to distinguish a phpize config.m4 from any unrelated autoconf
	// file, or a gemspec that declares spec.extensions from one that merely
	// mentions the word. Bounded by markerReadCap.
	Contains string
	// Glob makes Path a filepath.Glob pattern instead of an exact path.
	// filepath.Glob expands * ? [..] within a single path segment, which
	// covers root-level fan-outs like "*.gemspec".
	Glob bool
	// Walk makes Path a "<root>/<basename>" pair: <basename> (the last
	// segment) is searched for anywhere beneath <root> (the rest) by a
	// bounded directory walk. filepath.Glob cannot express "**", so this
	// covers native-extension layouts like ext/<name>/extconf.rb and the
	// deeper ext/<name>/<sub>/extconf.rb some gems use.
	Walk bool
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
	// BaseProfile, when set, names another registered profile whose built
	// image this profile builds FROM instead of the runner image. EnsureImage
	// builds that base first and passes its content-addressed tag as the
	// BASE_IMAGE build-arg, folding the tag into this profile's own tag so a
	// change anywhere up the chain (runner, base Dockerfile) rebuilds this
	// profile too. Empty (the common case) means FROM the runner image.
	BaseProfile string
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
	{
		// Before ruby: a gem that ships a native extension (C/C++, or Rust
		// via rb-sys/Cargo) routes to the sanitizer-instrumented interpreter.
		// ruby-ext is a SUPERSET of both the ruby and ruby-rails profiles — it
		// keeps the full Ruby-level audit, adds memory-safety coverage, and
		// installs Brakeman (see docker/profiles/ruby-ext/Dockerfile) — so a
		// gem that also looks like a Rails app still gets Rails SAST despite
		// matching here first, and a false match against a *Ruby* repo only
		// costs build time, never coverage. The auto-chained revalidate/verify
		// scans now inherit the parent scan's resolved profile (#548), so verify
		// reproduces an ASan crash on this same image; robust detection still
		// matters for a manual re-run or the /v1/import path, which detect
		// fresh.
		//
		// It is NOT a superset of the rust profile (no Miri, only a minimal
		// rustc for rb-sys shims), so the Cargo.toml marker below is gated on
		// an rb-sys mention: an unqualified ext/**/Cargo.toml would pull a
		// pure-Rust crate in here — ruby-ext precedes rust — and strip its
		// Rust-specific coverage.
		//
		// Markers (OR): the gemspec's spec.extensions is RubyGems' own
		// definition of "has native code" and is authoritative; the bounded
		// ext/ walks catch the conventional ext/<name>/extconf.rb (mkmf, also
		// used by rb-sys Rust) and a Cargo-native gem's ext/<name>/Cargo.toml
		// that names rb-sys (magnus builds on it); the root extconf.rb covers
		// the older single-dir style. A real Cargo-native gem also ships an
		// extconf.rb or spec.extensions, so the sibling markers still catch it
		// if the rb-sys needle is ever absent.
		Name: "ruby-ext",
		AnyMarkers: []ProfileMarker{
			{Path: "*.gemspec", Glob: true, Contains: ".extensions"},
			{Path: "ext/extconf.rb", Walk: true},
			{Path: "ext/Cargo.toml", Walk: true, Contains: "rb-sys"},
			{Path: "extconf.rb"},
		},
	},
	{
		// Before ruby: a Rails app (config/application.rb is the canonical
		// boot file) also gets Brakeman, the Rails-specific SAST, on top of
		// the ruby runtime. Like ruby-ext this is a superset of the ruby
		// profile — it builds FROM the ruby profile image (BaseProfile) and
		// adds Brakeman, so the interpreter is byte-identical with no second
		// from-source compile. Marker-only so it does not collide with ruby's
		// Bundler ecosystem in the registry-sanity test. The marker requires
		// the file to name Rails::Application (the base class every app's
		// Application subclasses) so a coincidental config/application.rb in a
		// non-Rails repo — of any language — does not route here.
		Name:        "ruby-rails",
		BaseProfile: "ruby",
		Markers: []ProfileMarker{
			{Path: "config/application.rb", Contains: "Rails::Application"},
		},
	},
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
		// brief reports no package manager for Perl (it parses cpanfile /
		// META.json into purls but leaves package_managers null), so the
		// profile matches on the dist's build files instead. Before c-cpp so
		// a CPAN dist that also commits a generated Makefile, or whose
		// Makefile.PL has already been run, routes here rather than to the
		// native toolchain.
		Name: "perl",
		AnyMarkers: []ProfileMarker{
			{Path: "Makefile.PL"},
			{Path: "Build.PL"},
			{Path: "cpanfile"},
			{Path: "dist.ini"},
			{Path: "META.json"},
			{Path: "META.yml"},
		},
	},
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
		if !markerPresent(m, srcDir) {
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
		if markerPresent(m, srcDir) {
			return true
		}
	}
	return false
}

// markerWalkMaxDepth and markerWalkMaxFiles bound the Walk matcher so a
// deep or hostile tree can't stall detection. The depth is generous enough
// for real ext/ layouts (ext/<name>/<sub>/extconf.rb) while the file cap is
// a backstop against a pathological repo.
const (
	markerWalkMaxDepth = 6
	markerWalkMaxFiles = 50_000
)

// markerPresent reports whether a single marker is satisfied under srcDir,
// dispatching on the marker's mode (exact path, Glob pattern, or bounded
// Walk). Contains, when set, additionally requires the matched file to hold
// the substring.
func markerPresent(m ProfileMarker, srcDir string) bool {
	switch {
	case m.Glob:
		matches, err := filepath.Glob(filepath.Join(srcDir, m.Path))
		if err != nil {
			return false
		}
		for _, f := range matches {
			if m.Contains == "" || fileContains(f, m.Contains) {
				return true
			}
		}
		return false
	case m.Walk:
		return walkMarkerPresent(m, srcDir)
	default:
		full := filepath.Join(srcDir, m.Path)
		if m.Contains == "" {
			_, err := os.Stat(full)
			return err == nil
		}
		return fileContains(full, m.Contains)
	}
}

// walkMarkerPresent searches for a file named filepath.Base(m.Path) anywhere
// under filepath.Dir(m.Path) (relative to srcDir), bounded by
// markerWalkMaxDepth and markerWalkMaxFiles. A missing or unreadable root is
// simply "not present" — detection never fails a scan. When Contains is set
// the matched file must also hold the substring.
func walkMarkerPresent(m ProfileMarker, srcDir string) bool {
	return walkMarkerPresentBounded(m, srcDir, markerWalkMaxDepth, markerWalkMaxFiles)
}

// walkMarkerPresentBounded is walkMarkerPresent with the depth and file bounds
// injected, so both caps are unit-testable without materialising a
// markerWalkMaxDepth-deep tree or markerWalkMaxFiles of files.
func walkMarkerPresentBounded(m ProfileMarker, srcDir string, maxDepth, maxFiles int) bool {
	root := filepath.Join(srcDir, filepath.Dir(m.Path))
	target := filepath.Base(m.Path)
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	files := 0
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip it, don't abort the walk
		}
		if d.IsDir() {
			if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		files++
		if files > maxFiles {
			return fs.SkipAll
		}
		if d.Name() == target && (m.Contains == "" || fileContains(path, m.Contains)) {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
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
// detection blip never blocks a scan. relabel mirrors the runner's
// --selinux setting so the read-only /src mount is relabeled (":ro,z")
// on an SELinux host, just like the real scan's /work mount.
func DetectProfile(ctx context.Context, rt ContainerRuntime, runnerImage, srcDir string, relabel bool) Profile {
	absSrc, err := filepath.Abs(srcDir)
	if err != nil {
		return Profile{}
	}
	args := rt.runArgs("--rm",
		"--network", "none",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", bindMount(absSrc, "/src", relabel, "ro"),
		"--entrypoint", "brief",
		runnerImage, "/src",
	)
	cmd := exec.CommandContext(ctx, rt.bin(), args...)
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

// profileBuildLocks serialises the image build per tag. Two scans
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
// base instead of reusing a months-old cached profile image. On docker it
// shells out to `docker buildx imagetools inspect --raw`; on runtimes without
// buildx (podman and Apple's container), it uses `skopeo inspect --raw` when
// skopeo is installed. Both fetch the canonical manifest bytes without pulling
// layers. Best-effort:
// returns "" when the tool is unavailable, the registry is unreachable, or the
// ref is local-only (e.g. scrutineer-runner:local), so imageTag falls back to
// keying on the ref string alone rather than blocking the scan.
//
// remoteRunnerDigest (the runner-image staleness check) is the other caller; it
// prepends "sha256:" and compares the result against the local RepoDigest. That
// only holds because this hashes the canonical manifest bytes, which is exactly
// what a registry records as a tag's digest -- keep it that way (don't switch to
// a config or layer digest) or the staleness banner silently mis-fires.
func resolveBaseDigest(ctx context.Context, rt ContainerRuntime, runnerImage string) string {
	if runnerImage == "" {
		return ""
	}
	var out []byte
	var err error
	if rt.Bin == runtimePodman || rt.Bin == runtimeApple {
		// podman and Apple's container CLI have no `buildx imagetools`; skopeo
		// fetches the same canonical manifest bytes without pulling layers. ""
		// when skopeo is absent, so the caller keeps the ref-string fallback
		// (no new failure mode).
		if _, lookErr := exec.LookPath("skopeo"); lookErr != nil {
			return ""
		}
		out, err = exec.CommandContext(ctx, "skopeo", "inspect", "--raw", "docker://"+runnerImage).Output()
	} else {
		out, err = exec.CommandContext(ctx, "docker", "buildx", "imagetools", "inspect", runnerImage, "--raw").Output()
	}
	if err != nil || len(out) == 0 {
		return ""
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
}

// EnsureImage builds the profile's container image if it is not in the
// local cache and returns the tag to pass to the runtime's `run`. A
// runner-based profile is wired with `--build-arg RUNNER_IMAGE=...` so its
// FROM picks up the configured runner; a chained profile (BaseProfile set) is
// built FROM the base profile's image — built first and passed as
// `--build-arg BASE_IMAGE=...`. Concurrency-safe: a per-tag mutex serialises
// duplicate builds. emit is called only on a cache miss (before and after the
// image build) so the scan log shows progress during a multi-minute first
// build.
func (p Profile) EnsureImage(ctx context.Context, rt ContainerRuntime, profilesDir, runnerImage string, emit func(Event)) (string, error) {
	if p.IsDefault() {
		return runnerImage, nil
	}
	if profilesDir == "" {
		return "", ErrNoProfilesDir
	}

	// baseImage is what the profile's FROM resolves to. For a chained profile
	// (BaseProfile set, e.g. ruby-rails FROM ruby) that is the base profile's
	// own built image — build it first — so the shared base is never recompiled
	// and the interpreter is byte-identical. Otherwise it is the runner image,
	// and we fold in its resolved registry digest so a moved :latest rebuilds.
	baseImage := runnerImage
	baseDigest := ""
	if p.BaseProfile != "" {
		base := ProfileByName(p.BaseProfile)
		if base.IsDefault() {
			return "", fmt.Errorf("profile %s: unknown base profile %q", p.Name, p.BaseProfile)
		}
		var err error
		if baseImage, err = base.EnsureImage(ctx, rt, profilesDir, runnerImage, emit); err != nil {
			return "", fmt.Errorf("profile %s: build base %s: %w", p.Name, p.BaseProfile, err)
		}
	} else {
		baseDigest = resolveBaseDigest(ctx, rt, runnerImage)
	}

	dockerfile := filepath.Join(profilesDir, p.Name, "Dockerfile")
	contents, err := os.ReadFile(dockerfile)
	if err != nil {
		return "", fmt.Errorf("read profile dockerfile: %w", err)
	}
	// Hashing baseImage in makes invalidation transitive: for a chained profile
	// it is the base's already-content-addressed tag (so a base rebuild yields a
	// new tag here), and for a runner profile it is the runner ref keyed
	// alongside baseDigest exactly as before.
	tag := imageTag(p.Name, contents, baseImage, baseDigest)

	mu := lockForTag(tag)
	mu.Lock()
	defer mu.Unlock()

	if imageExistsLocally(ctx, rt, tag) {
		return tag, nil
	}
	emit(Event{Kind: KindText, Text: "profile: building " + tag + " (first build can take several minutes)"})
	start := time.Now()
	args := profileBuildArgs(p, tag, dockerfile, filepath.Join(profilesDir, p.Name), baseImage, baseDigest)
	cmd := exec.CommandContext(ctx, rt.bin(), args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s build %s: %w\n%s", rt.bin(), tag, err, out)
	}
	emit(Event{Kind: KindText, Text: "profile: built " + tag + " in " + time.Since(start).Round(time.Second).String()})
	return tag, nil
}

// profileBuildArgs assembles the `build` argv for a profile image. Pure (no
// I/O) so the chained-vs-runner branching is unit-testable without a runtime.
//
//   - A chained profile (BaseProfile set) receives its base as BASE_IMAGE and
//     never --pull's: the base is the locally-built base profile image, not a
//     registry ref, so --pull would try to fetch a tag that exists only here.
//     The runner's freshness is already handled when the base itself is built.
//   - A runner-based profile passes RUNNER_IMAGE and --pull's the runner when
//     its digest resolved, so BuildKit fetches the base the tag is keyed on
//     rather than a stale cached :latest (see #477).
func profileBuildArgs(p Profile, tag, dockerfile, contextDir, baseImage, baseDigest string) []string {
	args := []string{"build"}
	if p.BaseProfile == "" && baseDigest != "" {
		args = append(args, "--pull")
	}
	args = append(args, "-t", tag, "-f", dockerfile)
	switch {
	case p.BaseProfile != "":
		args = append(args, "--build-arg", "BASE_IMAGE="+baseImage)
	case baseImage != "":
		args = append(args, "--build-arg", "RUNNER_IMAGE="+baseImage)
	}
	args = append(args, contextDir)
	return args
}

func imageExistsLocally(ctx context.Context, rt ContainerRuntime, tag string) bool {
	return exec.CommandContext(ctx, rt.bin(), "image", "inspect", tag).Run() == nil
}
