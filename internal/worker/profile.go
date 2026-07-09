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
	"time"
)

// Internal selector category names that BriefMatch.Category can reference.
// package_manager and language map to brief's top-level package_managers and
// languages arrays; everything else is a key under brief's tools object.
const (
	briefPackageManager  = "package_manager"
	briefLanguage        = "language"
	briefBuild           = "build"
	briefNativeExtension = "native_extension"
)

// BriefMatch selects a profile when brief detected any of Names in the
// given Category. Names are matched case-insensitively against
// Detection.Name in brief's JSON output.
type BriefMatch struct {
	Category string
	Names    []string
}

// Profile selects a per-ecosystem runner image. The default profile
// (empty name) uses the runner image configured globally; named profiles
// build a Dockerfile under docker/profiles/<name>/ on demand and tag the
// resulting image with the sha of the Dockerfile contents.
type Profile struct {
	// Name matches the directory under docker/profiles/. Empty means
	// "use the default runner image, no per-profile build".
	Name string
	// Detect selects the profile from brief's structured output. The
	// profile matches when any BriefMatch is satisfied; a BriefMatch is
	// satisfied when brief detected any of its Names in its Category.
	// Every profile must carry at least one entry: an empty Detect would
	// never match, and the registry sanity test rejects dead profiles.
	Detect []BriefMatch
	// BaseProfile, when set, names another registered profile whose built
	// image this profile builds FROM instead of the runner image. EnsureImage
	// builds that base first and passes its content-addressed tag as the
	// BASE_IMAGE build-arg, folding the tag into this profile's own tag so a
	// change anywhere up the chain (runner, base Dockerfile) rebuilds this
	// profile too. Empty (the common case) means FROM the runner image.
	BaseProfile string
	// FallbackProfile, when set, names the profile to degrade to when THIS
	// profile's image cannot be built (runner base unreachable, the
	// sanitizer-instrumented interpreter fails to compile, a toolchain step
	// breaks). Unlike BaseProfile — which this profile builds FROM — the
	// fallback is a coverage degrade: resolveProfile tries it next so the scan
	// still runs under a related profile whose PROFILE.md carries the right
	// guidance (notably the "native extensions — escalate, do not skip" note)
	// instead of silently dropping to the guide-less default runner. Empty
	// means degrade straight to the default image.
	FallbackProfile string
}

// IsDefault reports whether p falls back to the configured runner image
// instead of a profile-specific built one.
func (p Profile) IsDefault() bool { return p.Name == "" }

// pm returns a Detect list matching any of the given brief
// package_manager names. Shorthand for the common single-category case.
func pm(names ...string) []BriefMatch {
	return []BriefMatch{{Category: briefPackageManager, Names: names}}
}

// builtinProfiles is the v1 registry. Order matters: first match wins,
// so more specific profiles (php-ext) come before their general
// counterparts (php). Add a new entry plus a Dockerfile under
// docker/profiles/<name>/ to expose a profile.
var builtinProfiles = []Profile{
	{
		// brief's phpize detector looks for PHP_ARG_/PHP_NEW_EXTENSION in
		// config.m4, so an unrelated autoconf file doesn't route here.
		Name:   "php-ext",
		Detect: []BriefMatch{{briefNativeExtension, []string{"phpize"}}},
	},
	{Name: "php", Detect: pm("Composer")},
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
		// rustc for rb-sys shims). brief's mkmf detector keys on extconf.rb,
		// which rb-sys/magnus gems also ship, so a Rust-backed gem still
		// lands here without a separate Cargo.toml check; a pure-Rust crate
		// with no extconf.rb falls through to the rust profile below.
		Name:            "ruby-ext",
		FallbackProfile: "ruby",
		Detect:          []BriefMatch{{briefNativeExtension, []string{"mkmf"}}},
	},
	{
		// Before ruby: a Rails app also gets Brakeman, the Rails-specific
		// SAST, on top of the ruby runtime. Like ruby-ext this is a superset
		// of the ruby profile — it builds FROM the ruby profile image
		// (BaseProfile) and adds Brakeman, so the interpreter is
		// byte-identical with no second from-source compile. brief detects
		// Rails via config/routes.rb, bin/rails, or a `rails` dependency in
		// the Gemfile, so a coincidental config/application.rb in a non-Rails
		// repo does not route here.
		Name:            "ruby-rails",
		BaseProfile:     "ruby",
		FallbackProfile: "ruby",
		Detect:          []BriefMatch{{briefBuild, []string{"Rails"}}},
	},
	{Name: "ruby", Detect: pm("Bundler")},
	{Name: "node", Detect: pm("npm", "pnpm", "Yarn", "Bun")},
	{
		// Before python: brief's setuptools-Extension detector keys on
		// setup.py declaring Extension()/ext_modules or a .pyx file, so
		// route it to the ASan/UBSan interpreter.
		Name:            "python-ext",
		FallbackProfile: "python",
		Detect:          []BriefMatch{{briefNativeExtension, []string{"setuptools Extension"}}},
	},
	{Name: "python", Detect: pm("pip", "Pipenv", "Poetry", "uv", "PDM", "setuptools")},
	{Name: "go", Detect: pm("Go Modules")},
	{Name: "java", Detect: pm("Maven", "Gradle")},
	{Name: "dotnet", Detect: pm("NuGet", "dotnet CLI")},
	{Name: "beam", Detect: pm("Mix", "rebar3")},
	{Name: "rust", Detect: pm("Cargo")},
	{
		// Before c-cpp so a CPAN dist that also commits a generated Makefile,
		// or whose Makefile.PL has already been run, routes here rather than
		// to the native toolchain. brief reports cpanm in package_managers
		// for a repo with cpanfile/Makefile.PL/Build.PL/META.*; the language
		// match is a belt-and-braces for a dist with only *.pl/*.pm.
		Name: "perl",
		Detect: []BriefMatch{
			{briefPackageManager, []string{"cpanm"}},
			{briefLanguage, []string{"Perl"}},
		},
	},
	{
		// Last: brief reports no package manager for plain C/C++, so match
		// on the build tool instead. Language repos that also carry a
		// Makefile match their own package-manager profile first, so this
		// only catches repos that are actually native.
		Name: "c-cpp",
		Detect: []BriefMatch{
			{briefBuild, []string{"CMake", "Make", "Autotools", "Meson"}},
			{briefLanguage, []string{"C", "C++"}},
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

// briefDetections flattens brief's JSON output into category -> lower(name)
// -> true. package_managers and languages become the briefPackageManager /
// briefLanguage categories; every key under tools becomes its own category.
// Unknown JSON is tolerated: an unmarshal error or an absent field yields an
// empty (never nil) map so profile matching degrades to "no match" rather
// than failing the scan.
func briefDetections(out []byte) map[string]map[string]bool {
	type detection struct {
		Name string `json:"name"`
	}
	var r struct {
		PackageManagers []detection            `json:"package_managers"`
		Languages       []detection            `json:"languages"`
		Tools           map[string][]detection `json:"tools"`
	}
	_ = json.Unmarshal(out, &r)
	det := map[string]map[string]bool{}
	add := func(cat, name string) {
		if name == "" {
			return
		}
		if det[cat] == nil {
			det[cat] = map[string]bool{}
		}
		det[cat][strings.ToLower(name)] = true
	}
	for _, d := range r.PackageManagers {
		add(briefPackageManager, d.Name)
	}
	for _, d := range r.Languages {
		add(briefLanguage, d.Name)
	}
	for cat, ds := range r.Tools {
		for _, d := range ds {
			add(cat, d.Name)
		}
	}
	return det
}

// matchProfile returns the first builtinProfiles entry whose Detect list
// is satisfied by the brief output, or the zero Profile if none match.
func matchProfile(briefOut []byte) Profile {
	det := briefDetections(briefOut)
	for _, p := range builtinProfiles {
		if p.matches(det) {
			return p
		}
	}
	return Profile{}
}

// matches reports whether any of p.Detect is satisfied by det. Names are
// compared case-insensitively (det keys are already lowercased).
func (p Profile) matches(det map[string]map[string]bool) bool {
	for _, m := range p.Detect {
		names := det[m.Category]
		for _, want := range m.Names {
			if names[strings.ToLower(want)] {
				return true
			}
		}
	}
	return false
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
		// A brief failure degrades to the default runner image; the scan
		// still runs, without profile-specific tooling.
		return Profile{}
	}
	return matchProfile(out)
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
		// A runner-based profile whose runner digest couldn't be resolved (offline,
		// auth denied, a local-only ref, or podman/Apple without skopeo) keys its
		// tag on the ref string alone, so a moved runner :latest yields the SAME
		// tag and this cached image is reused even though it may sit on a now-stale
		// runner base. Surface that so the otherwise-silent staleness is visible.
		// Chained profiles (BaseProfile set) inherit freshness from the base build
		// and are exempt.
		if p.BaseProfile == "" && baseDigest == "" {
			emit(Event{Kind: KindText, Text: "profile: reusing cached " + tag +
				" but could not verify the runner base is current (" + runnerImage +
				" digest unresolved); if it changed, `" + rt.bin() + " rmi " + tag + "` to force a rebuild"})
		}
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
