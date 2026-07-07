package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestBuildRunArgs_ClaudeConfigMount(t *testing.T) {
	d := ContainerRunner{}

	with := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/harness-state/scan-7")
	if !hasAdjacent(with, "-v", "/data/harness-state/scan-7:/harness-state") {
		t.Errorf("expected the config dir bind mount in %v", with)
	}
	if !hasAdjacent(with, "-e", "CLAUDE_CONFIG_DIR=/harness-state") {
		t.Errorf("expected CLAUDE_CONFIG_DIR env in %v", with)
	}

	// No config dir → no mount and no env, so default scans are unchanged.
	without := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")
	for _, a := range without {
		if strings.Contains(a, "/harness-state") || strings.HasPrefix(a, "CLAUDE_CONFIG_DIR=") {
			t.Errorf("did not expect any harness-state args, got %q in %v", a, without)
		}
	}
}

func TestBuildRunArgs_KeepIDGating(t *testing.T) {
	// --userns=keep-id is the rootless-podman bind-mount ownership fix. It must
	// appear ONLY for rootless podman; docker and rootful podman stay byte-for-
	// byte as before (no --userns token at all), so this also guards against a
	// regression that would silently alter the container arg vector.
	rootless := ContainerRunner{Runtime: ContainerRuntime{Bin: "podman", Rootless: true}}
	if got := rootless.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, ""); !slices.Contains(got, "--userns=keep-id") {
		t.Errorf("rootless podman: expected --userns=keep-id in %v", got)
	}

	for _, d := range []ContainerRunner{
		{}, // docker (zero value)
		{Runtime: ContainerRuntime{Bin: "docker"}},
		{Runtime: ContainerRuntime{Bin: "podman"}}, // rootful podman
	} {
		got := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")
		for _, a := range got {
			if strings.HasPrefix(a, "--userns") {
				t.Errorf("runtime %+v: unexpected %q in %v", d.Runtime, a, got)
			}
		}
	}

	// Rootless podman with a resume config dir keeps BOTH the mount and keep-id
	// so the persisted session store stays host-owned across container restarts.
	withCfg := rootless.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/cfg/scan-1")
	if !slices.Contains(withCfg, "--userns=keep-id") {
		t.Errorf("rootless+config: expected --userns=keep-id in %v", withCfg)
	}
	if !hasAdjacent(withCfg, "-v", "/data/cfg/scan-1:/harness-state") {
		t.Errorf("rootless+config: expected harness-state mount in %v", withCfg)
	}
}

func TestBuildRunArgs_AppleOmitsDockerOnlyFlags(t *testing.T) {
	d := ContainerRunner{
		Runtime:             ContainerRuntime{Bin: "apple"},
		HardenedRuntimeOnly: true,
	}
	got := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")
	for _, a := range got {
		if a == "--add-host" {
			t.Errorf("apple runtime must not receive Docker/Podman --add-host: %v", got)
		}
		if a == "--security-opt" {
			t.Errorf("apple runtime must not receive unsupported --security-opt: %v", got)
		}
	}
	if !slices.Contains(got, "--read-only") {
		t.Errorf("apple runtime should keep supported read-only rootfs flag: %v", got)
	}
	if !hasAdjacent(got, "--progress", "none") {
		t.Errorf("apple runtime should suppress runtime progress on stdout: %v", got)
	}
}

// TestBuildRunArgs_AppleHardenedProxyTargetsScanGateway covers the subtle part
// of Apple --hardened: with no --add-host to repoint host.docker.internal, the
// proxy env must name THIS scan's --internal gateway (not the default-network
// gateway the startup ProxyURL was built for), while still attaching the
// per-scan network, mounting rootfs read-only, and omitting the unsupported
// docker flags.
func TestBuildRunArgs_AppleHardenedProxyTargetsScanGateway(t *testing.T) {
	d := ContainerRunner{
		Runtime:  ContainerRuntime{Bin: "apple"},
		Hardened: true,
		ProxyURL: "http://scrutineer:tok@192.168.64.1:45000", // startup default-network gateway
	}
	hnet := hardenedNet{name: "scrutineer-hardened-9", gatewayIP: "192.168.128.1"}
	got := d.buildRunArgs("/work/abs", "img:latest", hnet, "")
	joined := strings.Join(got, " ")

	if !strings.Contains(joined, "HTTPS_PROXY=http://scrutineer:tok@192.168.128.1:45000") {
		t.Errorf("apple hardened HTTPS_PROXY should target the per-scan gateway: %v", got)
	}
	if strings.Contains(joined, "192.168.64.1") {
		t.Errorf("apple hardened proxy must not keep the default-network gateway: %v", got)
	}
	if !hasAdjacent(got, "--network", "scrutineer-hardened-9") {
		t.Errorf("apple hardened should attach the per-scan --internal network: %v", got)
	}
	if !slices.Contains(got, "--read-only") {
		t.Errorf("apple hardened should mount rootfs read-only: %v", got)
	}
	for _, a := range got {
		if a == "--add-host" || a == "--security-opt" {
			t.Errorf("apple must not receive %q: %v", a, got)
		}
	}
}

func TestBuildRunArgs_SELinuxRelabel(t *testing.T) {
	// With relabeling on, every host bind mount must carry the ":z" shared
	// relabel so the container can access it on an SELinux host.
	on := ContainerRunner{SELinuxRelabel: true}
	got := on.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/cfg/scan-1")
	if !hasAdjacent(got, "-v", "/work/abs:/work:z") {
		t.Errorf("expected /work mount relabeled with :z in %v", got)
	}
	if !hasAdjacent(got, "-v", "/data/cfg/scan-1:/harness-state:z") {
		t.Errorf("expected /harness-state mount relabeled with :z in %v", got)
	}

	// With relabeling off (the zero value / default), mounts are byte-for-byte
	// unchanged -- no :z anywhere -- so non-SELinux hosts are unaffected.
	off := ContainerRunner{}
	got = off.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/cfg/scan-1")
	if !hasAdjacent(got, "-v", "/work/abs:/work") {
		t.Errorf("expected unrelabeled /work mount in %v", got)
	}
	if !hasAdjacent(got, "-v", "/data/cfg/scan-1:/harness-state") {
		t.Errorf("expected unrelabeled /harness-state mount in %v", got)
	}
	for _, a := range got {
		if strings.HasSuffix(a, ":z") || strings.HasSuffix(a, ",z") {
			t.Errorf("did not expect any :z relabel when SELinuxRelabel is false, got %q in %v", a, got)
		}
	}
}

func TestBuildRunArgs_ContainerHardening(t *testing.T) {
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	const tmpfs = "/tmp:rw,noexec,nosuid,size=256m"
	const net = "scrutineer-hardened-9"

	hasNoNewPrivs := func(args []string) bool { return hasAdjacent(args, "--security-opt", "no-new-privileges") }

	// --hardened-runtime-only: read-only + no-new-privileges, but NOT the
	// per-scan --internal network -- that network is the part rootless podman
	// can't route to the host proxy, and is the whole reason this flag exists.
	roR := ContainerRunner{HardenedRuntimeOnly: true}.buildRunArgs("/work/abs", "img:latest", hardenedNet{name: net}, "")
	if !slices.Contains(roR, "--read-only") || !hasNoNewPrivs(roR) {
		t.Errorf("hardened-rootless-runtime: expected --read-only + no-new-privileges in %v", roR)
	}
	if hasAdjacent(roR, "--network", net) {
		t.Errorf("hardened-rootless-runtime must NOT attach the per-scan --internal network: %v", roR)
	}

	// --hardened: the container hardening AND the per-scan network.
	h := ContainerRunner{Hardened: true}.buildRunArgs("/work/abs", "img:latest", hardenedNet{name: net}, "")
	if !slices.Contains(h, "--read-only") || !hasNoNewPrivs(h) {
		t.Errorf("hardened: expected --read-only + no-new-privileges in %v", h)
	}
	if !hasAdjacent(h, "--network", net) {
		t.Errorf("hardened: expected the per-scan --internal network in %v", h)
	}
	// No-regression guard for --hardened: read-only, no-new-privileges, and the
	// per-scan network must stay one contiguous, correctly-ordered run. Splitting
	// the old single `if d.Hardened` block into two must not reorder or separate
	// them, so --hardened's arg vector is byte-for-byte what it was before.
	if i := slices.Index(h, "--read-only"); i < 0 || i+4 >= len(h) ||
		h[i+1] != "--security-opt" || h[i+2] != "no-new-privileges" ||
		h[i+3] != "--network" || h[i+4] != net {
		t.Errorf("hardened arg order changed (possible regression): %v", h)
	}

	// Default mode: neither container-hardening option (byte-for-byte unchanged).
	def := ContainerRunner{}.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")
	if slices.Contains(def, "--read-only") || hasNoNewPrivs(def) {
		t.Errorf("default mode must set neither --read-only nor no-new-privileges: %v", def)
	}

	// The baseline -- --cap-drop ALL, non-root --user, the /tmp tmpfs -- is
	// present in EVERY mode; the new flag must not disturb that invariant.
	for _, mode := range []ContainerRunner{{}, {HardenedRuntimeOnly: true}, {Hardened: true}} {
		args := mode.buildRunArgs("/work/abs", "img:latest", hardenedNet{name: net}, "")
		if !hasAdjacent(args, "--cap-drop", "ALL") {
			t.Errorf("%+v: missing --cap-drop ALL: %v", mode, args)
		}
		if !hasAdjacent(args, "--user", user) {
			t.Errorf("%+v: missing --user %s: %v", mode, user, args)
		}
		if !hasAdjacent(args, "--tmpfs", tmpfs) {
			t.Errorf("%+v: missing --tmpfs: %v", mode, args)
		}
	}
}

func TestCheckHardenedWorkspace_GatedOnHardeningFlags(t *testing.T) {
	// A small real workspace is under the cap, so every mode passes.
	small := t.TempDir()
	for _, d := range []ContainerRunner{{}, {HardenedRuntimeOnly: true}, {Hardened: true}} {
		if err := d.checkHardenedWorkspace(small); err != nil {
			t.Errorf("%+v: small workspace should pass: %v", d, err)
		}
	}

	// The check must be ACTIVE under both hardening flags and a no-op otherwise.
	// dirSize errors on a missing path, so an active check surfaces that error
	// while a no-op returns nil -- a cheap way to assert the gating without
	// building a 2 GiB tree. This is the cap being folded into rootless hardening.
	missing := filepath.Join(t.TempDir(), "gone")
	if err := (ContainerRunner{}).checkHardenedWorkspace(missing); err != nil {
		t.Errorf("default mode must be a no-op, got %v", err)
	}
	if err := (ContainerRunner{HardenedRuntimeOnly: true}).checkHardenedWorkspace(missing); err == nil {
		t.Error("--hardened-runtime-only must run the workspace cap check")
	}
	if err := (ContainerRunner{Hardened: true}).checkHardenedWorkspace(missing); err == nil {
		t.Error("--hardened must run the workspace cap check")
	}
}

// hasAdjacent reports whether args contains flag immediately followed by val,
// matching how a container `run` takes `-v host:container` / `-e KEY=VAL` pairs.
func hasAdjacent(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

func TestDirSize_SumsRegularFilesAcrossSubdirs(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "nested", "deep")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a"), make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b"), make([]byte, 512), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := dirSize(root)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if n != 1536 {
		t.Errorf("dirSize = %d, want 1536", n)
	}
}

func TestDirSize_ErrorsOnMissingRoot(t *testing.T) {
	// Walk on a missing path returns an error. The hardened cap relies
	// on this propagation to fail closed: an unverifiable workspace
	// must not slip past the size check.
	_, err := dirSize(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("dirSize on missing path returned no error")
	}
}

func TestHardenedNetworkName_UniquePerScanID(t *testing.T) {
	tests := []struct {
		id   uint
		want string
	}{
		{1, "scrutineer-hardened-1"},
		{42, "scrutineer-hardened-42"},
		{4294967295, "scrutineer-hardened-4294967295"},
	}
	for _, tc := range tests {
		if got := hardenedNetworkName(tc.id); got != tc.want {
			t.Errorf("hardenedNetworkName(%d) = %q, want %q", tc.id, got, tc.want)
		}
	}
	if !strings.HasPrefix(hardenedNetworkName(7), hardenedNetworkPrefix) {
		t.Errorf("hardenedNetworkName must start with %q to be sweepable", hardenedNetworkPrefix)
	}
}

func TestParseHardenedNetworkNames_KeepsStrictPrefixOnly(t *testing.T) {
	// The runtime's --filter name= is a substring match, so output can include
	// false positives like a user-named "my-scrutineer-hardened-net". The
	// parser must keep only names that start with the strict prefix.
	in := []byte("\nscrutineer-hardened-1\nscrutineer-hardened-42\nmy-scrutineer-hardened-net\n  \nbridge\n")
	got := parseHardenedNetworkNames(in)
	want := []string{"scrutineer-hardened-1", "scrutineer-hardened-42"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseHardenedNetworkNames = %#v, want %#v", got, want)
	}
}

func TestParseHardenedNetworkNames_EmptyInput(t *testing.T) {
	if got := parseHardenedNetworkNames(nil); len(got) != 0 {
		t.Errorf("parseHardenedNetworkNames(nil) = %#v, want empty", got)
	}
	if got := parseHardenedNetworkNames([]byte("   \n\n")); len(got) != 0 {
		t.Errorf("parseHardenedNetworkNames(whitespace) = %#v, want empty", got)
	}
}

func TestNetworkListNamesArgs(t *testing.T) {
	// Apple's `network list` has neither --filter nor a Go-template --format, so
	// it lists every name with --quiet; docker/podman keep the filtered form.
	if got := networkListNamesArgs(ContainerRuntime{Bin: "apple"}); !slices.Equal(got, []string{"network", "list", "--quiet"}) {
		t.Errorf("apple networkListNamesArgs = %v", got)
	}
	for _, bin := range []string{"docker", "podman"} {
		got := networkListNamesArgs(ContainerRuntime{Bin: bin})
		if !hasAdjacent(got, "--filter", "name="+hardenedNetworkPrefix) || !hasAdjacent(got, "--format", "{{.Name}}") {
			t.Errorf("%s networkListNamesArgs = %v", bin, got)
		}
	}
}

func TestRouteGatewayIPv4_ParsesDefaultGateway(t *testing.T) {
	// The awk filter emits just the default route's gateway hex field, so that
	// single-field line is the only shape this needs to parse.
	if got := routeGatewayIPv4([]byte("0140A8C0\n")); got != "192.168.64.1" {
		t.Errorf("routeGatewayIPv4 = %q, want 192.168.64.1", got)
	}
	if got := routeGatewayIPv4([]byte("")); got != "" {
		t.Errorf("routeGatewayIPv4(empty) = %q, want empty", got)
	}
	if got := routeGatewayIPv4([]byte("nothex\n")); got != "" {
		t.Errorf("routeGatewayIPv4(non-hex) = %q, want empty", got)
	}
}

func TestRunSkill_HardenedRefusesZeroScanID(t *testing.T) {
	// The per-scan network name embeds ScanID. A zero ID collapses every
	// hardened scan onto scrutineer-hardened-0, which silently defeats
	// isolation -- the whole property this code path adds. Guard must
	// fire before any container invocation.
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := ContainerRunner{Hardened: true}
	sj := SkillJob{
		WorkRoot: work,
		Name:     "noop",
		SrcReady: true,
		ScanID:   0,
	}
	_, err := d.RunSkill(context.Background(), sj, func(Event) {})
	if err == nil {
		t.Fatal("RunSkill with Hardened=true and ScanID=0 returned nil error")
	}
	if !strings.Contains(err.Error(), "ScanID") {
		t.Errorf("error %q does not mention ScanID", err)
	}
}

func TestDirSize_IgnoresIrregularEntries(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), make([]byte, 256), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(root, "link")); err != nil {
		// Symlink creation can fail on filesystems that don't support
		// it; skip rather than fail since the assertion below covers
		// the regular-file case either way.
		t.Skipf("symlink not supported: %v", err)
	}
	n, err := dirSize(root)
	if err != nil {
		t.Fatalf("dirSize: %v", err)
	}
	if n != 256 {
		t.Errorf("dirSize = %d, want 256 (symlinks must not be counted)", n)
	}
}

func TestHardenedProbeArgs(t *testing.T) {
	docker := ContainerRuntime{Bin: "docker"}
	apple := ContainerRuntime{Bin: "apple"}

	// The block probe is security-load-bearing: it must run on the per-scan
	// internal network, carry no proxy env (or it would test the proxy path
	// instead of raw egress), hit a literal IP (so a pass is not just blocked
	// DNS), and guard against a curl-less image.
	block := docker.hardenedEgressBlockArgs("scrutineer-hardened-7", "img:latest")
	if !hasAdjacent(block, "--network", "scrutineer-hardened-7") {
		t.Errorf("block probe missing --network: %v", block)
	}
	if !hasAdjacent(block, "--cap-drop", "ALL") {
		t.Errorf("block probe missing --cap-drop ALL: %v", block)
	}
	for _, a := range block {
		if strings.Contains(a, "HTTPS_PROXY") || strings.Contains(a, "HTTP_PROXY") {
			t.Errorf("block probe must not set proxy env: %v", block)
		}
	}
	joined := strings.Join(block, " ")
	if !strings.Contains(joined, "1.1.1.1") {
		t.Errorf("block probe should hit a literal IP: %v", block)
	}
	if !strings.Contains(joined, "NOCURL") {
		t.Errorf("block probe should guard against missing curl: %v", block)
	}

	// docker/podman reach probe wires the gateway alias the same way the real
	// run does and targets the proxy port through that alias.
	reach := docker.hardenedProxyReachArgs("scrutineer-hardened-7", "192.0.2.5", "54321", "img:latest")
	if !hasAdjacent(reach, "--network", "scrutineer-hardened-7") {
		t.Errorf("reach probe missing --network: %v", reach)
	}
	if !hasAdjacent(reach, "--add-host", HostGatewayAlias+":192.0.2.5") {
		t.Errorf("reach probe missing gateway add-host: %v", reach)
	}
	if !strings.Contains(strings.Join(reach, " "), HostGatewayAlias+":54321") {
		t.Errorf("reach probe should target the proxy port via the alias: %v", reach)
	}

	// Apple has no --add-host: the block probe still suppresses lifecycle
	// progress, and the reach probe targets the resolved gateway IP:port
	// directly (the same address buildRunArgs points the proxy env at).
	appleBlock := apple.hardenedEgressBlockArgs("scrutineer-hardened-7", "img:latest")
	if !hasAdjacent(appleBlock, "--progress", "none") {
		t.Errorf("apple block probe should suppress progress: %v", appleBlock)
	}
	appleReach := apple.hardenedProxyReachArgs("scrutineer-hardened-7", "192.168.128.1", "54321", "img:latest")
	for _, a := range appleReach {
		if a == "--add-host" {
			t.Errorf("apple reach probe must not use --add-host: %v", appleReach)
		}
	}
	if !hasAdjacent(appleReach, "--progress", "none") {
		t.Errorf("apple reach probe should suppress progress: %v", appleReach)
	}
	if !strings.Contains(strings.Join(appleReach, " "), "192.168.128.1:54321") {
		t.Errorf("apple reach probe should target the gateway IP:port directly: %v", appleReach)
	}
}

func TestProxyPortFromURL(t *testing.T) {
	if port, err := proxyPortFromURL("http://scrutineer:tok@host.docker.internal:54321"); err != nil || port != "54321" {
		t.Errorf("proxyPortFromURL = %q,%v; want 54321,nil", port, err)
	}
	if _, err := proxyPortFromURL("http://host.docker.internal"); err == nil {
		t.Error("expected error for URL without a port")
	}
	if _, err := proxyPortFromURL("://bad"); err == nil {
		t.Error("expected error for malformed URL")
	}
}

func TestRedactURLUserinfo(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"https://proxy.example.com/v1", "https://proxy.example.com/v1"},
		{"https://user:secret@proxy.example.com/v1", "https://REDACTED@proxy.example.com/v1"},
		{"https://onlyuser@proxy.example.com/v1", "https://REDACTED@proxy.example.com/v1"},
		{"not a url", "not a url"},
		{"", ""},
	}
	for _, c := range cases {
		got := redactURLUserinfo(c.in)
		if got != c.want {
			t.Errorf("redactURLUserinfo(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResolveProfile_SubPath(t *testing.T) {
	d := ContainerRunner{ProfilesDir: t.TempDir()} // Provide a ProfilesDir so it doesn't short-circuit

	work := t.TempDir()
	sub := filepath.Join(work, "nested", "php-ext")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	// The php-ext profile detects config.m4 containing PHP_ARG_
	if err := os.WriteFile(filepath.Join(sub, "config.m4"), []byte("PHP_ARG_"), 0o600); err != nil {
		t.Fatal(err)
	}

	var events []Event
	emit := func(e Event) { events = append(events, e) }

	// 1. Root path should NOT match php-ext (will default or fallback)
	d.resolveProfile(context.Background(), "", work, "", emit)

	matchedPhpExtAtRoot := false
	for _, e := range events {
		if strings.Contains(e.Text, "profile: php-ext") {
			matchedPhpExtAtRoot = true
		}
	}
	if matchedPhpExtAtRoot {
		t.Errorf("expected no php-ext profile match at root")
	}

	events = nil // clear

	// 2. SubPath should match php-ext
	d.resolveProfile(context.Background(), "", work, "nested/php-ext", emit)

	matchedPhpExtInSubPath := false
	for _, e := range events {
		if strings.Contains(e.Text, "profile: php-ext") {
			matchedPhpExtInSubPath = true
		}
	}
	if !matchedPhpExtInSubPath {
		t.Errorf("expected php-ext profile match using subPath")
	}
}

// TestResolveProfile_DegradesToFallback exercises the FallbackProfile degrade
// loop: when a profile's own image can't be built, the scan must continue under
// its fallback rather than the guide-less default runner. ruby-ext ships no
// Dockerfile here, so EnsureImage fails the read before it touches the runtime;
// ruby's Dockerfile is present, and a stub docker whose `image inspect` exits 0
// lets ruby resolve from cache with no real build. resolveProfile should log the
// fallback and hand back the ruby profile, not the default.
func TestResolveProfile_DegradesToFallback(t *testing.T) {
	// This drives ruby-ext -> ruby specifically; fail loudly if the registry
	// wiring the test depends on ever changes.
	if got := ProfileByName("ruby-ext").FallbackProfile; got != "ruby" {
		t.Fatalf("test assumes ruby-ext falls back to ruby; registry now says %q", got)
	}

	profiles := t.TempDir()
	// The fallback (ruby) ships a Dockerfile; the first profile (ruby-ext) does
	// not, so its EnsureImage fails the read before any runtime call.
	if err := os.MkdirAll(filepath.Join(profiles, "ruby"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profiles, "ruby", "Dockerfile"), []byte("FROM scratch\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Stub docker: `image inspect` exits 0 so ruby resolves from the local cache
	// (no real build); anything else (e.g. resolveBaseDigest's `buildx`) exits
	// non-zero, which the callers already treat as a soft miss.
	binDir := t.TempDir()
	stub := "#!/bin/sh\n[ \"$1\" = \"image\" ] && exit 0\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	d := ContainerRunner{ProfilesDir: profiles} // default Bin "docker" resolves to the stub

	var events []Event
	emit := func(e Event) { events = append(events, e) }

	// Request ruby-ext explicitly to skip detection and drive the build directly.
	name, _ := d.resolveProfile(context.Background(), "ruby-ext", t.TempDir(), "", emit)

	if name != "ruby" {
		t.Errorf("resolveProfile returned profile %q, want the ruby fallback", name)
	}
	var loggedFallback bool
	for _, e := range events {
		if strings.Contains(e.Text, "falling back to ruby") {
			loggedFallback = true
		}
	}
	if !loggedFallback {
		t.Errorf("expected a %q log line; got events %v", "falling back to ruby", events)
	}
}

func TestUsesEgressSidecar(t *testing.T) {
	// The egress proxy sidecar is for exactly one configuration: rootless podman
	// under --hardened, where the --internal network can't reach the host proxy.
	// Everything else keeps the host-proxy path.
	rootlessHardened := ContainerRunner{Hardened: true, Runtime: ContainerRuntime{Bin: "podman", Rootless: true}}
	if !rootlessHardened.usesEgressSidecar() {
		t.Error("rootless podman + --hardened must use the egress sidecar")
	}
	for _, d := range []ContainerRunner{
		{Hardened: true}, // docker hardened -> host proxy
		{Hardened: true, Runtime: ContainerRuntime{Bin: "podman"}},     // rootful podman hardened
		{Hardened: true, Runtime: ContainerRuntime{Bin: runtimeApple}}, // apple hardened -> host proxy, NOT a sidecar
		{Runtime: ContainerRuntime{Bin: "podman", Rootless: true}},     // rootless but not hardened
		{Runtime: ContainerRuntime{Bin: "docker"}},                     // docker, not hardened
	} {
		if d.usesEgressSidecar() {
			t.Errorf("did not expect a sidecar for %+v", d)
		}
	}
}

func TestProxySidecarRunArgs(t *testing.T) {
	d := ContainerRunner{
		Runtime:  ContainerRuntime{Bin: "podman", Rootless: true},
		Hardened: true,
		Egress: EgressSidecarConfig{
			Token:     "tok",
			Allow:     []string{"*.anthropic.com", "host.docker.internal"},
			APIPort:   "8080",
			GatewayIP: "192.0.2.9",
		},
	}
	args := d.proxySidecarRunArgs("scrutineer-proxy-7", "scrutineer-hardened-7")

	// Detached and locked down -- the sidecar runs scrutineer's own trusted code
	// but gets the same defense-in-depth as the scan container.
	if !slices.Contains(args, "-d") {
		t.Errorf("sidecar must be detached: %v", args)
	}
	if slices.Contains(args, "--rm") {
		t.Errorf("sidecar must NOT use --rm, or its logs vanish on an early exit: %v", args)
	}
	if !hasAdjacent(args, "--name", "scrutineer-proxy-7") {
		t.Errorf("missing --name: %v", args)
	}
	if !hasAdjacent(args, "--cap-drop", "ALL") || !hasAdjacent(args, "--security-opt", "no-new-privileges") || !slices.Contains(args, "--read-only") {
		t.Errorf("sidecar not locked down: %v", args)
	}
	// Host-gateway wired to the resolved IPv4 so it can reach the host skill API.
	if !hasAdjacent(args, "--add-host", HostGatewayAlias+":192.0.2.9") {
		t.Errorf("missing host-gateway add-host: %v", args)
	}
	// Must start on the per-scan --internal network so it is the sidecar's
	// FIRST interface -- the one the first-iface listen keyword binds to. The
	// default bridge (egress leg) is connected by startProxySidecar afterwards
	// and must never appear here, or the listener would face it.
	if !hasAdjacent(args, "--network", "scrutineer-hardened-7") {
		t.Errorf("sidecar must start on the per-scan --internal network: %v", args)
	}
	if hasAdjacent(args, "--network", "podman") {
		t.Errorf("the egress leg must be connected after launch, not at run time: %v", args)
	}
	// Config via env; the listen host is the keyword the sidecar resolves to its
	// --internal leg, not an all-interfaces bind.
	for _, kv := range []string{
		"SCRUTINEER_PROXY_TOKEN=tok",
		"SCRUTINEER_PROXY_ALLOW=*.anthropic.com,host.docker.internal",
		"SCRUTINEER_PROXY_API_HOST=192.0.2.9",
		"SCRUTINEER_PROXY_API_PORT=8080",
		"SCRUTINEER_PROXY_LISTEN=" + SidecarListenFirstIface + ":3128",
	} {
		if !hasAdjacent(args, "-e", kv) {
			t.Errorf("missing env %q in %v", kv, args)
		}
	}
	// Runs the DEFAULT runner image (which carries the scrutineer binary), then
	// `scrutineer proxy`. The tail must be: -- <image> scrutineer proxy.
	tail := args[len(args)-4:]
	if !reflect.DeepEqual(tail, []string{"--", DefaultRunnerImage, "scrutineer", "proxy"}) {
		t.Errorf("sidecar command tail = %v, want -- %s scrutineer proxy", tail, DefaultRunnerImage)
	}
	// No host bind mounts and no keep-id: the sidecar touches no host files.
	for _, a := range args {
		if a == "-v" || strings.HasPrefix(a, "--userns") {
			t.Errorf("sidecar must not bind-mount or keep-id: %q in %v", a, args)
		}
	}
}

func TestNoteworthyProxyLogLine(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`time=2026-06-27T00:00:00Z level=WARN msg="egress denied" method=CONNECT host=evil.test`, true},
		{`time=2026-06-27T00:00:00Z level=ERROR msg="something broke"`, true},
		{`time=2026-06-27T00:00:00Z level=INFO msg="egress proxy listening" addr=:3128`, false},
		{`time=2026-06-27T00:00:00Z level=INFO msg="egress proxy: waiting for host skill API"`, false},
		{"", false},
	}
	for _, c := range cases {
		if got := noteworthyProxyLogLine(c.line); got != c.want {
			t.Errorf("noteworthyProxyLogLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

func TestEmitProxyLogLines(t *testing.T) {
	// Capture-on-teardown must surface the sidecar's denials/failures into the
	// scan record but drop routine INFO chatter, each prefixed so it's traceable.
	out := []byte(strings.Join([]string{
		`time=t level=INFO msg="egress proxy listening" addr=:3128`,
		`time=t level=WARN msg="egress denied" method=CONNECT host=evil.test`,
		``,
		`time=t level=ERROR msg="upstream unreachable"`,
		`time=t level=INFO msg="waiting for host skill API"`,
	}, "\n"))

	var got []string
	emitProxyLogLines(out, func(e Event) {
		if e.Kind != KindText {
			t.Errorf("unexpected event kind %v", e.Kind)
		}
		got = append(got, e.Text)
	})

	want := []string{
		`egress-proxy: time=t level=WARN msg="egress denied" method=CONNECT host=evil.test`,
		`egress-proxy: time=t level=ERROR msg="upstream unreachable"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("emitProxyLogLines emitted\n  %v\nwant\n  %v", got, want)
	}
}

func TestVerifyProxyBinary_NoopWhenImageAbsent(t *testing.T) {
	// The smoke test must never block startup when there is no image to run: an
	// empty image short-circuits, and an image not present locally is skipped
	// (the first scan pulls it and would surface any problem then). Both return
	// nil without depending on a runtime being installed.
	if err := VerifyProxyBinary(context.Background(), ContainerRuntime{Bin: "docker"}, ""); err != nil {
		t.Errorf("empty image must be a no-op, got %v", err)
	}
	if err := VerifyProxyBinary(context.Background(), ContainerRuntime{Bin: "docker"}, "scrutineer-nonexistent-test-image:does-not-exist"); err != nil {
		t.Errorf("absent image must be a no-op, got %v", err)
	}
}

func TestStartProxySidecar_RequiresGatewayIP(t *testing.T) {
	// An unresolved host-gateway means the sidecar cannot reach the host API, so
	// the scan must be refused before any container is launched (fail closed).
	d := ContainerRunner{
		Runtime:  ContainerRuntime{Bin: "podman", Rootless: true},
		Hardened: true,
		Egress:   EgressSidecarConfig{Token: "t", Allow: []string{"x"}, APIPort: "8080"}, // GatewayIP empty
	}
	if _, _, err := d.startProxySidecar(SkillJob{ScanID: 7}, "scrutineer-hardened-7"); err == nil {
		t.Fatal("expected an error when the host-gateway IPv4 is unresolved")
	}
}

func TestSidecarReachArgs(t *testing.T) {
	// Probe (b), sidecar variant: curl the sidecar by IP:port on the --internal
	// network (that network is --disable-dns, so the scan reaches it by IP, not by
	// name); no --add-host.
	args := sidecarReachArgs("scrutineer-hardened-7", "10.89.1.2:3128", "img:latest")
	if !hasAdjacent(args, "--network", "scrutineer-hardened-7") {
		t.Errorf("missing --network: %v", args)
	}
	if !hasAdjacent(args, "--cap-drop", "ALL") {
		t.Errorf("missing --cap-drop ALL: %v", args)
	}
	for _, a := range args {
		if a == "--add-host" {
			t.Errorf("sidecar reach probe must not wire --add-host: %v", args)
		}
	}
	if !strings.Contains(strings.Join(args, " "), "http://10.89.1.2:3128/") {
		t.Errorf("reach probe should curl the sidecar endpoint: %v", args)
	}
}

func TestBuildRunArgs_SidecarProxyURL(t *testing.T) {
	// In sidecar mode HTTPS_PROXY points at the sidecar by IP on the --internal
	// network, built per-scan from the endpoint -- NOT the process-wide host
	// proxy URL, which must not leak into the scan.
	d := ContainerRunner{
		Hardened: true,
		Runtime:  ContainerRuntime{Bin: "podman", Rootless: true},
		ProxyURL: "http://scrutineer:tok@host.docker.internal:55000",
		Egress:   EgressSidecarConfig{Token: "tok"},
	}
	hn := hardenedNet{name: "scrutineer-hardened-7", proxyEndpoint: "10.89.1.2:3128", proxyName: "scrutineer-proxy-7"}
	args := d.buildRunArgs("/work/abs", "img:latest", hn, "")

	const want = "http://scrutineer:tok@10.89.1.2:3128"
	for _, env := range []string{"HTTPS_PROXY=" + want, "HTTP_PROXY=" + want, "ALL_PROXY=" + want} {
		if !hasAdjacent(args, "-e", env) {
			t.Errorf("expected sidecar %s in %v", env, args)
		}
	}
	for _, a := range args {
		if strings.Contains(a, "host.docker.internal:55000") {
			t.Errorf("host-proxy URL leaked into a sidecar scan: %q", a)
		}
	}
	// The scan still attaches the per-scan --internal network.
	if !hasAdjacent(args, "--network", "scrutineer-hardened-7") {
		t.Errorf("missing per-scan --internal network: %v", args)
	}
}

func TestBuildRunArgs_HostProxyURLWhenNoSidecar(t *testing.T) {
	// With no sidecar endpoint the scan uses the process-wide host proxy URL,
	// exactly as docker/rootful hardened and non-hardened scans do today.
	d := ContainerRunner{ProxyURL: "http://scrutineer:tok@host.docker.internal:55000"}
	args := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")
	if !hasAdjacent(args, "-e", "HTTPS_PROXY=http://scrutineer:tok@host.docker.internal:55000") {
		t.Errorf("expected the host proxy URL in %v", args)
	}
}

func TestHardenedNetworkCreateArgs(t *testing.T) {
	args := hardenedNetworkCreateArgs("scrutineer-hardened-9")
	// --internal isolates egress; --disable-dns keeps the network's non-forwarding
	// resolver out of any connected sidecar (it would NXDOMAIN external lookups and
	// shadow the sidecar's working bridge resolver).
	if !slices.Contains(args, "--internal") {
		t.Errorf("missing --internal: %v", args)
	}
	if !slices.Contains(args, "--disable-dns") {
		t.Errorf("missing --disable-dns: %v", args)
	}
	// The name comes last, after "--", so it can never be read as a flag.
	if tail := args[len(args)-2:]; tail[0] != "--" || tail[1] != "scrutineer-hardened-9" {
		t.Errorf("name must be the final arg after --: %v", args)
	}
}

func TestProxySidecarName_UniquePerScanID(t *testing.T) {
	if a, b := proxySidecarName(1), proxySidecarName(2); a == b {
		t.Errorf("names collided: %q == %q", a, b)
	}
	if got := proxySidecarName(7); got != "scrutineer-proxy-7" {
		t.Errorf("proxySidecarName(7) = %q, want scrutineer-proxy-7", got)
	}
}

func TestParseProxySidecarNames_KeepsStrictPrefixOnly(t *testing.T) {
	out := []byte("scrutineer-proxy-1\nscrutineer-proxy-42\nmy-scrutineer-proxy-x\nunrelated\n\n")
	got := parseProxySidecarNames(out)
	want := []string{"scrutineer-proxy-1", "scrutineer-proxy-42"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseProxySidecarNames = %v, want %v", got, want)
	}
	if names := parseProxySidecarNames([]byte("   \n")); names != nil {
		t.Errorf("empty input should yield nil, got %v", names)
	}
}
