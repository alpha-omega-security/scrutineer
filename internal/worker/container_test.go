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

	with := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/claude-config/scan-7")
	if !hasAdjacent(with, "-v", "/data/claude-config/scan-7:/claude-config") {
		t.Errorf("expected the config dir bind mount in %v", with)
	}
	if !hasAdjacent(with, "-e", "CLAUDE_CONFIG_DIR=/claude-config") {
		t.Errorf("expected CLAUDE_CONFIG_DIR env in %v", with)
	}

	// No config dir → no mount and no env, so default scans are unchanged.
	without := d.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "")
	for _, a := range without {
		if strings.Contains(a, "/claude-config") || strings.HasPrefix(a, "CLAUDE_CONFIG_DIR=") {
			t.Errorf("did not expect any claude-config args, got %q in %v", a, without)
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
	if !hasAdjacent(withCfg, "-v", "/data/cfg/scan-1:/claude-config") {
		t.Errorf("rootless+config: expected claude-config mount in %v", withCfg)
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
	if !hasAdjacent(got, "-v", "/data/cfg/scan-1:/claude-config:z") {
		t.Errorf("expected /claude-config mount relabeled with :z in %v", got)
	}

	// With relabeling off (the zero value / default), mounts are byte-for-byte
	// unchanged -- no :z anywhere -- so non-SELinux hosts are unaffected.
	off := ContainerRunner{}
	got = off.buildRunArgs("/work/abs", "img:latest", hardenedNet{}, "/data/cfg/scan-1")
	if !hasAdjacent(got, "-v", "/work/abs:/work") {
		t.Errorf("expected unrelabeled /work mount in %v", got)
	}
	if !hasAdjacent(got, "-v", "/data/cfg/scan-1:/claude-config") {
		t.Errorf("expected unrelabeled /claude-config mount in %v", got)
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

	// --hardened-rootless-runtime: read-only + no-new-privileges, but NOT the
	// per-scan --internal network -- that network is the part rootless podman
	// can't route to the host proxy, and is the whole reason this flag exists.
	roR := ContainerRunner{HardenedRootlessRuntime: true}.buildRunArgs("/work/abs", "img:latest", hardenedNet{name: net}, "")
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
	for _, mode := range []ContainerRunner{{}, {HardenedRootlessRuntime: true}, {Hardened: true}} {
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
	for _, d := range []ContainerRunner{{}, {HardenedRootlessRuntime: true}, {Hardened: true}} {
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
	if err := (ContainerRunner{HardenedRootlessRuntime: true}).checkHardenedWorkspace(missing); err == nil {
		t.Error("--hardened-rootless-runtime must run the workspace cap check")
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
	// The block probe is security-load-bearing: it must run on the per-scan
	// internal network, carry no proxy env (or it would test the proxy path
	// instead of raw egress), hit a literal IP (so a pass is not just blocked
	// DNS), and guard against a curl-less image.
	block := hardenedEgressBlockArgs("scrutineer-hardened-7", "img:latest")
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

	// The reach probe must wire the gateway alias the same way the real run
	// does and target the proxy port through that alias.
	reach := hardenedProxyReachArgs("scrutineer-hardened-7", "192.0.2.5", "54321", "img:latest")
	if !hasAdjacent(reach, "--network", "scrutineer-hardened-7") {
		t.Errorf("reach probe missing --network: %v", reach)
	}
	if !hasAdjacent(reach, "--add-host", HostGatewayAlias+":192.0.2.5") {
		t.Errorf("reach probe missing gateway add-host: %v", reach)
	}
	if !strings.Contains(strings.Join(reach, " "), HostGatewayAlias+":54321") {
		t.Errorf("reach probe should target the proxy port via the alias: %v", reach)
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
