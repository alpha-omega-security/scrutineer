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

func TestBuildDockerArgs_ClaudeConfigMount(t *testing.T) {
	d := DockerRunner{}

	with := d.buildDockerArgs("/work/abs", "img:latest", "", "/data/claude-config/scan-7")
	if !hasAdjacent(with, "-v", "/data/claude-config/scan-7:/claude-config") {
		t.Errorf("expected the config dir bind mount in %v", with)
	}
	if !hasAdjacent(with, "-e", "CLAUDE_CONFIG_DIR=/claude-config") {
		t.Errorf("expected CLAUDE_CONFIG_DIR env in %v", with)
	}

	// No config dir → no mount and no env, so default scans are unchanged.
	without := d.buildDockerArgs("/work/abs", "img:latest", "", "")
	for _, a := range without {
		if strings.Contains(a, "/claude-config") || strings.HasPrefix(a, "CLAUDE_CONFIG_DIR=") {
			t.Errorf("did not expect any claude-config args, got %q in %v", a, without)
		}
	}
}

func TestBuildDockerArgs_KeepIDGating(t *testing.T) {
	// --userns=keep-id is the rootless-podman bind-mount ownership fix. It must
	// appear ONLY for rootless podman; docker and rootful podman stay byte-for-
	// byte as before (no --userns token at all), so this also guards against a
	// regression that would silently alter the docker arg vector.
	rootless := DockerRunner{Runtime: ContainerRuntime{Bin: "podman", Rootless: true}}
	if got := rootless.buildDockerArgs("/work/abs", "img:latest", "", ""); !slices.Contains(got, "--userns=keep-id") {
		t.Errorf("rootless podman: expected --userns=keep-id in %v", got)
	}

	for _, d := range []DockerRunner{
		{}, // docker (zero value)
		{Runtime: ContainerRuntime{Bin: "docker"}},
		{Runtime: ContainerRuntime{Bin: "podman"}}, // rootful podman
	} {
		got := d.buildDockerArgs("/work/abs", "img:latest", "", "")
		for _, a := range got {
			if strings.HasPrefix(a, "--userns") {
				t.Errorf("runtime %+v: unexpected %q in %v", d.Runtime, a, got)
			}
		}
	}

	// Rootless podman with a resume config dir keeps BOTH the mount and keep-id
	// so the persisted session store stays host-owned across container restarts.
	withCfg := rootless.buildDockerArgs("/work/abs", "img:latest", "", "/data/cfg/scan-1")
	if !slices.Contains(withCfg, "--userns=keep-id") {
		t.Errorf("rootless+config: expected --userns=keep-id in %v", withCfg)
	}
	if !hasAdjacent(withCfg, "-v", "/data/cfg/scan-1:/claude-config") {
		t.Errorf("rootless+config: expected claude-config mount in %v", withCfg)
	}
}

func TestBuildDockerArgs_SELinuxRelabel(t *testing.T) {
	// With relabeling on, every host bind mount must carry the ":z" shared
	// relabel so the container can access it on an SELinux host.
	on := DockerRunner{SELinuxRelabel: true}
	got := on.buildDockerArgs("/work/abs", "img:latest", "", "/data/cfg/scan-1")
	if !hasAdjacent(got, "-v", "/work/abs:/work:z") {
		t.Errorf("expected /work mount relabeled with :z in %v", got)
	}
	if !hasAdjacent(got, "-v", "/data/cfg/scan-1:/claude-config:z") {
		t.Errorf("expected /claude-config mount relabeled with :z in %v", got)
	}

	// With relabeling off (the zero value / default), mounts are byte-for-byte
	// unchanged -- no :z anywhere -- so non-SELinux hosts are unaffected.
	off := DockerRunner{}
	got = off.buildDockerArgs("/work/abs", "img:latest", "", "/data/cfg/scan-1")
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

func TestBuildDockerArgs_ContainerHardening(t *testing.T) {
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	const tmpfs = "/tmp:rw,noexec,nosuid,size=256m"
	const net = "scrutineer-hardened-9"

	hasNoNewPrivs := func(args []string) bool { return hasAdjacent(args, "--security-opt", "no-new-privileges") }

	// --hardened-rootless-runtime: read-only + no-new-privileges, but NOT the
	// per-scan --internal network -- that network is the part rootless podman
	// can't route to the host proxy, and is the whole reason this flag exists.
	roR := DockerRunner{HardenedRootlessRuntime: true}.buildDockerArgs("/work/abs", "img:latest", net, "")
	if !slices.Contains(roR, "--read-only") || !hasNoNewPrivs(roR) {
		t.Errorf("hardened-rootless-runtime: expected --read-only + no-new-privileges in %v", roR)
	}
	if hasAdjacent(roR, "--network", net) {
		t.Errorf("hardened-rootless-runtime must NOT attach the per-scan --internal network: %v", roR)
	}

	// --hardened: the container hardening AND the per-scan network.
	h := DockerRunner{Hardened: true}.buildDockerArgs("/work/abs", "img:latest", net, "")
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
	def := DockerRunner{}.buildDockerArgs("/work/abs", "img:latest", "", "")
	if slices.Contains(def, "--read-only") || hasNoNewPrivs(def) {
		t.Errorf("default mode must set neither --read-only nor no-new-privileges: %v", def)
	}

	// The baseline -- --cap-drop ALL, non-root --user, the /tmp tmpfs -- is
	// present in EVERY mode; the new flag must not disturb that invariant.
	for _, mode := range []DockerRunner{{}, {HardenedRootlessRuntime: true}, {Hardened: true}} {
		args := mode.buildDockerArgs("/work/abs", "img:latest", net, "")
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

// hasAdjacent reports whether args contains flag immediately followed by val,
// matching how docker run takes `-v host:container` / `-e KEY=VAL` pairs.
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
	// Docker's --filter name= is a substring match, so output can include
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
	// fire before any docker invocation.
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := DockerRunner{Hardened: true}
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
