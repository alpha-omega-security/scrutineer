package worker

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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
