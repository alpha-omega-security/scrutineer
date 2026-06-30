package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"scrutineer/internal/config"
	"scrutineer/internal/worker"
)

func fullConfig() *config.Config {
	return &config.Config{
		Addr:             "0.0.0.0:9090",
		Data:             "/var/lib/scrutineer",
		Effort:           "medium",
		NoContainer:      new(true),
		Hardened:         new(true),
		RunnerImage:      "custom:v1",
		SkillsRepo:       "https://example.com/skills.git",
		Skills:           []string{"/etc/skills"},
		Concurrency:      8,
		Clone:            "full",
		ScanTimeout:      "30m",
		MaxTurns:         200,
		AnthropicBaseURL: "https://proxy.corp.com/v1",
		ForkOrg:          "fork-central",
	}
}

func TestFlagsMerge_configFillsUnset(t *testing.T) {
	cfg := fullConfig()
	f := &flags{addr: "127.0.0.1:8080", cloneMode: "shallow", set: map[string]bool{}}
	f.merge(cfg)
	if f.addr != cfg.Addr {
		t.Errorf("addr = %q, want %q", f.addr, cfg.Addr)
	}
	if f.dataDir != cfg.Data {
		t.Errorf("dataDir = %q", f.dataDir)
	}
	if !f.noContainer {
		t.Errorf("noContainer not applied")
	}
	if !f.hardened {
		t.Errorf("hardened not applied")
	}
	if f.concurrency != 8 {
		t.Errorf("concurrency = %d", f.concurrency)
	}
	if !f.fullClone() {
		t.Errorf("cloneMode = %q, want full", f.cloneMode)
	}
	if len(f.skillLocal) != 1 || f.skillLocal[0] != "/etc/skills" {
		t.Errorf("skillLocal = %v", f.skillLocal)
	}
	if f.scanTimeout != 30*time.Minute {
		t.Errorf("scanTimeout = %v", f.scanTimeout)
	}
	if f.maxTurns != 200 {
		t.Errorf("maxTurns = %d", f.maxTurns)
	}
	if f.anthropicBaseURL != cfg.AnthropicBaseURL {
		t.Errorf("anthropicBaseURL = %q, want %q", f.anthropicBaseURL, cfg.AnthropicBaseURL)
	}
	if f.forkOrg != cfg.ForkOrg {
		t.Errorf("forkOrg = %q, want %q", f.forkOrg, cfg.ForkOrg)
	}
}

func TestFlagsMerge_cliFlagWins(t *testing.T) {
	cfg := fullConfig()
	f := &flags{
		addr: "127.0.0.1:8080", cloneMode: "shallow", concurrency: 2,
		anthropicBaseURL: "https://my-flag.example.com/v1",
		set:              map[string]bool{"addr": true, "clone": true, "concurrency": true, "anthropic-base-url": true},
	}
	f.merge(cfg)
	if f.addr != "127.0.0.1:8080" {
		t.Errorf("addr overridden despite explicit flag: %q", f.addr)
	}
	if f.cloneMode != "shallow" {
		t.Errorf("cloneMode overridden despite explicit flag: %q", f.cloneMode)
	}
	if f.concurrency != 2 {
		t.Errorf("concurrency overridden despite explicit flag: %d", f.concurrency)
	}
	// effort wasn't in set, so config still applies
	if f.effort != cfg.Effort {
		t.Errorf("effort = %q, want %q", f.effort, cfg.Effort)
	}
	if f.anthropicBaseURL != "https://my-flag.example.com/v1" {
		t.Errorf("anthropicBaseURL overridden despite explicit flag: %q", f.anthropicBaseURL)
	}
}

func TestFlagsMerge_zeroConfigLeavesDefaults(t *testing.T) {
	f := &flags{addr: "127.0.0.1:8080", concurrency: 4, scanTimeout: time.Hour, set: map[string]bool{}}
	f.merge(&config.Config{})
	if f.addr != "127.0.0.1:8080" {
		t.Errorf("empty config clobbered addr: %q", f.addr)
	}
	if f.concurrency != 4 {
		t.Errorf("zero concurrency clobbered default: %d", f.concurrency)
	}
	if f.scanTimeout != time.Hour {
		t.Errorf("empty scan_timeout clobbered default: %v", f.scanTimeout)
	}
	if f.anthropicBaseURL != "" {
		t.Errorf("empty config set anthropicBaseURL: %q", f.anthropicBaseURL)
	}
}

func TestFlagsMerge_hardenedCliWinsOverConfig(t *testing.T) {
	// CLI hardened=false must not be overridden by config hardened:true.
	cfg := &config.Config{Hardened: new(true)}
	f := &flags{set: map[string]bool{"hardened": true}}
	f.merge(cfg)
	if f.hardened {
		t.Errorf("CLI --hardened=false was overridden by config")
	}
}

func TestFlagsMerge_legacyNoDockerFlagHonored(t *testing.T) {
	// The pre-rename --no-docker alias must behave exactly like --no-container:
	// passing it on the CLI suppresses a conflicting config value. Both flags
	// bind to the same variable, and merge checks both set-keys.
	cfg := &config.Config{NoContainer: new(false)} // config wants the container ON
	f := &flags{noContainer: true, set: map[string]bool{"no-docker": true}}
	f.merge(cfg)
	if !f.noContainer {
		t.Error("legacy --no-docker on the CLI was overridden by config; the alias must win like --no-container")
	}
}

func TestRegisterFlags_noContainerAliasParsesFromArgv(t *testing.T) {
	// Both the canonical --no-container and the deprecated --no-docker alias
	// must parse off the command line and set the same noContainer field, so
	// existing `scrutineer --no-docker ...` invocations keep working.
	for _, name := range []string{"--no-container", "--no-docker"} {
		f := &flags{}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		registerFlags(fs, f)
		if err := fs.Parse([]string{name}); err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		if !f.noContainer {
			t.Errorf("%s did not set noContainer", name)
		}
	}
}

func TestRegisterFlags_hardenedRuntimeOnlyAliasParsesFromArgv(t *testing.T) {
	// Both the canonical --hardened-runtime-only and the deprecated
	// --hardened-rootless-runtime alias must parse off the command line and set
	// the same hardenedRuntimeOnly field, so existing
	// `scrutineer --hardened-rootless-runtime ...` invocations keep working.
	for _, name := range []string{"--hardened-runtime-only", "--hardened-rootless-runtime"} {
		f := &flags{}
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		registerFlags(fs, f)
		if err := fs.Parse([]string{name}); err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		if !f.hardenedRuntimeOnly {
			t.Errorf("%s did not set hardenedRuntimeOnly", name)
		}
	}
}

func TestFlagsMerge_hardenedRuntimeOnlyConfigAlias(t *testing.T) {
	// The deprecated hardened_rootless_runtime config key still applies when the
	// canonical hardened_runtime_only is absent.
	legacy := &flags{}
	legacy.merge(&config.Config{HardenedRootlessRuntime: new(true)})
	if !legacy.hardenedRuntimeOnly {
		t.Error("deprecated config hardened_rootless_runtime was ignored")
	}
	// The canonical key takes precedence over the deprecated alias.
	both := &flags{}
	both.merge(&config.Config{HardenedRuntimeOnly: new(false), HardenedRootlessRuntime: new(true)})
	if both.hardenedRuntimeOnly {
		t.Error("hardened_runtime_only should take precedence over hardened_rootless_runtime")
	}
}

func TestBuildEgressAllow_defaultIncludesConfigAndAnthropicHost(t *testing.T) {
	cfg := &config.Config{EgressAllow: []string{"artifactory.internal", "*.mycorp.net"}}
	allow := buildEgressAllow(worker.ClaudeHarness{}.EgressHosts(), false, cfg, "https://proxy.corp.com/v1", quietLog())

	if !slices.Contains(allow, "*.anthropic.com") {
		t.Errorf("default mode dropped harness egress hosts: %v", allow)
	}
	if !slices.Contains(allow, "*.ecosyste.ms") {
		t.Errorf("default mode dropped DefaultEgressAllow entries: %v", allow)
	}
	if !slices.Contains(allow, "artifactory.internal") || !slices.Contains(allow, "*.mycorp.net") {
		t.Errorf("default mode did not honour egress_allow: %v", allow)
	}
	if !slices.Contains(allow, "proxy.corp.com") {
		t.Errorf("default mode did not auto-add anthropic base URL host: %v", allow)
	}
}

func TestBuildEgressAllow_hardenedDropsConfigKeepsHarness(t *testing.T) {
	cfg := &config.Config{EgressAllow: []string{"artifactory.internal"}}
	allow := buildEgressAllow(worker.ClaudeHarness{}.EgressHosts(), true, cfg, "https://proxy.corp.com/v1", quietLog())

	if slices.Contains(allow, "*.ecosyste.ms") {
		t.Errorf("hardened leaked DefaultEgressAllow entries: %v", allow)
	}
	if slices.Contains(allow, "artifactory.internal") {
		t.Errorf("hardened honoured egress_allow when it must not: %v", allow)
	}
	if !slices.Contains(allow, "*.anthropic.com") {
		t.Errorf("hardened did not include the harness egress hosts: %v", allow)
	}
	if !slices.Contains(allow, worker.HostGatewayAlias) {
		t.Errorf("hardened did not include HardenedEgressAllow entries: %v", allow)
	}
	if !slices.Contains(allow, "proxy.corp.com") {
		t.Errorf("hardened dropped the anthropic base URL host: %v", allow)
	}
}

func TestBuildEgressAllow_hardenedNilConfig(t *testing.T) {
	harnessHosts := worker.ClaudeHarness{}.EgressHosts()
	allow := buildEgressAllow(harnessHosts, true, nil, "", quietLog())
	if len(allow) != len(harnessHosts)+len(worker.HardenedEgressAllow) {
		t.Errorf("hardened minimal allow = %v, want exactly harness hosts + HardenedEgressAllow", allow)
	}
}

func TestBuildEgressAllow_nonClaudeHarnessExcludesAnthropic(t *testing.T) {
	// A non-claude harness must not inherit *.anthropic.com from the
	// static lists; only the hosts it declares are added.
	allow := buildEgressAllow([]string{"api.openai.com"}, true, nil, "", quietLog())
	if slices.Contains(allow, "*.anthropic.com") {
		t.Errorf("non-claude harness allowlist still contains anthropic: %v", allow)
	}
	if !slices.Contains(allow, "api.openai.com") {
		t.Errorf("non-claude harness hosts not included: %v", allow)
	}
}

func TestResolveEgressSidecar_NoSidecarForNonRootless(t *testing.T) {
	// docker, rootful podman, and the zero (docker) runtime keep the in-process
	// host proxy: resolveEgressSidecar returns the zero config (no sidecar), and
	// without probing for a gateway. Only rootless podman gets a sidecar, which
	// is covered end to end by the podman integration test.
	f := &flags{addr: "127.0.0.1:8080", runnerImage: "img"}
	for _, rt := range []worker.ContainerRuntime{
		{Bin: "docker"},
		{Bin: "podman"}, // rootful
		{Bin: "apple"},  // apple -- hardened, but uses the host proxy, not a sidecar
		{},              // zero value = docker
	} {
		got, err := resolveEgressSidecar(rt, f, []string{"x"}, "tok", quietLog())
		if err != nil {
			t.Errorf("runtime %+v: unexpected error: %v", rt, err)
		}
		if got.Token != "" || got.GatewayIP != "" || got.APIPort != "" || got.Allow != nil {
			t.Errorf("runtime %+v: expected no sidecar config, got %+v", rt, got)
		}
	}
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// writeTestKey writes PEM bytes to a temp file and returns the path.
func writeTestKey(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// genSSHKey returns an unencrypted OpenSSH ed25519 private key PEM and
// the corresponding public key line.
func genSSHKey(t *testing.T) (pemBytes []byte, pubLine string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), string(ssh.MarshalAuthorizedKey(sshPub))
}

// genEncryptedSSHKey returns a passphrase-protected OpenSSH ed25519
// private key PEM.
func genEncryptedSSHKey(t *testing.T, passphrase []byte) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestLoadIdentities_unencryptedSSH(t *testing.T) {
	pemData, _ := genSSHKey(t)
	ids, err := loadIdentities(writeTestKey(t, pemData))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestLoadIdentities_encryptedSSH(t *testing.T) {
	passphrase := []byte("test-passphrase")
	pemData := genEncryptedSSHKey(t, passphrase)

	// Inject the passphrase so the prompt is not needed.
	orig := promptPassphrase
	promptPassphrase = func(string) ([]byte, error) { return passphrase, nil }
	t.Cleanup(func() { promptPassphrase = orig })

	ids, err := loadIdentities(writeTestKey(t, pemData))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestLoadIdentities_encryptedSSH_wrongPassphrase(t *testing.T) {
	pemData := genEncryptedSSHKey(t, []byte("correct"))

	orig := promptPassphrase
	promptPassphrase = func(string) ([]byte, error) { return []byte("wrong"), nil }
	t.Cleanup(func() { promptPassphrase = orig })

	_, err := loadIdentities(writeTestKey(t, pemData))
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestLoadIdentities_encryptedSSH_noTerminal(t *testing.T) {
	pemData := genEncryptedSSHKey(t, []byte("secret"))

	// Use the real promptPassphrase — stdin is not a terminal in tests.
	orig := promptPassphrase
	promptPassphrase = defaultPromptPassphrase
	t.Cleanup(func() { promptPassphrase = orig })

	_, err := loadIdentities(writeTestKey(t, pemData))
	if err == nil {
		t.Fatal("expected error when stdin is not a terminal")
	}
}

func TestLoadIdentities_ageNative(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	ids, err := loadIdentities(writeTestKey(t, []byte(id.String()+"\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

func TestLoadRecipients_mixedKeyTypes(t *testing.T) {
	_, sshPub := genSSHKey(t)
	ageID, _ := age.GenerateX25519Identity()

	content := "# comment\n" + sshPub + ageID.Recipient().String() + "\n"
	recs, err := loadRecipients(writeTestKey(t, []byte(content)))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d recipients, want 2 (one SSH, one age)", len(recs))
	}
}

func TestLoadRecipients_empty(t *testing.T) {
	// A file with only comments and blank lines yields zero recipients.
	// That must be an error: the operator configured the path expecting
	// keys, so loading nothing silently would defer the failure to a
	// confusing 400 at export time.
	path := writeTestKey(t, []byte("# only a comment\n\n   \n"))
	_, err := loadRecipients(path)
	if err == nil {
		t.Fatal("expected error for a recipients file with no keys")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir available: %v", err)
	}
	cases := []struct{ in, want string }{
		{"", ""},
		{"/etc/recipients.txt", "/etc/recipients.txt"},
		{"relative/path", "relative/path"},
		{"~", home},
		{"~/.ssh/id_ed25519", filepath.Join(home, ".ssh/id_ed25519")},
		{"~notme/keys", "~notme/keys"}, // ~user form is left untouched
	}
	for _, tc := range cases {
		got, err := expandHome(tc.in)
		if err != nil {
			t.Fatalf("expandHome(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("expandHome(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if h, _ := os.UserHomeDir(); h != home {
		t.Skipf("os.UserHomeDir()=%q does not follow $HOME on this platform", h)
	}

	f := &flags{
		dataDir:        "~/data",
		profilesDir:    "~/profiles",
		recipientsFile: "~/keys/recipients.txt",
		identityFile:   "/abs/identity", // absolute — left untouched
		metadataDir:    "~/in-repo",     // in-repo path — must NOT expand
		skillLocal:     skillDirs{"~/skills-a", "./skills-b"},
	}
	if err := f.normalizePaths(); err != nil {
		t.Fatal(err)
	}

	checks := []struct{ name, got, want string }{
		{"dataDir", f.dataDir, filepath.Join(home, "data")},
		{"profilesDir", f.profilesDir, filepath.Join(home, "profiles")},
		{"recipientsFile", f.recipientsFile, filepath.Join(home, "keys/recipients.txt")},
		{"identityFile", f.identityFile, "/abs/identity"},
		{"metadataDir", f.metadataDir, "~/in-repo"},
		{"skillLocal[0]", f.skillLocal[0], filepath.Join(home, "skills-a")},
		{"skillLocal[1]", f.skillLocal[1], "./skills-b"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

func TestFlagsMerge_recipientsAndIdentity(t *testing.T) {
	cfg := &config.Config{
		RecipientsFile: "/etc/recipients.txt",
		IdentityFile:   "/etc/identity.key",
	}
	f := &flags{set: map[string]bool{}}
	f.merge(cfg)
	if f.recipientsFile != cfg.RecipientsFile {
		t.Errorf("recipientsFile = %q, want %q", f.recipientsFile, cfg.RecipientsFile)
	}
	if f.identityFile != cfg.IdentityFile {
		t.Errorf("identityFile = %q, want %q", f.identityFile, cfg.IdentityFile)
	}
}

func TestFlagsMerge_recipientsCliFlagWins(t *testing.T) {
	cfg := &config.Config{RecipientsFile: "/from/config"}
	f := &flags{recipientsFile: "/from/cli", set: map[string]bool{"recipients-file": true}}
	f.merge(cfg)
	if f.recipientsFile != "/from/cli" {
		t.Errorf("CLI flag should win, got %q", f.recipientsFile)
	}
}

func TestBaseURLHost(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"https://api.anthropic.com", "api.anthropic.com"},
		{"https://my-proxy.corp.com/v1", "my-proxy.corp.com"},
		{"https://my-proxy.corp.com:8443/v1", "my-proxy.corp.com"},
		{"http://localhost:4000", "localhost"},
		{"://broken", ""},
	}
	for _, tc := range cases {
		if got := baseURLHost(tc.in); got != tc.want {
			t.Errorf("baseURLHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
