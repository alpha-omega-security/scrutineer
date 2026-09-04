package worker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"scrutineer/internal/testutil"
)

func TestResolveOpencodeProviderBuildsScopedAuth(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "groq-secret")
	d := ContainerRunner{
		Harness: OpencodeHarness{},
		Image:   "stock:1",
		OpencodeProviders: map[string]OpencodeProviderConfig{
			"groq": {
				RunnerImage:   "groq:1",
				ConfigContent: `{"provider":{}}`,
				APIKeyEnv:     "GROQ_API_KEY",
				AuthMetadata:  map[string]string{"accountId": "team-1"},
				EgressHosts:   []string{"api.groq.com"},
			},
		},
	}
	provider, err := d.resolveOpencodeProvider("groq/llama-3.3-70b-versatile")
	if err != nil {
		t.Fatal(err)
	}
	if !provider.Configured || provider.ID != "groq" || provider.RunnerImage != "groq:1" {
		t.Fatalf("resolved provider = %+v", provider)
	}
	for _, binary := range []string{"brief", "scrutineer"} {
		if !slices.Contains(provider.RequiredBinaries, binary) {
			t.Errorf("derived image check does not require %s: %v", binary, provider.RequiredBinaries)
		}
	}
	var auth map[string]opencodeAuthEntry
	if err := json.Unmarshal([]byte(provider.Env["OPENCODE_AUTH_CONTENT"]), &auth); err != nil {
		t.Fatal(err)
	}
	if len(auth) != 1 || auth["groq"].Key != "groq-secret" || auth["groq"].Metadata["accountId"] != "team-1" {
		t.Errorf("provider-only auth = %#v", auth)
	}
	if provider.Env["OPENCODE_CONFIG_CONTENT"] != `{"provider":{}}` {
		t.Errorf("config content = %q", provider.Env["OPENCODE_CONFIG_CONTENT"])
	}
	if !slices.Equal(provider.EgressHosts, []string{"api.groq.com"}) {
		t.Errorf("provider egress = %v", provider.EgressHosts)
	}
}

func TestResolveOpencodeProviderRequiresNamedCredentials(t *testing.T) {
	d := ContainerRunner{
		Harness: OpencodeHarness{},
		OpencodeProviders: map[string]OpencodeProviderConfig{
			"kiro": {PassEnv: []string{"KIRO_API_KEY"}},
		},
	}
	_, err := d.resolveOpencodeProvider("kiro/auto")
	if err == nil || !strings.Contains(err.Error(), "KIRO_API_KEY") {
		t.Fatalf("resolve error = %v, want missing KIRO_API_KEY", err)
	}
}

func TestResolveOpencodeProviderDoesNotLabelOtherHarnesses(t *testing.T) {
	provider, err := (ContainerRunner{Harness: ClaudeHarness{}}).resolveOpencodeProvider("anthropic/claude")
	if err != nil {
		t.Fatal(err)
	}
	if provider.ID != "" || provider.Configured {
		t.Errorf("Claude model resolved as OpenCode provider: %+v", provider)
	}
}

func TestResolveOpencodeProviderRejectsUnconfiguredNonStockProvider(t *testing.T) {
	d := ContainerRunner{
		Harness: OpencodeHarness{},
		OpencodeProviders: map[string]OpencodeProviderConfig{
			"kiro": {EgressHosts: []string{"runtime.kiro.dev"}},
		},
	}
	_, err := d.resolveOpencodeProvider("lmstudio/qwen/qwen3.5-9b")
	if err == nil || !strings.Contains(err.Error(), "opencode.providers.lmstudio") {
		t.Fatalf("unconfigured provider error = %v, want opencode.providers.lmstudio", err)
	}
	for _, model := range []string{"anthropic/claude-sonnet-5", "openai/gpt-6"} {
		provider, err := d.resolveOpencodeProvider(model)
		if err != nil || provider.Configured || provider.ID != OpencodeProviderID(model) {
			t.Errorf("stock model %q: provider=%+v err=%v, want unconfigured pass-through", model, provider, err)
		}
	}
}

func TestBuildRunArgsForProviderScopesEnvironmentAndState(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "unrelated-openai-secret")
	t.Setenv("ANTHROPIC_API_KEY", "unrelated-anthropic-secret")
	d := ContainerRunner{Harness: OpencodeHarness{}, SELinuxRelabel: true}
	provider := opencodeProvider{
		ID:         "kiro",
		StateDir:   "/state/kiro",
		Configured: true,
		Env: map[string]string{
			"KIRO_API_KEY":            "kiro-secret",
			"OPENCODE_CONFIG_CONTENT": `{"plugin":["kiro"]}`,
		},
	}
	args := d.buildRunArgsForProvider("/work/abs", "kiro:1", hardenedNet{}, "/state/scan-1", provider, "/tmp")
	joined := strings.Join(args, " ")
	for _, secret := range []string{"kiro-secret", "unrelated-openai-secret", "unrelated-anthropic-secret"} {
		if strings.Contains(joined, secret) {
			t.Errorf("container argv contains secret %q: %v", secret, args)
		}
	}
	for _, key := range []string{"KIRO_API_KEY", "OPENCODE_CONFIG_CONTENT"} {
		if !hasAdjacent(args, "-e", key) {
			t.Errorf("container args do not inherit selected key %s: %v", key, args)
		}
	}
	for _, key := range []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"} {
		if slices.Contains(args, key) {
			t.Errorf("container args inherited unrelated key %s: %v", key, args)
		}
	}
	authSrc := filepath.Join("/state/kiro", "opencode", "auth.json")
	if !hasAdjacent(args, "-v", authSrc+":/harness-state/data/opencode/auth.json:z") {
		t.Errorf("provider auth mount missing: %v", args)
	}
	if !hasAdjacent(args, "-e", "XDG_DATA_HOME=/harness-state/data") {
		t.Errorf("per-scan OpenCode data path missing: %v", args)
	}
	for _, arg := range args {
		if strings.Contains(arg, "/opencode-provider-state") || arg == "/state/kiro:/opencode-provider-state:z" {
			t.Errorf("whole provider state directory is exposed: %v", args)
		}
	}
	if !hasAdjacent(args, "-w", "/tmp") {
		t.Errorf("readiness working directory is not neutral: %v", args)
	}
}

func TestBuildRunArgsForOpencodeKeepsPerScanAuthState(t *testing.T) {
	d := ContainerRunner{Harness: OpencodeHarness{}}
	args := d.buildRunArgs("stock:1", hardenedNet{}, "/state/scan-1")
	if !hasAdjacent(args, "-e", "XDG_DATA_HOME=/harness-state/data") {
		t.Errorf("per-scan OpenCode auth state missing: %v", args)
	}
}

func TestEnsureOpencodeProviderStateRejectsOtherCredentials(t *testing.T) {
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	authDir := filepath.Join(state, "opencode")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "auth.json"), []byte(`{"kiro":{"type":"api"},"openai":{"type":"api"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := ensureOpencodeProviderState(opencodeProvider{ID: "kiro", StateDir: state})
	if err == nil || !strings.Contains(err.Error(), `credentials for provider "openai"`) {
		t.Fatalf("state validation error = %v", err)
	}
}

func TestEnsureOpencodeProviderStateRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports 0777 for every directory; the POSIX perm check does not apply")
	}
	state := t.TempDir()
	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	err := ensureOpencodeProviderState(opencodeProvider{ID: "github-copilot", StateDir: state})
	if err == nil || !strings.Contains(err.Error(), "expose credentials") {
		t.Fatalf("state permission error = %v", err)
	}
}

func TestEnsureOpencodeProviderStateRequiresStoredCredentials(t *testing.T) {
	state := filepath.Join(t.TempDir(), "oauth-state")
	err := ensureOpencodeProviderState(opencodeProvider{ID: "github-copilot", StateDir: state})
	if err == nil || !strings.Contains(err.Error(), "missing stored credentials") {
		t.Fatalf("missing stored credential error = %v", err)
	}

	state = filepath.Join(t.TempDir(), "native-state")
	err = ensureOpencodeProviderState(opencodeProvider{ID: "kiro", StateDir: state, ExternalCredentials: true})
	if err != nil {
		t.Fatalf("external credential should be allowed to initialise state: %v", err)
	}
	data, err := os.ReadFile(opencodeProviderAuthPath(state))
	if err != nil || strings.TrimSpace(string(data)) != "{}" {
		t.Fatalf("initial auth state = %q, %v", data, err)
	}
}

func TestConfigureOpencodeProviderEgressScopesHostProxyToSelectedProvider(t *testing.T) {
	d := ContainerRunner{
		Harness: OpencodeHarness{},
		Runtime: ContainerRuntime{Bin: runtimePodman},
		OpencodeProviders: map[string]OpencodeProviderConfig{
			"groq": {EgressHosts: []string{"api.groq.com", "auth.example.com"}},
			"kiro": {EgressHosts: []string{"q.us-east-1.amazonaws.com"}},
		},
		Egress: EgressSidecarConfig{Allow: []string{"models.dev"}},
		ProviderProxy: ScopedEgressProxyConfig{
			Allow:         []string{"models.dev"},
			APIPort:       "8080",
			APIHosts:      []string{HostGatewayAlias},
			ContainerHost: HostGatewayAlias,
		},
	}
	provider, err := d.resolveOpencodeProvider("groq/model")
	if err != nil {
		t.Fatal(err)
	}
	got, cleanup, err := d.configureOpencodeProviderEgress(provider)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, allow := range [][]string{got.Egress.Allow, got.ProviderProxy.Allow} {
		if !slices.Contains(allow, "api.groq.com") || !slices.Contains(allow, "auth.example.com") {
			t.Errorf("selected provider hosts missing from %v", allow)
		}
		if slices.Contains(allow, "q.us-east-1.amazonaws.com") {
			t.Errorf("unselected provider host leaked into %v", allow)
		}
	}
	if got.ProxyURL == "" || got.ProxyURL == d.ProxyURL {
		t.Errorf("provider-scoped proxy URL = %q", got.ProxyURL)
	}
	args := got.buildRunArgsForProvider("/work/abs", "stock:1", hardenedNet{}, "", provider, "/tmp")
	if !slices.Contains(args, "--http-proxy=false") {
		t.Errorf("podman host proxy inheritance is enabled: %v", args)
	}
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if !hasAdjacent(args, "-e", key+"="+got.ProxyURL) {
			t.Errorf("selected provider proxy missing from %s: %v", key, args)
		}
	}
}

func TestConfigureOpencodeProviderEgressOpensHostPort(t *testing.T) {
	// An ephemeral loopback server stands in for a host-local model server so
	// the test does not depend on whatever occupies a well-known port.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	_, hostPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	deniedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer func() { _ = deniedLn.Close() }()
	_, deniedPort, _ := net.SplitHostPort(deniedLn.Addr().String())

	d := ContainerRunner{
		Harness: OpencodeHarness{},
		OpencodeProviders: map[string]OpencodeProviderConfig{
			"ollama": {HostPort: hostPort},
		},
		Egress: EgressSidecarConfig{Allow: []string{HostGatewayAlias}},
		ProviderProxy: ScopedEgressProxyConfig{
			Allow:         []string{HostGatewayAlias},
			APIPort:       "8080",
			APIHosts:      []string{HostGatewayAlias},
			ContainerHost: HostGatewayAlias,
		},
	}
	provider, err := d.resolveOpencodeProvider("ollama/llama3.3")
	if err != nil {
		t.Fatal(err)
	}
	if provider.HostPort != hostPort || !provider.Configured {
		t.Fatalf("resolved provider = %+v", provider)
	}
	got, cleanup, err := d.configureOpencodeProviderEgress(provider)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	// Sidecar path picks the port up from the mutated Egress config.
	if !slices.Equal(got.Egress.HostPorts, []string{hostPort}) {
		t.Errorf("sidecar host ports = %v", got.Egress.HostPorts)
	}
	// Host-proxy path: the scoped listener must accept the gateway alias on
	// the provider's host port (rewritten to 127.0.0.1 -> upstream) and refuse
	// an unlisted port at the gate before dialing.
	pu, _ := url.Parse(got.ProxyURL)
	pu.Host = "127.0.0.1:" + pu.Port()
	tr := &http.Transport{Proxy: http.ProxyURL(pu)}
	client := &http.Client{Transport: tr, Timeout: time.Second}
	resp, err := client.Get("http://" + HostGatewayAlias + ":" + hostPort + "/")
	if err != nil {
		t.Fatalf("host port via scoped proxy: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("scoped proxy did not reach host-local server on provider port: %d", resp.StatusCode)
	}
	resp, err = client.Get("http://" + HostGatewayAlias + ":" + deniedPort + "/")
	if err != nil {
		t.Fatalf("unlisted port via scoped proxy: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("scoped proxy allowed unlisted host port: %d", resp.StatusCode)
	}
}

func TestConfigureOpencodeProviderEgressScopesSidecarToSelectedProvider(t *testing.T) {
	d := ContainerRunner{
		Harness:  OpencodeHarness{},
		Hardened: true,
		Runtime:  ContainerRuntime{Bin: "podman", Rootless: true},
		Egress:   EgressSidecarConfig{Allow: []string{"models.dev"}},
	}
	provider := opencodeProvider{
		ID:          "kiro",
		Configured:  true,
		EgressHosts: []string{"runtime.us-east-1.kiro.dev"},
	}
	got, cleanup, err := d.configureOpencodeProviderEgress(provider)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if !slices.Equal(got.Egress.Allow, []string{"models.dev", "runtime.us-east-1.kiro.dev"}) {
		t.Errorf("sidecar allowlist = %v", got.Egress.Allow)
	}
	if got.ProxyURL != d.ProxyURL {
		t.Errorf("sidecar configuration unexpectedly started a host proxy: %q", got.ProxyURL)
	}
}

func TestOpencodeProviderImageFeedsLanguageProfileDetection(t *testing.T) {
	var detectedImage string
	d := ContainerRunner{
		Harness:     OpencodeHarness{},
		Image:       "provider:1",
		ProfilesDir: t.TempDir(),
		detectProfile: func(_ context.Context, _ ContainerRuntime, runnerImage, _ string, _ bool) Profile {
			detectedImage = runnerImage
			return Profile{}
		},
	}
	profile, image := d.resolveProfile(t.Context(), "", t.TempDir(), "", func(Event) {})
	if profile != "" || image != "provider:1" || detectedImage != "provider:1" {
		t.Errorf("profile=%q image=%q detected base=%q", profile, image, detectedImage)
	}
}

func TestCheckOpencodeReadinessFindsExactModel(t *testing.T) {
	runtime := writeFakeRuntime(t, "#!/bin/sh\ncase \" $* \" in *provider-readiness*) exit 0;; esac\nprintf 'groq/model-a\\ngroq/model-b\\n'\n")
	d := ContainerRunner{
		Harness:           OpencodeHarness{},
		Runtime:           ContainerRuntime{Bin: runtime},
		OpencodeReadiness: NewOpencodeReadinessCache(),
	}
	provider := opencodeProvider{ID: "groq", Model: "groq/model-b", RunnerImage: "stock:1", Env: map[string]string{}, EgressHosts: []string{"api.groq.com"}, Configured: true}
	if err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "stock:1", hardenedNet{}, ""); err != nil {
		t.Fatal(err)
	}
	provider.Model = "groq/model-c"
	err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "stock:1", hardenedNet{}, "")
	if err == nil || !strings.Contains(err.Error(), "unavailable in the selected image catalog") {
		t.Fatalf("missing model error = %v", err)
	}
}

func TestCheckOpencodeReadinessProbesHostPort(t *testing.T) {
	log := filepath.Join(t.TempDir(), "invocations")
	runtime := writeFakeRuntime(t, "#!/bin/sh\necho \"$*\" >> "+log+"\ncase \"$*\" in *host.docker.internal:11434*) exit 0;; *' opencode models '*) printf 'ollama/llama3.3\\n';; esac\n")
	d := ContainerRunner{
		Harness:           OpencodeHarness{},
		Runtime:           ContainerRuntime{Bin: runtime},
		OpencodeReadiness: NewOpencodeReadinessCache(),
	}
	provider := opencodeProvider{ID: "ollama", Model: "ollama/llama3.3", Env: map[string]string{}, HostPort: "11434", Configured: true}
	if err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "stock:1", hardenedNet{}, ""); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if !strings.Contains(string(data), "--proxytunnel") || !strings.Contains(string(data), "http://"+HostGatewayAlias+":11434/") {
		t.Errorf("readiness did not force a CONNECT tunnel to the host port: %s", data)
	}
	// A second call hits the readiness cache for the static checks but must
	// still probe the host port, since a local model server can stop between
	// scans while the image and catalog stay unchanged.
	_ = os.Remove(log)
	if err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "stock:1", hardenedNet{}, ""); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(log)
	if strings.Contains(string(data), "opencode models") {
		t.Errorf("cached call re-ran the catalog probe: %s", data)
	}
	if !strings.Contains(string(data), "http://"+HostGatewayAlias+":11434/") {
		t.Errorf("cached call skipped the host-port probe: %s", data)
	}

	err := checkOpencodeHostPort(provider, func(...string) ([]byte, error) {
		return []byte("curl: (56) CONNECT tunnel failed, response 502"), errors.New("exit status 56")
	})
	if err == nil || !strings.Contains(err.Error(), "host-local model server on port 11434") {
		t.Fatalf("host port readiness error = %v", err)
	}
}

func TestCheckOpencodeReadinessReportsBlockedProviderEgress(t *testing.T) {
	runtime := writeFakeRuntime(t, "#!/bin/sh\ncase \"$*\" in\n"+
		"*curl*) echo 'warning: platform mismatch' >&2; echo 'curl: (28) Connection timed out' >&2; echo 'scrutineer-readiness-fail: auth.groq.com'; exit 1;;\n"+
		"*) printf 'groq/model-a\\n';;\nesac\n")
	d := ContainerRunner{Harness: OpencodeHarness{}, Runtime: ContainerRuntime{Bin: runtime}}
	provider := opencodeProvider{ID: "groq", Model: "groq/model-a", Env: map[string]string{}, EgressHosts: []string{"api.groq.com", "auth.groq.com", "*.groq.net"}, Configured: true}
	err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "stock:1", hardenedNet{}, "")
	if err == nil || !strings.Contains(err.Error(), `configured egress host "auth.groq.com"`) {
		t.Fatalf("blocked egress error = %v", err)
	}
}

func TestCheckOpencodeReadinessReportsMissingSupportingBinary(t *testing.T) {
	runtime := writeFakeRuntime(t, "#!/bin/sh\necho 'scrutineer-readiness-fail: kiro-cli'; exit 1\n")
	d := ContainerRunner{Harness: OpencodeHarness{}, Runtime: ContainerRuntime{Bin: runtime}}
	provider := opencodeProvider{
		ID:               "kiro",
		Model:            "kiro/auto",
		RunnerImage:      "kiro:1",
		Env:              map[string]string{},
		RequiredBinaries: []string{"brief", "kiro-cli"},
		Configured:       true,
	}
	err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "kiro:1", hardenedNet{}, "")
	if err == nil || !strings.Contains(err.Error(), `supporting binary "kiro-cli" is missing`) {
		t.Fatalf("missing binary error = %v", err)
	}
}

func TestCheckOpencodeReadinessProbesOncePerCheck(t *testing.T) {
	log := filepath.Join(t.TempDir(), "invocations")
	runtime := writeFakeRuntime(t, "#!/bin/sh\necho x >> "+log+"\ncase \"$*\" in *provider-readiness*) exit 0;; esac\nprintf 'kiro/auto\\n'\n")
	d := ContainerRunner{Harness: OpencodeHarness{}, Runtime: ContainerRuntime{Bin: runtime}}
	provider := opencodeProvider{
		ID:               "kiro",
		Model:            "kiro/auto",
		Env:              map[string]string{},
		RequiredBinaries: []string{"brief", "scrutineer", "kiro-cli"},
		EgressHosts:      []string{"a.example", "b.example", "*.c.example"},
		Configured:       true,
	}
	if err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "kiro:1", hardenedNet{}, ""); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if n := strings.Count(string(data), "x"); n != 3 {
		t.Errorf("readiness launched %d containers, want 3 (binaries, hosts, catalog)", n)
	}
}

func TestCheckOpencodeReadinessCapsCatalogFailureOutput(t *testing.T) {
	runtime := writeFakeRuntime(t, "#!/bin/sh\nyes 'Cannot find package kiro-adapter' | head -c 5000; exit 1\n")
	d := ContainerRunner{Harness: OpencodeHarness{}, Runtime: ContainerRuntime{Bin: runtime}}
	provider := opencodeProvider{ID: "kiro", Model: "kiro/auto", Env: map[string]string{}, Configured: true}
	err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "kiro:1", hardenedNet{}, "")
	if err == nil || !strings.Contains(err.Error(), "adapter or plugin is missing") {
		t.Fatalf("catalog failure error = %v", err)
	}
	if len(err.Error()) > 3000 {
		t.Errorf("catalog failure output not capped: %d bytes", len(err.Error()))
	}
}

func TestOpencodeStateLockSerialisesSharedStateDir(t *testing.T) {
	c := NewOpencodeReadinessCache()
	dir := t.TempDir()
	held := false
	overlap := false
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			unlock := c.lockState(dir)
			if held {
				overlap = true
			}
			held = true
			time.Sleep(5 * time.Millisecond)
			held = false
			unlock()
		})
	}
	wg.Wait()
	if overlap {
		t.Error("two callers held the same state_dir lock at once")
	}
	// A distinct state_dir must not contend with the first, and empty is a
	// no-op so a nil cache or a provider without state never blocks.
	other := c.lockState(t.TempDir())
	other()
	(*OpencodeReadinessCache)(nil).lockState("")()
}

func writeFakeRuntime(t *testing.T, script string) string {
	t.Helper()
	return testutil.WriteStub(t, t.TempDir(), "fake-runtime", script)
}

func TestClassifyOpencodeReadinessErrors(t *testing.T) {
	provider := opencodeProvider{ID: "kiro"}
	runErr := errors.New("exit status 1")
	for _, tc := range []struct {
		output string
		want   string
	}{
		{"Cannot find package kiro-adapter", "adapter or plugin is missing"},
		{"kiro-cli: command not found", "supporting binary is missing"},
		{"connect ECONNREFUSED", "configured egress hosts"},
	} {
		if got := classifyOpencodeReadinessError(provider, tc.output, runErr); !strings.Contains(got.Error(), tc.want) {
			t.Errorf("classify %q = %v, want %q", tc.output, got, tc.want)
		}
	}
}

func TestContainerRunErrorStateResumeRetryIgnoresProviderErrors(t *testing.T) {
	h := stubHarness{acctErr: "invalid_api_key"}
	s := containerRunErrorState{}
	s.observe(Event{Kind: KindError, Text: "session abc not found"}, h, "kiro")
	if !s.resumeRetryable() {
		t.Error("provider error event blocked the fresh-restart resume fallback")
	}
	err := s.failure(opencodeProvider{ID: "kiro"}, "docker", errors.New("exit 1"))
	if !strings.Contains(err.Error(), "session abc not found") {
		t.Errorf("provider error text lost from failure: %v", err)
	}
	s.observe(Event{Kind: KindError, Text: "invalid_api_key: revoked"}, h, "kiro")
	if s.resumeRetryable() {
		t.Error("account error event did not block the resume fallback")
	}
}

func TestContainerRunErrorStateKeepsStockProviderErrorText(t *testing.T) {
	// A stock (unconfigured) OpenCode provider still has an ID, so its error
	// event should reach the scan failure instead of the bare exit status.
	s := containerRunErrorState{}
	s.observe(Event{Kind: KindError, Text: "Unexpected server error. Check server logs for details."}, stubHarness{}, "anthropic")
	err := s.failure(opencodeProvider{ID: "anthropic"}, "docker", errors.New("exit status 1"))
	if !strings.Contains(err.Error(), "Unexpected server error") || !strings.Contains(err.Error(), `"anthropic"`) {
		t.Errorf("stock provider failure = %v, want OpenCode provider error text", err)
	}
	// A non-opencode backend has no provider ID and keeps the plain exit error.
	s = containerRunErrorState{}
	s.observe(Event{Kind: KindError, Text: "some claude error"}, stubHarness{}, "")
	err = s.failure(opencodeProvider{}, "docker", errors.New("exit status 1"))
	if strings.Contains(err.Error(), "OpenCode provider") {
		t.Errorf("non-opencode failure wrapped as provider error: %v", err)
	}
}

func TestClassifyOpencodeProviderRunErrorPreservesUnderlyingMessage(t *testing.T) {
	provider := opencodeProvider{ID: "kiro"}
	err := classifyOpencodeProviderRunError(provider, "proxy CONNECT failed for runtime.us-east-1.kiro.dev", errors.New("exit status 1"))
	if !strings.Contains(err.Error(), "configured egress hosts") || !strings.Contains(err.Error(), "runtime.us-east-1.kiro.dev") {
		t.Fatalf("provider run error = %v", err)
	}
}

func TestEnvironmentWithReplacesAndAdds(t *testing.T) {
	got := environmentWith([]string{"A=old", "B=keep"}, map[string]string{"A": "new", "C": "added"})
	for _, want := range []string{"A=new", "B=keep", "C=added"} {
		if !slices.Contains(got, want) {
			t.Errorf("environment = %v, missing %q", got, want)
		}
	}
}

func TestRunnerImageContentDigestPrefersRegistryDigest(t *testing.T) {
	runtime := writeFakeRuntime(t, "#!/bin/sh\nprintf 'registry.example/provider@sha256:abc\\n'\n")
	if got := runnerImageContentDigest(t.Context(), ContainerRuntime{Bin: runtime}, "provider:1"); got != "sha256:abc" {
		t.Errorf("runner image digest = %q, want sha256:abc", got)
	}
}

func TestRunnerImageContentDigestParsesAppleInspectJSON(t *testing.T) {
	// container image inspect emits a JSON array with no --format support, so
	// the digest is read from configuration.descriptor.digest with id as the
	// fallback for locally built images.
	dir := t.TempDir()
	testutil.WriteStub(t, dir, "container", "#!/bin/sh\ncase \"$*\" in *no-descriptor*) printf '[{\"id\":\"sha256:localid\"}]';; *) printf '[{\"id\":\"sha256:localid\",\"configuration\":{\"descriptor\":{\"digest\":\"sha256:def\"}}}]';; esac\n")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if got := runnerImageContentDigest(t.Context(), ContainerRuntime{Bin: runtimeApple}, "provider:1"); got != "sha256:def" {
		t.Errorf("apple runner image digest = %q, want sha256:def", got)
	}
	if got := runnerImageContentDigest(t.Context(), ContainerRuntime{Bin: runtimeApple}, "no-descriptor:1"); got != "sha256:localid" {
		t.Errorf("apple runner image id fallback = %q, want sha256:localid", got)
	}
}
