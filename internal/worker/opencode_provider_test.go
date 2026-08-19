package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
	if !hasAdjacent(args, "-v", "/state/kiro:/opencode-provider-state:z") {
		t.Errorf("provider state mount missing: %v", args)
	}
	if !hasAdjacent(args, "-e", "XDG_DATA_HOME=/opencode-provider-state") {
		t.Errorf("provider state XDG path missing: %v", args)
	}
	if !hasAdjacent(args, "-w", "/tmp") {
		t.Errorf("readiness working directory is not neutral: %v", args)
	}
}

func TestBuildRunArgsForOpencodeKeepsPerScanAuthState(t *testing.T) {
	d := ContainerRunner{Harness: OpencodeHarness{}}
	args := d.buildRunArgs("/work/abs", "stock:1", hardenedNet{}, "/state/scan-1")
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
}

func TestOpencodeProviderEgressStableAndUnique(t *testing.T) {
	providers := map[string]OpencodeProviderConfig{
		"groq": {EgressHosts: []string{"api.groq.com", "auth.example.com"}},
		"kiro": {EgressHosts: []string{"q.us-east-1.amazonaws.com", "auth.example.com"}},
	}
	want := []string{"api.groq.com", "auth.example.com", "q.us-east-1.amazonaws.com"}
	if got := OpencodeProviderEgress(providers); !slices.Equal(got, want) {
		t.Errorf("egress hosts = %v, want %v", got, want)
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
	runtime := filepath.Join(t.TempDir(), "fake-runtime")
	if err := os.WriteFile(runtime, []byte("#!/bin/sh\nprintf 'groq/model-a\\ngroq/model-b\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := ContainerRunner{
		Harness:           OpencodeHarness{},
		Runtime:           ContainerRuntime{Bin: runtime},
		OpencodeReadiness: NewOpencodeReadinessCache(),
	}
	provider := opencodeProvider{ID: "groq", Model: "groq/model-b", RunnerImage: "stock:1", Env: map[string]string{}, Configured: true}
	if err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "stock:1", hardenedNet{}, ""); err != nil {
		t.Fatal(err)
	}
	provider.Model = "groq/model-c"
	err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "stock:1", hardenedNet{}, "")
	if err == nil || !strings.Contains(err.Error(), "unavailable in the selected image catalog") {
		t.Fatalf("missing model error = %v", err)
	}
}

func TestCheckOpencodeReadinessReportsMissingSupportingBinary(t *testing.T) {
	runtime := filepath.Join(t.TempDir(), "fake-runtime")
	if err := os.WriteFile(runtime, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	d := ContainerRunner{Harness: OpencodeHarness{}, Runtime: ContainerRuntime{Bin: runtime}}
	provider := opencodeProvider{
		ID:               "kiro",
		Model:            "kiro/auto",
		RunnerImage:      "kiro:1",
		Env:              map[string]string{},
		RequiredBinaries: []string{"kiro-cli"},
		Configured:       true,
	}
	err := d.checkOpencodeReadiness(t.Context(), provider, t.TempDir(), "kiro:1", hardenedNet{}, "")
	if err == nil || !strings.Contains(err.Error(), `supporting binary "kiro-cli" is missing`) {
		t.Fatalf("missing binary error = %v", err)
	}
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

func TestEnvironmentWithReplacesAndAdds(t *testing.T) {
	got := environmentWith([]string{"A=old", "B=keep"}, map[string]string{"A": "new", "C": "added"})
	for _, want := range []string{"A=new", "B=keep", "C=added"} {
		if !slices.Contains(got, want) {
			t.Errorf("environment = %v, missing %q", got, want)
		}
	}
}

func TestRunnerImageContentDigestPrefersRegistryDigest(t *testing.T) {
	runtime := filepath.Join(t.TempDir(), "fake-runtime")
	if err := os.WriteFile(runtime, []byte("#!/bin/sh\nprintf 'registry.example/provider@sha256:abc\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := runnerImageContentDigest(t.Context(), ContainerRuntime{Bin: runtime}, "provider:1"); got != "sha256:abc" {
		t.Errorf("runner image digest = %q, want sha256:abc", got)
	}
}
