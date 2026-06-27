package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"scrutineer/internal/worker"
)

// envMap turns a map into a getenv-shaped lookup with "" for misses.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseProxyConfig_FromEnv(t *testing.T) {
	got, err := parseProxyConfig(nil, envMap(map[string]string{
		"SCRUTINEER_PROXY_TOKEN":    "tok123",
		"SCRUTINEER_PROXY_ALLOW":    "*.anthropic.com, host.docker.internal ,",
		"SCRUTINEER_PROXY_API_HOST": "192.0.2.7",
		"SCRUTINEER_PROXY_API_PORT": "8080",
		"SCRUTINEER_PROXY_LISTEN":   ":4000",
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := proxyConfig{
		listen:  ":4000",
		token:   "tok123",
		apiHost: "192.0.2.7",
		apiPort: "8080",
		allow:   []string{"*.anthropic.com", "host.docker.internal"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseProxyConfig = %+v, want %+v", got, want)
	}
}

func TestParseProxyConfig_ListenDefaults(t *testing.T) {
	got, err := parseProxyConfig(nil, envMap(map[string]string{
		"SCRUTINEER_PROXY_TOKEN": "tok",
		"SCRUTINEER_PROXY_ALLOW": "example.com",
	}))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.listen != ":3128" {
		t.Errorf("listen default = %q, want :3128", got.listen)
	}
}

func TestParseProxyConfig_FlagsOverrideEnv(t *testing.T) {
	got, err := parseProxyConfig(
		[]string{"-listen", ":9999", "-token", "flagtok", "-allow", "only.test"},
		envMap(map[string]string{
			"SCRUTINEER_PROXY_TOKEN":  "envtok",
			"SCRUTINEER_PROXY_ALLOW":  "env.test",
			"SCRUTINEER_PROXY_LISTEN": ":1111",
		}),
	)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.listen != ":9999" || got.token != "flagtok" || !reflect.DeepEqual(got.allow, []string{"only.test"}) {
		t.Errorf("flags did not override env: %+v", got)
	}
}

func TestParseProxyConfig_RequiresTokenAndAllow(t *testing.T) {
	if _, err := parseProxyConfig(nil, envMap(map[string]string{"SCRUTINEER_PROXY_ALLOW": "x.test"})); err == nil {
		t.Error("expected error when token is empty")
	}
	if _, err := parseProxyConfig(nil, envMap(map[string]string{"SCRUTINEER_PROXY_TOKEN": "tok"})); err == nil {
		t.Error("expected error when allowlist is empty")
	}
}

func TestSplitAllow(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"  ,  ", nil},
		{"a.com", []string{"a.com"}},
		{" a.com , b.com ,,c.com ", []string{"a.com", "b.com", "c.com"}},
	}
	for _, c := range cases {
		if got := splitAllow(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitAllow(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestEgressSidecarEnvContract(t *testing.T) {
	// The host side (worker.EgressSidecarEnv, baked into the runner container's
	// env) and the sidecar side (parseProxyConfig, in `scrutineer proxy`) must
	// agree on the SCRUTINEER_PROXY_* names and values. This round trip locks
	// that contract: rename a var on one side without the other and it breaks.
	cfg := worker.EgressSidecarConfig{
		Token:     "tok",
		Allow:     []string{"*.anthropic.com", "host.docker.internal"},
		APIPort:   "8080",
		GatewayIP: "192.0.2.9",
	}
	env := map[string]string{}
	for _, kv := range worker.EgressSidecarEnv(cfg, ":3128") {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
	}

	got, err := parseProxyConfig(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("sidecar could not parse the host's env: %v", err)
	}
	if got.token != cfg.Token {
		t.Errorf("token: host set %q, sidecar read %q", cfg.Token, got.token)
	}
	if got.apiHost != cfg.GatewayIP {
		t.Errorf("api host: host set %q, sidecar read %q", cfg.GatewayIP, got.apiHost)
	}
	if got.apiPort != cfg.APIPort {
		t.Errorf("api port: host set %q, sidecar read %q", cfg.APIPort, got.apiPort)
	}
	if got.listen != ":3128" {
		t.Errorf("listen: sidecar read %q, want :3128", got.listen)
	}
	if !reflect.DeepEqual(got.allow, cfg.Allow) {
		t.Errorf("allow: host set %v, sidecar read %v", cfg.Allow, got.allow)
	}
}

func TestDispatch_RoutesProxy(t *testing.T) {
	// `proxy` must be handled by dispatch (not fall through to the server). With
	// no token configured it returns an error, which proves the route is wired
	// without starting a listener. Clear the env so an ambient SCRUTINEER_PROXY_*
	// can't make this run the (blocking) server.
	t.Setenv("SCRUTINEER_PROXY_TOKEN", "")
	t.Setenv("SCRUTINEER_PROXY_ALLOW", "")
	handled, err := dispatch([]string{"proxy"}, &bytes.Buffer{})
	if !handled {
		t.Fatal("dispatch did not handle the proxy subcommand")
	}
	if err == nil {
		t.Error("expected an error from proxy with no token/allowlist configured")
	}
}
