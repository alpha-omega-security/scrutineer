package main

import (
	"bytes"
	"errors"
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
	for _, kv := range worker.EgressSidecarEnv(cfg, worker.SidecarListenFirstIface+":3128") {
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
	if got.listen != worker.SidecarListenFirstIface+":3128" {
		t.Errorf("listen: sidecar read %q, want %s:3128", got.listen, worker.SidecarListenFirstIface)
	}
	if !reflect.DeepEqual(got.allow, cfg.Allow) {
		t.Errorf("allow: host set %v, sidecar read %v", cfg.Allow, got.allow)
	}
	// The keyword the host injects is the one resolveListen recognises, closing
	// the loop: the sidecar ends up bound to its --internal leg, not :3128.
	resolved, err := resolveListen(got.listen, func() (string, error) { return "10.89.1.2", nil })
	if err != nil || resolved != "10.89.1.2:3128" {
		t.Errorf("resolveListen(%q) = %q, %v, want 10.89.1.2:3128", got.listen, resolved, err)
	}
}

func TestResolveListen(t *testing.T) {
	// Anything that is not the keyword passes through untouched and must not
	// consult the interfaces -- covers manual runs (-listen :3128 or an explicit
	// address) and leaves bad values to fail at bind time.
	for _, listen := range []string{":3128", "0.0.0.0:3128", "10.0.0.1:3128", "not-a-hostport"} {
		called := false
		got, err := resolveListen(listen, func() (string, error) { called = true; return "", nil })
		if err != nil || got != listen || called {
			t.Errorf("resolveListen(%q) = %q, %v (resolver called: %v), want passthrough", listen, got, err, called)
		}
	}

	got, err := resolveListen(worker.SidecarListenFirstIface+":3128", func() (string, error) { return "10.89.1.2", nil })
	if err != nil || got != "10.89.1.2:3128" {
		t.Errorf("keyword listen = %q, %v, want 10.89.1.2:3128", got, err)
	}

	// No resolvable first interface means the sidecar cannot bind its internal
	// leg; serving on all interfaces instead would defeat the point, so the
	// resolver's failure must fail the whole resolution (fail closed).
	if _, err := resolveListen(worker.SidecarListenFirstIface+":3128", func() (string, error) { return "", errors.New("no iface") }); err == nil {
		t.Error("expected a resolver failure to fail listen resolution")
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
