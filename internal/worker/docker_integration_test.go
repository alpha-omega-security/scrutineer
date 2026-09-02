package worker

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"
)

type dockerNoopHarness struct{ stubHarness }

func (dockerNoopHarness) Binary() string            { return "true" }
func (dockerNoopHarness) Args(harness.Job) []string { return nil }

func TestIntegration_DockerDesktopProxySidecar(t *testing.T) {
	image := os.Getenv("SCRUTINEER_TEST_RUNNER_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_RUNNER_IMAGE to run the Docker Desktop integration")
	}
	rt, ok := container.DetectRuntime("docker")
	if !ok {
		t.Skip("docker is unavailable")
	}
	if !rt.DockerDesktop {
		t.Skip("docker daemon is not Docker Desktop")
	}
	if !imageExistsLocally(t.Context(), rt, image) {
		t.Skipf("runner image %q is unavailable locally", image)
	}

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()
	_, apiPort, err := net.SplitHostPort(api.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	gatewayIP := ResolveHostGatewayIPv4(rt, image, "")
	if gatewayIP == "" {
		t.Fatal("host-gateway did not resolve on Docker Desktop")
	}

	key := fmt.Sprintf("docker-%d-%d", os.Getpid(), time.Now().UnixNano())
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := ContainerRunner{
		Image:    image,
		Harness:  dockerNoopHarness{},
		Hardened: true,
		Runtime:  rt,
		Egress: EgressSidecarConfig{
			Token:     NewProxyToken(),
			Allow:     []string{HostGatewayAlias},
			APIPort:   apiPort,
			GatewayIP: gatewayIP,
		},
	}
	_, err = runner.RunSkill(t.Context(), SkillJob{
		IsolationKey: key,
		WorkRoot:     work,
		SrcReady:     true,
		Name:         "noop",
	}, func(Event) {})
	if err != nil {
		t.Fatalf("RunSkill: %v", err)
	}

	containerName := proxySidecarName(key)
	if err := exec.Command("docker", "inspect", "--", containerName).Run(); err == nil {
		t.Errorf("sidecar %q remains after RunSkill", containerName)
	}
	networkName := hardenedNetworkName(key)
	if err := exec.Command("docker", "network", "inspect", "--", networkName).Run(); err == nil {
		t.Errorf("network %q remains after RunSkill", networkName)
	}
}
