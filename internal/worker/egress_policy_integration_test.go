package worker

// Real-container check of per-skill egress policies on Docker Desktop. It needs
// internet access and a local runner image that carries this branch's
// scrutineer binary. Build the image with:
//
//	GOOS=linux GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -o "$TMP/scrutineer" ./cmd/scrutineer
//	printf 'FROM curlimages/curl:8.11.1\nCOPY scrutineer /usr/local/bin/scrutineer\n' > "$TMP/Dockerfile"
//	docker build -t scrutineer-egress-policy-test "$TMP"
//
// then run it with SCRUTINEER_TEST_EGRESS_POLICY_IMAGE=scrutineer-egress-policy-test
// go test -race -run EgressPolicy -v ./internal/worker/

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alpha-omega-security/harness"
	"github.com/alpha-omega-security/harness/container"

	"scrutineer/internal/egressgrant"
)

const plainCurlImage = "curlimages/curl:8.11.1"

// policyProbeScript records the curl outcome for each destination through the
// proxy plus one attempt that ignores the proxy entirely.
const policyProbeScript = `cd /work
probe() {
  name=$1; shift
  code=$("$@" 2>/work/$name.err)
  echo "$?" >/work/$name.exit
  echo "$code" >/work/$name.code
}
c='curl -sS -o /dev/null -w %{http_code} --max-time 15'
probe example_com $c https://example.com/
probe example_org $c https://example.org/
probe example_com_8443 $c https://example.com:8443/
probe direct env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy -u ALL_PROXY -u all_proxy curl -sS -o /dev/null -w %{http_code} --noproxy '*' --max-time 10 https://example.com/
`

type policyProbeHarness struct{ stubHarness }

func (policyProbeHarness) Binary() string            { return "sh" }
func (policyProbeHarness) Args(harness.Job) []string { return []string{"-c", policyProbeScript} }

type policyProbeResult struct {
	files  map[string]string
	events []Event
	err    error
}

func (r policyProbeResult) code(name string) string { return r.files[name+".code"] }
func (r policyProbeResult) exit(name string) string { return r.files[name+".exit"] }

func (r policyProbeResult) reached(name string) bool {
	return r.exit(name) == "0" && r.code(name) == "200"
}

func TestIntegration_EgressPolicyPerSkill(t *testing.T) {
	rt, image := policyIntegrationSetup(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer api.Close()
	_, apiPort, err := net.SplitHostPort(api.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	gatewayIP := ResolveHostGatewayIPv4(rt, image, "")
	if gatewayIP == "" {
		t.Fatal("host-gateway did not resolve on Docker Desktop")
	}
	alpha, _ := egressgrant.Parse([]string{"example.com:443"})
	beta, _ := egressgrant.Parse([]string{"example.org:443"})
	runner := ContainerRunner{
		Image:    image,
		Harness:  policyProbeHarness{},
		Hardened: true,
		Runtime:  rt,
		Egress: EgressSidecarConfig{
			Token:     NewProxyToken(),
			Allow:     []string{HostGatewayAlias},
			APIPort:   apiPort,
			GatewayIP: gatewayIP,
		},
		EgressPolicies: map[string][]EgressGrant{"alpha": alpha, "beta": beta},
	}

	results := map[string]*policyProbeResult{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, skill := range []string{"alpha", "beta"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := runPolicyProbe(t, runner, skill)
			mu.Lock()
			results[skill] = &res
			mu.Unlock()
		}()
	}
	wg.Wait()

	for _, skill := range []string{"alpha", "beta"} {
		res := results[skill]
		if res.err != nil {
			t.Fatalf("%s: RunSkill: %v", skill, res.err)
		}
		t.Logf("%s: example.com=%s/%s example.org=%s/%s example.com:8443=%s/%s direct=%s/%s", skill,
			res.exit("example_com"), res.code("example_com"), res.exit("example_org"), res.code("example_org"),
			res.exit("example_com_8443"), res.code("example_com_8443"), res.exit("direct"), res.code("direct"))
		if res.reached("direct") {
			t.Errorf("%s: direct connection bypassed the proxy", skill)
		}
		if res.exit("direct") == "0" {
			t.Errorf("%s: direct attempt exited 0 (code %s)", skill, res.code("direct"))
		}
		if res.reached("example_com_8443") {
			t.Errorf("%s: reached example.com on an undeclared port", skill)
		}
		if !hasEventPrefix(res.events, "egress-policy: skill="+skill+" grants=") {
			t.Errorf("%s: no egress-policy event in %v", skill, res.events)
		}
		if !hasEventPrefix(res.events, "egress-proxy: ") {
			t.Errorf("%s: no egress-proxy denial line in %v", skill, res.events)
		}
	}
	a, b := results["alpha"], results["beta"]
	if !a.reached("example_com") {
		t.Errorf("alpha could not reach example.com (exit %s code %s): %s; if the network is unreachable from Docker this test cannot pass", a.exit("example_com"), a.code("example_com"), a.files["example_com.err"])
	}
	if a.reached("example_org") {
		t.Error("alpha reached example.org without a grant")
	}
	if !b.reached("example_org") {
		t.Errorf("beta could not reach example.org (exit %s code %s): %s", b.exit("example_org"), b.code("example_org"), b.files["example_org.err"])
	}
	if b.reached("example_com") {
		t.Error("beta reached example.com without a grant")
	}
}

func TestIntegration_EgressPolicyInstallFailureRefusesScan(t *testing.T) {
	rt, _ := policyIntegrationSetup(t)
	if !imageExistsLocally(t.Context(), rt, plainCurlImage) {
		t.Skipf("image %q is unavailable locally", plainCurlImage)
	}
	gatewayIP := ResolveHostGatewayIPv4(rt, plainCurlImage, "")
	if gatewayIP == "" {
		t.Fatal("host-gateway did not resolve on Docker Desktop")
	}
	grants, _ := egressgrant.Parse([]string{"example.com:443"})
	runner := ContainerRunner{
		Image:          plainCurlImage,
		Harness:        policyProbeHarness{},
		Hardened:       true,
		Runtime:        rt,
		Egress:         EgressSidecarConfig{Token: NewProxyToken(), Allow: []string{HostGatewayAlias}, APIPort: "8080", GatewayIP: gatewayIP},
		EgressPolicies: map[string][]EgressGrant{"alpha": grants},
	}
	res := runPolicyProbe(t, runner, "alpha")
	if res.err == nil {
		t.Fatal("scan with grants ran although the sidecar image cannot enforce them")
	}
	if len(res.files) != 0 {
		t.Errorf("the skill ran despite the failed policy install: %v", res.files)
	}
}

func policyIntegrationSetup(t *testing.T) (ContainerRuntime, string) {
	t.Helper()
	image := os.Getenv("SCRUTINEER_TEST_EGRESS_POLICY_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_EGRESS_POLICY_IMAGE to run the egress policy integration")
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
	return rt, image
}

func runPolicyProbe(t *testing.T, runner ContainerRunner, skill string) policyProbeResult {
	t.Helper()
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The scan runs as a different uid on some runtimes; let it write results.
	if err := os.Chmod(work, 0o777); err != nil { //nolint:gosec // test workspace only
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []Event
	_, err := runner.RunSkill(t.Context(), SkillJob{
		IsolationKey: fmt.Sprintf("policy-%s-%d-%d", skill, os.Getpid(), time.Now().UnixNano()),
		WorkRoot:     work,
		SrcReady:     true,
		Name:         skill,
	}, func(e Event) { mu.Lock(); events = append(events, e); mu.Unlock() })
	files := map[string]string{}
	entries, _ := os.ReadDir(work)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if b, readErr := os.ReadFile(filepath.Join(work, e.Name())); readErr == nil {
			files[e.Name()] = strings.TrimSpace(string(b))
		}
	}
	return policyProbeResult{files: files, events: events, err: err}
}

func hasEventPrefix(events []Event, prefix string) bool {
	for _, e := range events {
		if strings.HasPrefix(e.Text, prefix) {
			return true
		}
	}
	return false
}
