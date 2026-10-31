package worker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alpha-omega-security/harness/container"
)

// modelProxyCLIReply is the text the fake upstream streams back. The test
// looks for it in the scan's events to prove the real CLI completed a turn
// through the proxy.
const modelProxyCLIReply = "PROXY-OK"

// fakeAnthropicUpstream answers the Messages API the way the real CLI expects:
// a streamed message for stream:true, a plain JSON message otherwise plus a
// token count for count_tokens. Every request is recorded so the test can
// check what crossed the proxy.
type fakeAnthropicUpstream struct {
	mu       sync.Mutex
	requests []recordedModelRequest
}

type recordedModelRequest struct {
	method, path string
	header       http.Header
}

func (f *fakeAnthropicUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, recordedModelRequest{method: r.Method, path: r.URL.Path, header: r.Header.Clone()})
	f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/messages/count_tokens":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"input_tokens":1}`)
	case "/v1/messages":
		var req struct {
			Stream bool `json:"stream"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Stream {
			writeFakeMessageStream(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[{"type":"text","text":%q}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`, modelProxyCLIReply)
	default:
		http.NotFound(w, r)
	}
}

func writeFakeMessageStream(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	events := []string{
		`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}`,
		`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + modelProxyCLIReply + `"}}`,
		`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}`,
		`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}`,
		`event: message_stop` + "\n" + `data: {"type":"message_stop"}`,
	}
	rc := http.NewResponseController(w)
	for _, e := range events {
		_, _ = io.WriteString(w, e+"\n\n")
		_ = rc.Flush()
	}
}

func (f *fakeAnthropicUpstream) snapshot() []recordedModelRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedModelRequest(nil), f.requests...)
}

// TestIntegration_ModelProxyRealCLI runs the real claude CLI from the runner
// image through the -model-proxy path: RunSkill, the egress proxy's inspected
// forward hop and the model proxy, against a fake Anthropic upstream. It
// proves the CLI accepts the scan token and the plain http:// base URL, that
// every route it calls is on the allowlist, that its streamed turn completes
// and that the upstream only ever sees the real key.
func TestIntegration_ModelProxyRealCLI(t *testing.T) {
	image := os.Getenv("SCRUTINEER_TEST_MODEL_PROXY_CLI_IMAGE")
	if image == "" {
		t.Skip("set SCRUTINEER_TEST_MODEL_PROXY_CLI_IMAGE to a runner image with the claude CLI (e.g. ghcr.io/alpha-omega-security/scrutineer-runner:latest)")
	}
	rt, ok := container.DetectRuntime("docker")
	if !ok {
		t.Skip("docker is unavailable")
	}
	if !imageExistsLocally(t.Context(), rt, image) {
		t.Skipf("image %q is unavailable locally", image)
	}

	const realSecret = "sk-ant-REAL-CLI-INTEGRATION-SECRET"
	t.Setenv("ANTHROPIC_API_KEY", realSecret)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")

	fake := &fakeAnthropicUpstream{}
	upstream := httptest.NewServer(fake)
	defer upstream.Close()

	var proxyLog bytes.Buffer
	mp, err := NewModelProxy(upstream.URL, realSecret, slog.New(slog.NewTextHandler(&proxyLog, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// The listener the container reaches through the egress proxy, standing in
	// for the web server's root mux that serves ModelProxyPathPrefix.
	mux := http.NewServeMux()
	mux.Handle(ModelProxyPathPrefix+"/", mp)
	webListener := httptest.NewServer(mux)
	defer webListener.Close()
	_, webPort, err := net.SplitHostPort(webListener.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var egressLog bytes.Buffer
	token := NewProxyToken()
	egressPort, err := StartEgressProxy(&EgressProxy{
		Allow:    []string{HostGatewayAlias},
		Token:    token,
		APIPort:  webPort,
		APIHosts: []string{HostGatewayAlias},
		Log:      slog.New(slog.NewTextHandler(&egressLog, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	d := ContainerRunner{
		Image:         image,
		Runtime:       rt,
		Harness:       ClaudeHarness{},
		MaxTurns:      1,
		ProxyURL:      ProxyURLForHost(token, HostGatewayAlias, egressPort),
		ModelProxy:    mp,
		ModelProxyURL: "http://" + HostGatewayAlias + ":" + webPort + ModelProxyPathPrefix,
	}
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	var events []string
	job := SkillJob{
		WorkRoot: work,
		SrcReady: true,
		Name:     "model-proxy-cli-integration",
		Prompt:   "Reply with exactly " + modelProxyCLIReply + " and nothing else.",
		StateDir: t.TempDir(),
	}
	result, err := d.RunSkill(t.Context(), job, func(e Event) { events = append(events, e.Kind+": "+e.Text) })
	transcript := strings.Join(events, "\n")
	if err != nil {
		t.Fatalf("RunSkill: %v\nevents:\n%s\nmodel proxy log:\n%s\negress log:\n%s", err, transcript, proxyLog.String(), egressLog.String())
	}

	if !strings.Contains(transcript, modelProxyCLIReply) {
		t.Errorf("the CLI's turn never surfaced the streamed reply %q; events:\n%s", modelProxyCLIReply, transcript)
	}
	checkModelProxyCLIResumes(t, d, job, result.SessionID)
	requests := fake.snapshot()
	if len(requests) == 0 {
		t.Fatal("the CLI made no model request through the proxy")
	}
	for _, req := range requests {
		t.Logf("CLI request through the proxy: %s %s", req.method, req.path)
	}
	t.Logf("egress proxy log:\n%s", egressLog.String())
	for _, req := range requests {
		if got := req.header.Get("X-Api-Key"); got != realSecret {
			t.Errorf("%s %s reached the upstream with x-api-key %q, want the real key", req.method, req.path, got)
		}
		for name, values := range req.header {
			for _, v := range values {
				if strings.Contains(v, modelProxyTokenPrefix) {
					t.Errorf("%s %s forwarded the scan token in header %s", req.method, req.path, name)
				}
			}
		}
	}
	if strings.Contains(proxyLog.String(), "model proxy denied") || strings.Contains(proxyLog.String(), "upstream error") {
		t.Errorf("the model proxy refused or failed a CLI request:\n%s", proxyLog.String())
	}
	if strings.Contains(egressLog.String(), "egress denied") {
		t.Errorf("the egress proxy refused a CLI request:\n%s", egressLog.String())
	}
}

func checkModelProxyCLIResumes(t *testing.T, runner ContainerRunner, job SkillJob, savedSession string) {
	t.Helper()
	if savedSession == "" {
		t.Fatal("fresh run did not report a session")
	}
	for _, sessionID := range []string{savedSession, "11111111-1111-4111-8111-111111111111"} {
		job.ResumeSessionID = sessionID
		var events []string
		resumed, err := runner.RunSkill(t.Context(), job, func(e Event) {
			events = append(events, e.Kind+": "+e.Text)
		})
		transcript := strings.Join(events, "\n")
		if err != nil || resumed.SessionID == "" || !strings.Contains(transcript, modelProxyCLIReply) {
			t.Fatalf("resume %s: session=%q error=%v\nevents:\n%s", sessionID, resumed.SessionID, err, transcript)
		}
		missing := sessionID != savedSession
		if strings.Contains(transcript, "restarting fresh") != missing || (resumed.SessionID != sessionID) != missing {
			t.Fatalf("resume %s: unexpected fallback to %q\nevents:\n%s", sessionID, resumed.SessionID, transcript)
		}
		t.Logf("resume %s: resulting session=%s, fresh fallback=%v", sessionID, resumed.SessionID, missing)
	}
}
