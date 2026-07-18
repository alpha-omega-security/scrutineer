package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const objectSchema = `{"type":"object","required":["answer"],"additionalProperties":false,"properties":{"answer":{"type":"string"}}}`

func TestCall_requestsStructuredOutputAndReturnsUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "key" {
			t.Errorf("x-api-key = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != apiVersion {
			t.Errorf("anthropic-version = %q", got)
		}
		var request messageRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Model != "claude-sonnet-4-6" || request.MaxTokens != 64 {
			t.Errorf("request = %+v", request)
		}
		if len(request.Messages) != 1 || request.Messages[0] != (message{Role: "user", Content: "reply as JSON"}) {
			t.Errorf("messages = %+v", request.Messages)
		}
		if request.OutputConfig.Format.Type != "json_schema" || string(request.OutputConfig.Format.Schema) != objectSchema {
			t.Errorf("output_config = %+v", request.OutputConfig)
		}
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"{\"answer\":\"ok\"}"}],"usage":{"input_tokens":100,"output_tokens":12,"cache_read_input_tokens":30,"cache_creation_input_tokens":7}}`)
	}))
	defer server.Close()

	got, usage, err := Call(context.Background(), "reply as JSON", json.RawMessage(objectSchema), Options{
		Endpoint: server.URL + "/v1/messages", APIKey: "key", Model: "claude-sonnet-4-6", MaxTokens: 64, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"answer":"ok"}` {
		t.Errorf("result = %s", got)
	}
	if usage != (Usage{InputTokens: 100, OutputTokens: 12, CacheReadTokens: 30, CacheWriteTokens: 7}) {
		t.Errorf("usage = %+v", usage)
	}
}

func TestCall_crossOriginRedirectDropsAPIKey(t *testing.T) {
	var targetAPIKey string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetAPIKey = r.Header.Get("x-api-key")
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"{\"answer\":\"ok\"}"}],"usage":{}}`)
	}))
	defer target.Close()

	var sourceAPIKey string
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceAPIKey = r.Header.Get("x-api-key")
		http.Redirect(w, r, target.URL+"/v1/messages", http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := source.Client()
	if client.CheckRedirect != nil {
		t.Fatal("test client unexpectedly has a redirect policy")
	}
	_, _, err := Call(context.Background(), "reply as JSON", json.RawMessage(objectSchema), Options{
		Endpoint: source.URL + "/v1/messages", APIKey: "secret", Model: "claude-sonnet-4-6", MaxTokens: 64, HTTPClient: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sourceAPIKey != "secret" {
		t.Errorf("source x-api-key = %q, want credential on the original request", sourceAPIKey)
	}
	if targetAPIKey != "" {
		t.Errorf("redirect target received x-api-key = %q", targetAPIKey)
	}
	if client.CheckRedirect != nil {
		t.Error("Call mutated the caller-provided HTTP client's redirect policy")
	}
}

func TestSameOrigin(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"https://api.example.com/v1", "https://api.example.com/v2", true},
		{"https://api.example.com", "https://api.example.com:443/x", true},
		{"http://host:80", "http://host/y", true},
		{"https://api.example.com", "https://api.example.com:8443", false},
		{"https://api.example.com", "http://api.example.com", false},
		{"https://api.example.com", "https://evil.example.com", false},
	} {
		a, err := url.Parse(tt.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := url.Parse(tt.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := sameOrigin(a, b); got != tt.want {
			t.Errorf("sameOrigin(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCall_arrayStructuredOutput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"[1,2]"}],"usage":{}}`)
	}))
	defer server.Close()

	got, _, err := Call(context.Background(), "array", json.RawMessage(`{"type":"array","items":{"type":"integer"}}`), Options{
		Endpoint: server.URL, APIKey: "key", Model: "claude-sonnet-4-6", MaxTokens: 32, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `[1,2]` {
		t.Errorf("result = %s", got)
	}
}

func TestCall_malformedStructuredResponseStillReturnsUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"not JSON"}],"usage":{"input_tokens":9,"output_tokens":3}}`)
	}))
	defer server.Close()

	_, usage, err := Call(context.Background(), "object", json.RawMessage(objectSchema), Options{
		Endpoint: server.URL, APIKey: "key", Model: "claude-sonnet-4-6", MaxTokens: 32, HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("Call error = %v", err)
	}
	if usage.InputTokens != 9 || usage.OutputTokens != 3 {
		t.Errorf("usage = %+v, want returned despite validation failure", usage)
	}
}

func TestCall_rejectsAPIErrorsAndInvalidOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"type":"authentication_error","message":"bad key"}}`)
	}))
	defer server.Close()

	_, _, err := Call(context.Background(), "object", json.RawMessage(objectSchema), Options{
		Endpoint: server.URL, APIKey: "key", Model: "claude-sonnet-4-6", MaxTokens: 32, HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "authentication_error") {
		t.Fatalf("API error = %v", err)
	}
	_, _, err = Call(context.Background(), "object", json.RawMessage(objectSchema), Options{APIKey: "key", Model: "m"})
	if err == nil || !strings.Contains(err.Error(), "max tokens") {
		t.Fatalf("option error = %v", err)
	}
	_, _, err = Call(context.Background(), "object", json.RawMessage(`{`), Options{APIKey: "key", Model: "m", MaxTokens: 1})
	if err == nil || !strings.Contains(err.Error(), "schema is not valid JSON") {
		t.Fatalf("schema error = %v", err)
	}
	_, _, err = Call(context.Background(), "object", json.RawMessage(objectSchema), Options{
		Endpoint: "http://models.example.com/v1/messages", APIKey: "key", Model: "m", MaxTokens: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint must use https") {
		t.Fatalf("insecure endpoint error = %v", err)
	}
}
