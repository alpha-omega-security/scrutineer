package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const objectSchema = `{"type":"object","required":["answer"],"additionalProperties":false,"properties":{"answer":{"type":"string"}}}`

func TestCall_objectContinuationAndUsage(t *testing.T) {
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
		if len(request.Messages) != 2 || request.Messages[1] != (message{Role: "assistant", Content: "{"}) {
			t.Errorf("messages = %+v", request.Messages)
		}
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"\"answer\":\"ok\"}"}],"usage":{"input_tokens":100,"output_tokens":12,"cache_read_input_tokens":30,"cache_creation_input_tokens":7}}`)
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

func TestCall_arrayContinuation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"1,2]"}],"usage":{}}`)
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

func TestExtractJSON(t *testing.T) {
	for _, tc := range []struct {
		text string
		want string
	}{
		{`{"answer":"bare"}`, `{"answer":"bare"}`},
		{"Here is the result:\n```json\n{\"answer\":\"fenced\"}\n```", `{"answer":"fenced"}`},
		{"analysis first [1, 2] trailing prose", `[1, 2]`},
	} {
		got, err := ExtractJSON(tc.text)
		if err != nil {
			t.Fatalf("ExtractJSON(%q): %v", tc.text, err)
		}
		if string(got) != tc.want {
			t.Errorf("ExtractJSON(%q) = %s, want %s", tc.text, got, tc.want)
		}
	}
}

func TestCall_validationFailureStillReturnsUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"\"wrong\":true}"}],"usage":{"input_tokens":9,"output_tokens":3}}`)
	}))
	defer server.Close()

	_, usage, err := Call(context.Background(), "object", json.RawMessage(objectSchema), Options{
		Endpoint: server.URL, APIKey: "key", Model: "claude-sonnet-4-6", MaxTokens: 32, HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
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
}
