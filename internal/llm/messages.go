// Package llm provides small, structured one-shot model calls for work that
// does not need a full agent workspace or tool loop.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	DefaultEndpoint = "https://api.anthropic.com/v1/messages"
	apiVersion      = "2023-06-01"
	maxResponseSize = 10 << 20
	maxErrorSize    = 32 << 10
)

// Options configures one Anthropic Messages API request. Endpoint is the full
// Messages endpoint, which lets deployments use a compatible proxy. APIKey,
// Model, and MaxTokens are required so each call's billing and output budget
// are explicit at the call site.
type Options struct {
	Endpoint   string
	APIKey     string
	Model      string
	MaxTokens  int
	HTTPClient *http.Client
}

// Usage is the token accounting reported by the Messages API. Cache creation
// maps to CacheWriteTokens so worker scan accounting uses the same fields as
// harness result events.
type Usage struct {
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	CacheReadTokens  int `json:"cache_read_input_tokens"`
	CacheWriteTokens int `json:"cache_creation_input_tokens"`
}

type messageRequest struct {
	Model        string       `json:"model"`
	MaxTokens    int          `json:"max_tokens"`
	Messages     []message    `json:"messages"`
	OutputConfig outputConfig `json:"output_config"`
}

type outputConfig struct {
	Format structuredOutputFormat `json:"format"`
}

type structuredOutputFormat struct {
	Type   string          `json:"type"`
	Schema json.RawMessage `json:"schema"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messageResponse struct {
	Content []contentBlock `json:"content"`
	Usage   Usage          `json:"usage"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type apiError struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// Call sends prompt as one user turn and requests a response constrained to
// schema through Anthropic structured outputs. Usage is returned when the API
// response itself is valid but its structured text is malformed, so callers can
// still record billable requests.
//
// POST calls are intentionally not retried: the provider may have accepted a
// timed-out request, and retrying would risk paying for duplicate inference.
func Call(ctx context.Context, prompt string, schema json.RawMessage, opts Options) (json.RawMessage, Usage, error) {
	if !json.Valid(schema) {
		return nil, Usage{}, fmt.Errorf("llm: schema is not valid JSON")
	}
	if strings.TrimSpace(opts.APIKey) == "" {
		return nil, Usage{}, fmt.Errorf("llm: API key is required")
	}
	if strings.TrimSpace(opts.Model) == "" {
		return nil, Usage{}, fmt.Errorf("llm: model is required")
	}
	if opts.MaxTokens <= 0 {
		return nil, Usage{}, fmt.Errorf("llm: max tokens must be positive")
	}

	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	body, err := json.Marshal(messageRequest{
		Model:     opts.Model,
		MaxTokens: opts.MaxTokens,
		Messages: []message{
			{Role: "user", Content: prompt},
		},
		OutputConfig: outputConfig{Format: structuredOutputFormat{
			Type: "json_schema", Schema: schema,
		}},
	})
	if err != nil {
		return nil, Usage{}, fmt.Errorf("llm: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, Usage{}, fmt.Errorf("llm: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", opts.APIKey)
	req.Header.Set("anthropic-version", apiVersion)

	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, Usage{}, fmt.Errorf("llm: messages request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, Usage{}, responseError(resp)
	}

	data, err := readLimited(resp.Body, maxResponseSize)
	if err != nil {
		return nil, Usage{}, fmt.Errorf("llm: read response: %w", err)
	}
	var decoded messageResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, Usage{}, fmt.Errorf("llm: decode response: %w", err)
	}
	result := json.RawMessage(strings.TrimSpace(responseText(decoded.Content)))
	if !json.Valid(result) {
		return nil, decoded.Usage, fmt.Errorf("llm: structured response is not valid JSON")
	}
	return result, decoded.Usage, nil
}

func responseText(blocks []contentBlock) string {
	var text strings.Builder
	for _, block := range blocks {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	return text.String()
}

func responseError(resp *http.Response) error {
	body, err := readLimited(resp.Body, maxErrorSize)
	if err != nil {
		return fmt.Errorf("llm: messages API returned %s", resp.Status)
	}
	var apiErr apiError
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Error.Message != "" {
		if apiErr.Error.Type != "" {
			return fmt.Errorf("llm: messages API %s: %s: %s", resp.Status, apiErr.Error.Type, apiErr.Error.Message)
		}
		return fmt.Errorf("llm: messages API %s: %s", resp.Status, apiErr.Error.Message)
	}
	return fmt.Errorf("llm: messages API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d byte limit", limit)
	}
	return data, nil
}
