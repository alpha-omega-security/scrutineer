package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// OpenAIRunner implements SkillRunner by calling the OpenAI-compatible chat
// completions API directly. This allows any OpenAI-compatible backend (OpenAI,
// Azure, Ollama, vLLM, LiteLLM, etc.) to run skills without the claude CLI.
type OpenAIRunner struct {
	BaseURL   string // e.g. "https://api.openai.com/v1"
	APIKey    string
	Model     string // fallback model; SkillJob.Model wins when set
	FullClone bool
	MaxTurns  int
}

// openAI request/response types (minimal subset needed for tool use).

type oaiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content,omitempty"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

type oaiToolCall struct {
	ID       string        `json:"id"`
	Type     string        `json:"type"`
	Function oaiToolCallFn `json:"function"`
}

type oaiToolCallFn struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type oaiTool struct {
	Type     string     `json:"type"`
	Function oaiToolDef `json:"function"`
}

type oaiToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type oaiRequest struct {
	Model    string       `json:"model"`
	Messages []oaiMessage `json:"messages"`
	Tools    []oaiTool    `json:"tools,omitempty"`
}

type oaiResponse struct {
	Choices []oaiChoice `json:"choices"`
	Usage   *oaiUsage   `json:"usage,omitempty"`
	Error   *oaiError   `json:"error,omitempty"`
}

type oaiChoice struct {
	Message      oaiMessage `json:"message"`
	FinishReason string     `json:"finish_reason"`
}

type oaiUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type oaiError struct {
	Message string `json:"message"`
}

// openAI timeouts and permissions.
const (
	chatCompletionTimeout = 10 * time.Minute
	webFetchTimeout       = 30 * time.Second
)

// tools exposed to the model inside the workspace.
var openAITools = []oaiTool{
	{Type: "function", Function: oaiToolDef{
		Name:        "read_file",
		Description: "Read the contents of a file relative to the workspace root.",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Relative file path"}},"required":["path"]}`),
	}},
	{Type: "function", Function: oaiToolDef{
		Name:        "write_file",
		Description: "Write content to a file relative to the workspace root. Creates parent directories.",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Relative file path"},"content":{"type":"string","description":"File content"}},"required":["path","content"]}`),
	}},
	{Type: "function", Function: oaiToolDef{
		Name:        "list_directory",
		Description: "List files and directories at a path relative to the workspace root.",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"Relative directory path (use . for root)"}},"required":["path"]}`),
	}},
	{Type: "function", Function: oaiToolDef{
		Name:        "run_command",
		Description: "Run a shell command in the workspace root. Returns stdout+stderr.",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"command":{"type":"string","description":"Shell command to execute"}},"required":["command"]}`),
	}},
	{Type: "function", Function: oaiToolDef{
		Name:        "web_fetch",
		Description: "Fetch a URL and return the response body as text.",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"URL to fetch"}},"required":["url"]}`),
	}},
}

func (o OpenAIRunner) RunSkill(ctx context.Context, sj SkillJob, emit func(Event)) (SkillResult, error) {
	src, err := ensureClone(ctx, sj.Repo, sj.WorkRoot, o.FullClone, sj.Ref, emit)
	if err != nil {
		return SkillResult{}, err
	}
	commit := gitHead(src)
	work := sj.WorkRoot

	var outPath string
	if sj.OutputFile != "" {
		outPath = filepath.Join(work, sj.OutputFile)
		_ = os.Remove(outPath)
	}

	// Build system prompt from the staged skill.
	skillMD, err := os.ReadFile(filepath.Join(sj.SkillDir, "SKILL.md"))
	if err != nil {
		return SkillResult{}, fmt.Errorf("read skill: %w", err)
	}
	schemaTxt := ""
	if b, err := os.ReadFile(filepath.Join(sj.SkillDir, "schema.json")); err == nil {
		schemaTxt = "\n\n## Output Schema\n```json\n" + string(b) + "\n```"
	}

	systemPrompt := fmt.Sprintf(
		"You are an automated analysis agent. Execute the following skill on the repository cloned at ./src.\n\n"+
			"--- SKILL ---\n%s\n--- END SKILL ---%s\n\n"+
			"The workspace root is your working directory. The cloned repository is at ./src/. "+
			"Context about the repository is in ./context.json. "+
			"Write your output to ./%s as specified by the skill.",
		string(skillMD), schemaTxt, sj.OutputFile,
	)

	model := sj.Model
	if model == "" {
		model = o.Model
	}

	emit(Event{Kind: KindText, Text: fmt.Sprintf("$ openai [%s] <skill:%s>", model, sj.Name)})

	messages := []oaiMessage{{Role: "system", Content: systemPrompt}}
	messages = append(messages, oaiMessage{Role: "user", Content: buildSkillPrompt(sj.Name, sj.OutputFile)})

	maxTurns := effectiveMaxTurns(sj.MaxTurns, o.MaxTurns)
	var totalInput, totalOutput int

	for turn := 0; turn < maxTurns; turn++ {
		resp, err := o.callAPI(ctx, model, messages)
		if err != nil {
			return SkillResult{Commit: commit}, fmt.Errorf("openai api: %w", err)
		}
		if resp.Error != nil {
			return SkillResult{Commit: commit}, fmt.Errorf("openai api error: %s", resp.Error.Message)
		}
		if resp.Usage != nil {
			totalInput += resp.Usage.PromptTokens
			totalOutput += resp.Usage.CompletionTokens
		}
		if len(resp.Choices) == 0 {
			return SkillResult{Commit: commit}, fmt.Errorf("openai: empty response")
		}

		choice := resp.Choices[0]
		msg := choice.Message

		// Emit any text content.
		if msg.Content != "" {
			emit(Event{Kind: KindText, Text: msg.Content})
		}

		// No tool calls means the model is done.
		if len(msg.ToolCalls) == 0 {
			break
		}

		// Append assistant message with tool calls.
		messages = append(messages, msg)

		// Execute each tool call.
		for _, tc := range msg.ToolCalls {
			emit(Event{Kind: KindTool, Tool: tc.Function.Name, Text: truncate(tc.Function.Arguments)})
			result := o.executeTool(ctx, work, tc.Function.Name, tc.Function.Arguments)
			messages = append(messages, oaiMessage{
				Role:       "tool",
				Content:    result,
				ToolCallID: tc.ID,
			})
		}

		if choice.FinishReason == "stop" {
			break
		}
	}

	emit(Event{
		Kind:  KindResult,
		Text:  "done",
		Turns: maxTurns,
		Usage: Usage{InputTokens: totalInput, OutputTokens: totalOutput},
	})

	res := SkillResult{Commit: commit}
	if outPath != "" {
		res.Report = readCappedReport(outPath, emit)
	}
	return res, nil
}

func (o OpenAIRunner) callAPI(ctx context.Context, model string, messages []oaiMessage) (*oaiResponse, error) {
	reqBody := oaiRequest{
		Model:    model,
		Messages: messages,
		Tools:    openAITools,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(o.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.APIKey)
	}

	client := &http.Client{Timeout: chatCompletionTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var oaiResp oaiResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &oaiResp, nil
}

func (o OpenAIRunner) executeTool(ctx context.Context, workRoot, name, argsJSON string) string {
	var args map[string]string
	_ = json.Unmarshal([]byte(argsJSON), &args)

	switch name {
	case "read_file":
		return o.toolReadFile(workRoot, args["path"])
	case "write_file":
		return o.toolWriteFile(workRoot, args["path"], args["content"])
	case "list_directory":
		return o.toolListDir(workRoot, args["path"])
	case "run_command":
		return o.toolRunCommand(ctx, workRoot, args["command"])
	case "web_fetch":
		return o.toolWebFetch(ctx, args["url"])
	default:
		return fmt.Sprintf("unknown tool: %s", name)
	}
}

func (o OpenAIRunner) toolReadFile(workRoot, path string) string {
	full := filepath.Join(workRoot, filepath.Clean(path))
	if !strings.HasPrefix(full, workRoot) {
		return "error: path escapes workspace"
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	if len(b) > maxReportBytes {
		return string(b[:maxReportBytes]) + "\n[truncated]"
	}
	return string(b)
}

func (o OpenAIRunner) toolWriteFile(workRoot, path, content string) string {
	full := filepath.Join(workRoot, filepath.Clean(path))
	if !strings.HasPrefix(full, workRoot) {
		return "error: path escapes workspace"
	}
	if err := os.MkdirAll(filepath.Dir(full), dirPerm); err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), filePerm); err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return "ok"
}

func (o OpenAIRunner) toolListDir(workRoot, path string) string {
	full := filepath.Join(workRoot, filepath.Clean(path))
	if !strings.HasPrefix(full, workRoot) {
		return "error: path escapes workspace"
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	var sb strings.Builder
	for _, e := range entries {
		if e.IsDir() {
			sb.WriteString(e.Name() + "/\n")
		} else {
			sb.WriteString(e.Name() + "\n")
		}
	}
	return sb.String()
}

func (o OpenAIRunner) toolRunCommand(ctx context.Context, workRoot, command string) string {
	if command == "" {
		return "error: empty command"
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = workRoot
	out, err := cmd.CombinedOutput()
	result := string(out)
	if err != nil {
		result += "\nexit: " + err.Error()
	}
	if len(result) > maxReportBytes {
		result = result[:maxReportBytes] + "\n[truncated]"
	}
	return result
}

func (o OpenAIRunner) toolWebFetch(ctx context.Context, url string) string {
	if url == "" {
		return "error: empty url"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	client := &http.Client{Timeout: webFetchTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxReportBytes))
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	return string(b)
}
