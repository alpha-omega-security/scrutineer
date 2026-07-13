package worker

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	KindThinking  = "thinking"
	KindText      = "text"
	KindTool      = "tool"
	KindResult    = "result"
	KindError     = "error"
	KindSession   = "session"
	KindRateLimit = "rate_limit"

	lineLimit = 300
)

// Event is one line of activity from a claude -p stream-json run, flattened
// into something a human can read in a log view.
type Event struct {
	Kind      string
	Tool      string // for KindTool
	Text      string
	CostUSD   float64        // for KindResult
	Turns     int            // for KindResult
	Usage     Usage          // for KindResult
	SessionID string         // for KindSession
	RateLimit *RateLimitInfo // for KindRateLimit
}

// RateLimitInfo is the subscription limit status claude-code reports in a
// rate_limit_event line; it feeds auto-resume and the usage page panel.
type RateLimitInfo struct {
	Status         string `json:"status"`
	OverageStatus  string `json:"overageStatus"`
	IsUsingOverage bool   `json:"isUsingOverage"`
	ResetsAt       int64  `json:"resetsAt"`
	Type           string `json:"rateLimitType"`
}

// ResetTime converts the epoch-seconds resetsAt into a UTC time, or nil when
// the event carried no usable reset (nil receiver or non-positive timestamp).
func (r *RateLimitInfo) ResetTime() *time.Time {
	if r == nil || r.ResetsAt <= 0 {
		return nil
	}
	t := time.Unix(r.ResetsAt, 0).UTC()
	return &t
}

func (r *RateLimitInfo) Rejected() bool {
	if r == nil {
		return false
	}
	if strings.EqualFold(r.Status, "rejected") {
		return true
	}
	// overageStatus:"rejected" is normal for accounts without extra-usage
	// billing; it only blocks when the account is currently using overage.
	return r.IsUsingOverage && strings.EqualFold(r.OverageStatus, "rejected")
}

// Usage is the token breakdown from a result event.
type Usage struct {
	InputTokens      int `json:"input_tokens"`
	OutputTokens     int `json:"output_tokens"`
	CacheReadTokens  int `json:"cache_read_input_tokens"`
	CacheWriteTokens int `json:"cache_creation_input_tokens"`
}

type streamMessage struct {
	Type          string          `json:"type"`
	Subtype       string          `json:"subtype"`
	SessionID     string          `json:"session_id"`
	Message       *assistantMsg   `json:"message"`
	Result        json.RawMessage `json:"result"`
	CostUSD       *float64        `json:"total_cost_usd"`
	NumTurns      *int            `json:"num_turns"`
	Usage         *Usage          `json:"usage"`
	Error         json.RawMessage `json:"error"`
	RateLimitInfo *RateLimitInfo  `json:"rate_limit_info"`
}

type assistantMsg struct {
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type     string          `json:"type"`
	Thinking string          `json:"thinking"`
	Text     string          `json:"text"`
	Name     string          `json:"name"`
	Input    json.RawMessage `json:"input"`
}

// ParseStream reads claude --output-format stream-json lines from r and
// calls emit for each event. Lines that fail to decode are passed through
// as text so nothing is silently dropped.
//
// Lines are read with bufio.Reader rather than bufio.Scanner so a single
// oversized line (a large thinking block, or a tool_use/tool_result echoing
// a big file) does not truncate the rest of the stream — which would lose
// the terminal result event carrying cost/turns/usage and the max-turns
// signal (#467). A read error other than EOF is surfaced as an error event.
func ParseStream(r io.Reader, emit func(Event)) {
	scanJSONL(r, emit, parseStreamLine)
}

func parseStreamLine(raw []byte, emit func(Event)) {
	line := strings.TrimSpace(string(raw))
	if line == "" {
		return
	}
	var msg streamMessage
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		emit(Event{Kind: KindText, Text: line})
		return
	}
	switch msg.Type {
	case "system":
		// The init system message is the first line of a run and is the
		// only reliable place to read the session id. Capturing it here
		// lets the worker persist it before the run finishes, so a crash
		// mid-run is resumable. It is also the signal a `--resume`
		// actually loaded the conversation: a resume that fails to find
		// the session emits no init at all (just an error and a result
		// carrying a brand-new throwaway session id), so the runner must
		// not treat the result's session id as "resume succeeded" — only
		// this init event counts.
		if msg.Subtype == "init" && msg.SessionID != "" {
			emit(Event{Kind: KindSession, SessionID: msg.SessionID})
		}
	case "assistant":
		emitAssistant(msg.Message, emit)
	case "result":
		emit(resultEvent(msg))
		if msg.Subtype == "error_max_turns" {
			emit(Event{Kind: KindError, Text: "hit max turns"})
		}
	case "error":
		var s string
		if json.Unmarshal(msg.Error, &s) != nil {
			s = string(msg.Error)
		}
		emit(Event{Kind: KindError, Text: s})
	case "rate_limit_event":
		if msg.RateLimitInfo != nil {
			emit(Event{Kind: KindRateLimit, RateLimit: msg.RateLimitInfo})
		}
	}
}

func emitAssistant(m *assistantMsg, emit func(Event)) {
	if m == nil {
		return
	}
	for _, b := range m.Content {
		switch b.Type {
		case "thinking":
			if b.Thinking != "" {
				emit(Event{Kind: KindThinking, Text: b.Thinking})
			}
		case "text":
			if b.Text != "" {
				emit(Event{Kind: KindText, Text: b.Text})
			}
		case "tool_use":
			emit(Event{Kind: KindTool, Tool: b.Name, Text: summariseInput(b.Name, b.Input)})
		}
	}
}

func resultEvent(msg streamMessage) Event {
	ev := Event{Kind: KindResult}
	if len(msg.Result) > 0 {
		var s string
		if json.Unmarshal(msg.Result, &s) == nil {
			ev.Text = s
		} else {
			ev.Text = string(msg.Result)
		}
	}
	if msg.CostUSD != nil {
		ev.CostUSD = *msg.CostUSD
	}
	if msg.NumTurns != nil {
		ev.Turns = *msg.NumTurns
	}
	if msg.Usage != nil {
		ev.Usage = *msg.Usage
	}
	return ev
}

func summariseInput(tool string, raw json.RawMessage) string {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	// Harnesses disagree on tool-name casing (claude reports "Bash", codex
	// and opencode report "bash"); match case-insensitively so every
	// harness gets the concise summary instead of raw JSON.
	switch strings.ToLower(tool) {
	case "bash", "shell":
		if c, _ := m["command"].(string); c != "" {
			return c
		}
	case "read", "write", "edit":
		for _, k := range []string{"file_path", "path"} {
			if p, _ := m[k].(string); p != "" {
				return p
			}
		}
	case "grep", "glob":
		if p, _ := m["pattern"].(string); p != "" {
			return p
		}
	}
	if len(raw) > 0 {
		return truncate(string(raw))
	}
	return ""
}

func truncate(s string) string {
	if len(s) <= lineLimit {
		return s
	}
	return s[:lineLimit] + fmt.Sprintf("… (%d chars)", len(s))
}

// FormatEvent renders an Event as one log line.
func FormatEvent(e Event) string {
	switch e.Kind {
	case KindThinking:
		return "[thinking] " + truncate(e.Text)
	case KindTool:
		return fmt.Sprintf("[%s] %s", strings.ToLower(e.Tool), truncate(e.Text))
	case KindResult:
		return fmt.Sprintf("[result] cost=$%.4f turns=%d %s", e.CostUSD, e.Turns, truncate(e.Text))
	case KindSession:
		return "[session] " + e.SessionID
	case KindRateLimit:
		if e.RateLimit == nil {
			return "[rate-limit]"
		}
		line := "[rate-limit] " + e.RateLimit.Type + " " + e.RateLimit.Status
		if t := e.RateLimit.ResetTime(); t != nil {
			line += " resets " + t.Format("2006-01-02 15:04 UTC")
		}
		return line
	case KindError:
		return "[error] " + e.Text
	default:
		return e.Text
	}
}
