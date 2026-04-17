package worker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	KindThinking = "thinking"
	KindText     = "text"
	KindTool     = "tool"
	KindResult   = "result"
	KindError    = "error"

	lineLimit = 300
)

// Event is one line of activity from a claude -p stream-json run, flattened
// into something a human can read in a log view.
type Event struct {
	Kind    string
	Tool    string  // for KindTool
	Text    string
	CostUSD float64 // for KindResult
	Turns   int     // for KindResult
}

type streamMessage struct {
	Type     string          `json:"type"`
	Subtype  string          `json:"subtype"`
	Message  *assistantMsg   `json:"message"`
	Result   json.RawMessage `json:"result"`
	CostUSD  *float64        `json:"total_cost_usd"`
	Duration *int64          `json:"duration_ms"`
	NumTurns *int            `json:"num_turns"`
	Error    json.RawMessage `json:"error"`
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
func ParseStream(r io.Reader, emit func(Event)) {
	const bufSize = 1024 * 1024
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, bufSize), bufSize)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var msg streamMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			emit(Event{Kind: KindText, Text: line})
			continue
		}
		switch msg.Type {
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
	return ev
}

func summariseInput(tool string, raw json.RawMessage) string {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	switch tool {
	case "Bash":
		if c, _ := m["command"].(string); c != "" {
			return c
		}
	case "Read", "Write", "Edit":
		if p, _ := m["file_path"].(string); p != "" {
			return p
		}
	case "Grep", "Glob":
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
	case KindError:
		return "[error] " + e.Text
	default:
		return e.Text
	}
}
