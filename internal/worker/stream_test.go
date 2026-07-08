package worker

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestParseStream(t *testing.T) {
	in := `
{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"hmm"}]}}
{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"ls -la"}}]}}
{"type":"assistant","message":{"content":[{"type":"text","text":"done"}]}}
not json at all
{"type":"result","result":"ok","total_cost_usd":0.42,"num_turns":7,"duration_ms":1000,"usage":{"input_tokens":10,"output_tokens":66,"cache_read_input_tokens":1200,"cache_creation_input_tokens":34000}}

`
	var got []Event
	ParseStream(strings.NewReader(in), func(e Event) { got = append(got, e) })

	if len(got) != 5 {
		t.Fatalf("want 5 events, got %d: %+v", len(got), got)
	}
	if got[0].Kind != KindThinking || got[0].Text != "hmm" {
		t.Errorf("ev0: %+v", got[0])
	}
	if got[1].Kind != KindTool || got[1].Tool != "Bash" || got[1].Text != "ls -la" {
		t.Errorf("ev1: %+v", got[1])
	}
	if got[2].Kind != KindText || got[2].Text != "done" {
		t.Errorf("ev2: %+v", got[2])
	}
	if got[3].Kind != KindText || got[3].Text != "not json at all" {
		t.Errorf("ev3 passthrough: %+v", got[3])
	}
	if got[4].Kind != KindResult || got[4].CostUSD != 0.42 || got[4].Turns != 7 {
		t.Errorf("ev4: %+v", got[4])
	}
	wantU := Usage{InputTokens: 10, OutputTokens: 66, CacheReadTokens: 1200, CacheWriteTokens: 34000}
	if got[4].Usage != wantU {
		t.Errorf("ev4 usage: %+v", got[4].Usage)
	}
}

func TestParseStream_RateLimitEvent(t *testing.T) {
	// The exact shape claude-code emits on a subscription run.
	in := `{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1782990000,"rateLimitType":"five_hour","overageStatus":"rejected","isUsingOverage":false}}` + "\n"
	var got []Event
	ParseStream(strings.NewReader(in), func(e Event) { got = append(got, e) })
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d: %+v", len(got), got)
	}
	rl := got[0].RateLimit
	if got[0].Kind != KindRateLimit || rl == nil {
		t.Fatalf("ev0: %+v", got[0])
	}
	if rl.Status != "allowed" || rl.OverageStatus != "rejected" || rl.IsUsingOverage || rl.Type != "five_hour" || rl.ResetsAt != 1782990000 {
		t.Errorf("rate_limit_info = %+v", rl)
	}
	if reset := rl.ResetTime(); reset == nil || reset.Unix() != 1782990000 {
		t.Errorf("ResetTime() = %v", reset)
	}
}

func TestRateLimitInfo_ResetTime_Absent(t *testing.T) {
	if (*RateLimitInfo)(nil).ResetTime() != nil {
		t.Error("nil receiver should yield nil reset")
	}
	if (&RateLimitInfo{ResetsAt: 0}).ResetTime() != nil {
		t.Error("zero resetsAt should yield nil reset")
	}
}

func TestParseStream_SessionID(t *testing.T) {
	in := `
{"type":"system","subtype":"init","session_id":"sess-abc","tools":[]}
{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}
{"type":"result","subtype":"success","session_id":"sess-abc","result":"ok","num_turns":2}
`
	var sessions []string
	ParseStream(strings.NewReader(in), func(e Event) {
		if e.Kind == KindSession {
			sessions = append(sessions, e.SessionID)
		}
	})

	// Only the init message yields a session event; the result's session id
	// is deliberately ignored so a failed --resume (which emits no init but
	// a result carrying a throwaway id) isn't mistaken for a loaded session.
	if len(sessions) != 1 {
		t.Fatalf("want 1 session event, got %d: %v", len(sessions), sessions)
	}
	if sessions[0] != "sess-abc" {
		t.Errorf("session id = %q, want sess-abc", sessions[0])
	}
}

func TestParseStream_FailedResumeEmitsNoSession(t *testing.T) {
	// A --resume that can't find the conversation emits no init event, just
	// an error line and a result with a fresh throwaway session id. The
	// runner relies on seeing no session event here to fall back to a fresh
	// run, so this must produce zero KindSession events.
	in := `No conversation found with session ID: dead
{"type":"result","subtype":"error_during_execution","is_error":true,"session_id":"throwaway-id","num_turns":0}`
	for _, e := range collectEvents(in) {
		if e.Kind == KindSession {
			t.Errorf("unexpected session event: %+v", e)
		}
	}
}

func collectEvents(in string) []Event {
	var got []Event
	ParseStream(strings.NewReader(in), func(e Event) { got = append(got, e) })
	return got
}

// A single >1 MiB stream-json line (a large thinking block, or a
// tool_use/tool_result echoing a big file) must not truncate the rest of the
// stream: the terminal result event carries cost/turns/usage and the
// max-turns signal, so dropping it silently mis-records the scan (#467).
func TestParseStream_oversizedLineDoesNotTruncate(t *testing.T) {
	huge := `{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"` +
		strings.Repeat("x", 2*1024*1024) + `"}]}}`
	in := huge + "\n" +
		`{"type":"assistant","message":{"content":[{"type":"text","text":"after"}]}}` + "\n" +
		`{"type":"result","subtype":"error_max_turns","total_cost_usd":1.5,"num_turns":40}` + "\n"

	got := collectEvents(in)

	var sawAfter, sawResult, sawMaxTurns bool
	for _, e := range got {
		switch {
		case e.Kind == KindText && e.Text == "after":
			sawAfter = true
		case e.Kind == KindResult:
			sawResult = true
			if e.CostUSD != 1.5 || e.Turns != 40 {
				t.Errorf("result event = %+v, want cost=1.5 turns=40", e)
			}
		case e.Kind == KindError && e.Text == "hit max turns":
			sawMaxTurns = true
		}
	}
	if !sawAfter {
		t.Error("event after the oversized line was dropped")
	}
	if !sawResult {
		t.Error("terminal result event was dropped")
	}
	if !sawMaxTurns {
		t.Error("max-turns error event was dropped")
	}
	// The oversized line itself must still parse, not be dropped.
	if got[0].Kind != KindThinking || len(got[0].Text) != 2*1024*1024 {
		t.Errorf("oversized thinking event: kind=%q len=%d", got[0].Kind, len(got[0].Text))
	}
}

// A final line with no trailing newline (the process closed stdout without
// flushing one) must still be parsed, not silently lost on EOF.
func TestParseStream_finalLineWithoutNewline(t *testing.T) {
	in := `{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}` + "\n" +
		`{"type":"result","total_cost_usd":0.1,"num_turns":3}`
	got := collectEvents(in)
	if len(got) != 2 || got[1].Kind != KindResult || got[1].Turns != 3 {
		t.Errorf("events = %+v, want text + result", got)
	}
}

// A read error other than EOF is surfaced as an error event so a broken pipe
// or short read is visible in the scan log rather than swallowed.
func TestParseStream_readErrorIsEmitted(t *testing.T) {
	r := io.MultiReader(
		strings.NewReader(`{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]}}`+"\n"),
		iotest.ErrReader(errors.New("pipe broke")),
	)
	var got []Event
	ParseStream(r, func(e Event) { got = append(got, e) })

	if len(got) != 2 {
		t.Fatalf("events = %+v, want text + error", got)
	}
	if got[1].Kind != KindError || !strings.Contains(got[1].Text, "pipe broke") {
		t.Errorf("last event = %+v, want error carrying the read error", got[1])
	}
}

func TestFormatEvent(t *testing.T) {
	e := Event{Kind: "tool", Tool: "Read", Text: "/tmp/x"}
	if s := FormatEvent(e); s != "[read] /tmp/x" {
		t.Errorf("got %q", s)
	}
}

func TestSummariseInput_caseInsensitive(t *testing.T) {
	// claude reports "Bash", codex/opencode report "bash"; both must
	// summarise to the command string, not the raw JSON.
	tests := []struct {
		tool, raw, want string
	}{
		{"Bash", `{"command":"ls -la"}`, "ls -la"},
		{"bash", `{"command":"ls -la"}`, "ls -la"},
		{"Read", `{"file_path":"/tmp/x"}`, "/tmp/x"},
		{"read", `{"path":"/tmp/x"}`, "/tmp/x"},
		{"grep", `{"pattern":"foo"}`, "foo"},
		{"unknown", `{"x":1}`, `{"x":1}`},
	}
	for _, tt := range tests {
		if got := summariseInput(tt.tool, json.RawMessage(tt.raw)); got != tt.want {
			t.Errorf("summariseInput(%q, %s) = %q, want %q", tt.tool, tt.raw, got, tt.want)
		}
	}
}
