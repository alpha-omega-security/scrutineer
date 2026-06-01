package worker

import (
	"strings"
	"testing"
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

func TestFormatEvent(t *testing.T) {
	e := Event{Kind: "tool", Tool: "Read", Text: "/tmp/x"}
	if s := FormatEvent(e); s != "[read] /tmp/x" {
		t.Errorf("got %q", s)
	}
}
