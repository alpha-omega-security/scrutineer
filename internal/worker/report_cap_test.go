package worker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadCappedReport_normalSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var events []Event
	emit := func(e Event) { events = append(events, e) }
	got := readCappedReport(path, emit)

	if got != `{"ok":true}` {
		t.Errorf("body = %q, want full contents", got)
	}
	if len(events) != 0 {
		t.Errorf("expected no truncation event, got %+v", events)
	}
}

func TestReadCappedReport_truncatesOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	// Write 50 MB + 1 KB so we cross the cap.
	payload := make([]byte, (50<<20)+1024)
	for i := range payload {
		payload[i] = 'x'
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	var events []Event
	emit := func(e Event) { events = append(events, e) }
	got := readCappedReport(path, emit)

	if len(got) != maxReportBytes {
		t.Errorf("got %d bytes, want exactly %d (cap)", len(got), maxReportBytes)
	}
	if len(events) == 0 || !strings.Contains(events[0].Text, "truncating") {
		t.Errorf("expected a truncation log event, got %+v", events)
	}
}

func TestReadCappedReport_missingFileIsEmpty(t *testing.T) {
	got := readCappedReport("/nonexistent/never-written.json", func(Event) {})
	if got != "" {
		t.Errorf("missing file should return empty, got %q", got)
	}
}

func TestReadCappedReport_refusesSymlink(t *testing.T) {
	const secret = `{"host_secret":"do-not-emit"}`
	target := filepath.Join(t.TempDir(), "host-secret.json")
	if err := os.WriteFile(target, []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	if err := os.Symlink(target, report); err != nil {
		t.Fatal(err)
	}

	var events []Event
	if got := readCappedReport(report, func(e Event) { events = append(events, e) }); got != "" {
		t.Errorf("symlinked report returned target contents %q, want empty", got)
	}
	for _, event := range events {
		if strings.Contains(event.Text, secret) {
			t.Errorf("symlinked report leaked target contents in event %q", event.Text)
		}
	}
}

func TestReadCappedReport_refusesLinkToWorkspaceFile(t *testing.T) {
	work := t.TempDir()
	const token = `{"scrutineer":{"token":"secret-token"}}`
	if err := os.WriteFile(filepath.Join(work, "context.json"), []byte(token), 0o644); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(work, "report.json")
	if err := os.Symlink("context.json", report); err != nil {
		t.Fatal(err)
	}
	if got := readCappedReport(report, func(Event) {}); got != "" {
		t.Errorf("report linked to context.json returned %q, want empty", got)
	}
}
