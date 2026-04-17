package worker

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

type fakeRunner struct {
	res Result
	err error
}

func (f fakeRunner) Prompt(repo db.Repository, spec string) string { return "p:" + spec }

func (f fakeRunner) Run(ctx context.Context, job Job, emit func(Event)) (Result, error) {
	emit(Event{Kind: "text", Text: "cloning"})
	emit(Event{Kind: "result", CostUSD: 1.23, Turns: 5})
	return f.res, f.err
}

func TestRunClaudeRecordsResult(t *testing.T) {
	gdb, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobClaude, Status: db.ScanQueued, Model: "fake-model"}
	gdb.Create(&scan)

	report := `{"repository":"https://example.com/x","commit":"abc","spec_version":10,
	  "model":"test","date":"2026-01-01","languages":["Ruby"],"boundaries":[{"actor":"user","trusted":"no","controls":"input","source":"derived"}],
	  "inventory":[],"ruled_out":[],
	  "findings":[
	    {"id":"F1","sinks":["S1"],"title":"x","severity":"High","cwe":"CWE-79","location":"a.rb:1",
	     "trace":"backwards trace","boundary":"crosses user boundary","validation":"repro script","rating":"High because X"},
	    {"id":"F2","sinks":["S2"],"title":"y","severity":"Low","location":"b.rb:2",
	     "trace":"trace","boundary":"internal","validation":"confirmed","rating":"Low"}
	  ]}`
	w := &Worker{
		DB:     gdb,
		Log:    slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Runner: fakeRunner{res: Result{Commit: "abc", Report: report}},
	}

	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doClaude)(context.Background(), body); err != nil {
		t.Fatal(err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanDone {
		t.Errorf("status = %s", got.Status)
	}
	if got.Report != report || got.Commit != "abc" {
		t.Errorf("report/commit not saved: %+v", got)
	}
	if got.FindingsCount != 2 {
		t.Errorf("findings count = %d", got.FindingsCount)
	}
	var findings []db.Finding
	gdb.Where("scan_id = ?", got.ID).Find(&findings)
	if len(findings) != 2 {
		t.Fatalf("findings rows = %d", len(findings))
	}
	if findings[0].Severity != "High" || findings[0].CWE != "CWE-79" || findings[0].Trace == "" {
		t.Errorf("finding[0]: %+v", findings[0])
	}
	if got.CostUSD != 1.23 || got.Turns != 5 {
		t.Errorf("cost/turns not captured: %+v", got)
	}
	if got.Model != "fake-model" || got.Prompt == "" {
		t.Errorf("model/prompt not recorded: model=%q prompt=%q", got.Model, got.Prompt)
	}
	if got.Log == "" {
		t.Error("log empty")
	}
}
