package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

const testSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["tier"],
  "additionalProperties": false,
  "properties": {
    "tier":    {"type": "string", "enum": ["ready", "partial", "unprepared"]},
    "summary": {"type": "string"}
  }
}`

func TestValidateReportSchema_valid(t *testing.T) {
	got := validateReportSchema(testSchema, `{"tier":"ready","summary":"ok"}`)
	if got != "" {
		t.Errorf("expected no validation error, got %q", got)
	}
}

func TestValidateReportSchema_failures(t *testing.T) {
	tests := []struct {
		name   string
		report string
		want   string
	}{
		{"wrong type", `{"tier":{"x":1}}`, "/tier"},
		{"missing required", `{"summary":"x"}`, "tier"},
		{"bad enum", `{"tier":"great"}`, "/tier"},
		{"extra prop", `{"tier":"ready","extra":1}`, "additional"},
		{"not json", `not json`, "report.json is not valid JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validateReportSchema(testSchema, tc.report)
			if got == "" {
				t.Fatalf("expected validation failure, got none")
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("output %q does not mention %q", got, tc.want)
			}
		})
	}
}

func TestValidateReportSchema_malformedSchema(t *testing.T) {
	if got := validateReportSchema(`not json`, `{}`); !strings.Contains(got, "schema.json is not valid JSON") {
		t.Errorf("got %q", got)
	}
	if got := validateReportSchema(`{"type":42}`, `{}`); !strings.Contains(got, "schema.json could not be compiled") {
		t.Errorf("got %q", got)
	}
}

func TestValidateReportSchema_capsErrorCount(t *testing.T) {
	schema := `{"type":"object","properties":{
		"a":{"type":"string"},"b":{"type":"string"},"c":{"type":"string"},
		"d":{"type":"string"},"e":{"type":"string"},"f":{"type":"string"},
		"g":{"type":"string"},"h":{"type":"string"},"i":{"type":"string"},
		"j":{"type":"string"}}}`
	report := `{"a":1,"b":1,"c":1,"d":1,"e":1,"f":1,"g":1,"h":1,"i":1,"j":1}`
	got := validateReportSchema(schema, report)
	lines := strings.Count(got, "\n") + 1
	if lines > maxSchemaErrors+1 {
		t.Errorf("output has %d lines, want at most %d (cap + ellipsis): %q", lines, maxSchemaErrors+1, got)
	}
	if !strings.Contains(got, "more)") {
		t.Errorf("expected ellipsis line, got %q", got)
	}
}

func newSchemaTestWorker(t *testing.T, strict bool) (*Worker, *db.Skill, *db.Scan) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name: "posture-test", Description: "d", Body: "b",
		OutputFile: "report.json", OutputKind: "posture",
		SchemaJSON: testSchema, Version: 1, Active: true, Source: "ui",
	}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanRunning, SkillID: &skill.ID}
	gdb.Create(&scan)
	w := &Worker{
		DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir: t.TempDir(), SchemaStrict: strict,
	}
	return w, &skill, &scan
}

func TestParseSkillOutput_schemaWarnAndContinue(t *testing.T) {
	w, skill, scan := newSchemaTestWorker(t, false)

	// "extra" violates additionalProperties:false so schema fails, but the
	// posture parser only decodes tier+summary and ignores unknown keys.
	report := `{"tier":"ready","summary":"ok","extra":1}`
	var events []Event
	err := w.parseSkillOutput(skill, scan, report, func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatalf("warn mode should not return error: %v", err)
	}

	var sawSchemaErr, sawParserSuccess bool
	for _, e := range events {
		if e.Kind == KindError && strings.Contains(e.Text, "schema:") {
			sawSchemaErr = true
		}
		if strings.Contains(e.Text, "posture: ready") {
			sawParserSuccess = true
		}
	}
	if !sawSchemaErr {
		t.Error("expected schema error event in log")
	}
	if !sawParserSuccess {
		t.Error("expected posture parser to run after schema warning")
	}

	var repo db.Repository
	w.DB.First(&repo, scan.RepositoryID)
	if repo.Posture != "ready" {
		t.Errorf("repo.Posture = %q, want ready (parser should have run)", repo.Posture)
	}
}

func TestParseSkillOutput_schemaStrictFails(t *testing.T) {
	w, skill, scan := newSchemaTestWorker(t, true)

	report := `{"tier":{"x":1}}`
	var events []Event
	err := w.parseSkillOutput(skill, scan, report, func(e Event) { events = append(events, e) })

	var sve *SchemaValidationError
	if !errors.As(err, &sve) {
		t.Fatalf("expected *SchemaValidationError, got %T: %v", err, err)
	}
	if sve.Skill != "posture-test" {
		t.Errorf("Skill = %q, want posture-test", sve.Skill)
	}
	if !strings.Contains(sve.Detail, "/tier") {
		t.Errorf("Detail = %q, want mention of /tier", sve.Detail)
	}

	var repo db.Repository
	w.DB.First(&repo, scan.RepositoryID)
	if repo.Posture != "" {
		t.Errorf("repo.Posture = %q, want empty (parser should not have run)", repo.Posture)
	}
}

func TestParseSkillOutput_schemaStrictPassesThrough(t *testing.T) {
	w, skill, scan := newSchemaTestWorker(t, true)

	report := `{"tier":"partial","summary":"ok"}`
	if err := w.parseSkillOutput(skill, scan, report, func(Event) {}); err != nil {
		t.Fatalf("valid report should not error in strict mode: %v", err)
	}
	var repo db.Repository
	w.DB.First(&repo, scan.RepositoryID)
	if repo.Posture != "partial" {
		t.Errorf("repo.Posture = %q, want partial", repo.Posture)
	}
}

func TestWrap_schemaStrictKeepsReportOnFailure(t *testing.T) {
	gdb, err := db.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/x", Name: "x"}
	gdb.Create(&repo)
	skill := db.Skill{
		Name: "posture-test", Description: "d", Body: "b",
		OutputFile: "report.json", OutputKind: "posture",
		SchemaJSON: testSchema, Version: 1, Active: true, Source: "ui",
	}
	gdb.Create(&skill)
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued,
		SkillID: &skill.ID, Model: "fake"}
	gdb.Create(&scan)

	report := `{"tier":{"x":1}}`
	w := &Worker{
		DB: gdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		DataDir:      t.TempDir(),
		SchemaStrict: true,
		Runner:       fakeRunner{skillRes: SkillResult{Commit: "abc", Report: report}},
	}
	body, _ := json.Marshal(queue.Payload{ScanID: scan.ID})
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatalf("wrap should save and return nil, got %v", err)
	}

	var got db.Scan
	gdb.First(&got, scan.ID)
	if got.Status != db.ScanFailed {
		t.Errorf("Status = %s, want failed", got.Status)
	}
	if got.Report != report {
		t.Errorf("Report = %q, want preserved %q", got.Report, report)
	}
	if !strings.Contains(got.Error, "schema validation") {
		t.Errorf("Error = %q, want mention of schema validation", got.Error)
	}
}

func TestParseSkillOutput_noSchemaSkipsValidation(t *testing.T) {
	w, skill, scan := newSchemaTestWorker(t, true)
	skill.SchemaJSON = ""

	if err := w.parseSkillOutput(skill, scan, `{"tier":"ready"}`, func(Event) {}); err != nil {
		t.Fatalf("no schema should skip validation: %v", err)
	}
}
