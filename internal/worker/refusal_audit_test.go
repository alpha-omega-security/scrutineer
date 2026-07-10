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
)

func TestParseRefusalAudit(t *testing.T) {
	valid := `{"refused":false,"reason":null,"skipped":[{"path":"src/parser.c","reason":"obfuscated generated code"}]}`
	audit, err := parseRefusalAudit(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !audit.warning() {
		t.Error("audit with skipped paths should warn")
	}

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"refusal without reason", `{"refused":true,"reason":"","skipped":[]}`, "reason"},
		{"skipped without path", `{"refused":false,"reason":"","skipped":[{"reason":"partial"}]}`, "repository-relative"},
		{"unknown field", `{"refused":false,"reason":"","skipped":[],"extra":true}`, "valid JSON"},
		{"null", `null`, "one JSON object"},
		{"two documents", `{"refused":false,"reason":"","skipped":[]} {}`, "one JSON object"},
		{"absolute skipped path", `{"refused":false,"reason":null,"skipped":[{"path":"/etc/passwd","reason":"outside repo"}]}`, "repository-relative"},
		{"backslash skipped path", `{"refused":false,"reason":null,"skipped":[{"path":"src\\parser.c","reason":"outside repo"}]}`, "repository-relative"},
		{"windows drive skipped path", `{"refused":false,"reason":null,"skipped":[{"path":"C:/temp/file","reason":"outside repo"}]}`, "repository-relative"},
		{"parent skipped path", `{"refused":false,"reason":null,"skipped":[{"path":"src/../secret","reason":"outside repo"}]}`, "repository-relative"},
		{"empty skipped segment", `{"refused":false,"reason":null,"skipped":[{"path":"src//parser.c","reason":"outside repo"}]}`, "repository-relative"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRefusalAudit(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("parseRefusalAudit() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDoSkill_recordsRefusalAudit(t *testing.T) {
	runner := &sequenceRunner{results: []SkillResult{
		{SessionID: "session-1", Report: `{"findings":[]}`},
		{SessionID: "session-1", Report: `{"refused":false,"reason":null,"skipped":[{"path":"vendor/blob.bin","reason":"opaque generated data"}]}`},
	}}
	w, scanID := newRefusalAuditWorker(t, runner, refusalAuditSkillName)
	runRefusalAuditScan(t, w, scanID)

	if len(runner.jobs) != 2 {
		t.Fatalf("RunSkill calls = %d, want primary run plus audit", len(runner.jobs))
	}
	auditJob := runner.jobs[1]
	if auditJob.ResumeSessionID != "session-1" {
		t.Errorf("audit ResumeSessionID = %q, want session-1", auditJob.ResumeSessionID)
	}
	if auditJob.OutputFile != refusalAuditOutputFile {
		t.Errorf("audit OutputFile = %q, want %q", auditJob.OutputFile, refusalAuditOutputFile)
	}
	if auditJob.MaxTurns != refusalAuditMaxTurns {
		t.Errorf("audit MaxTurns = %d, want %d", auditJob.MaxTurns, refusalAuditMaxTurns)
	}
	if !strings.Contains(auditJob.ResumePrompt, "Do not restart analysis") {
		t.Errorf("audit prompt = %q, want focused follow-up", auditJob.ResumePrompt)
	}

	var scan db.Scan
	if err := w.DB.First(&scan, scanID).Error; err != nil {
		t.Fatal(err)
	}
	if scan.Report != `{"findings":[]}` {
		t.Errorf("primary report = %q, want unchanged", scan.Report)
	}
	if !scan.RefusalAuditWarning || !strings.Contains(scan.RefusalAudit, "vendor/blob.bin") {
		t.Errorf("audit fields = warning:%t report:%q", scan.RefusalAuditWarning, scan.RefusalAudit)
	}
}

func TestDoSkill_refusalAuditIsBestEffort(t *testing.T) {
	runner := &sequenceRunner{results: []SkillResult{{SessionID: "session-1", Report: `{"findings":[]}`}, {}}, errs: []error{nil, errors.New("expired session")}}
	w, scanID := newRefusalAuditWorker(t, runner, refusalAuditSkillName)
	runRefusalAuditScan(t, w, scanID)

	var scan db.Scan
	if err := w.DB.First(&scan, scanID).Error; err != nil {
		t.Fatal(err)
	}
	if scan.Status != db.ScanDone || scan.Report != `{"findings":[]}` {
		t.Errorf("scan = status:%s report:%q, want completed primary report", scan.Status, scan.Report)
	}
	if scan.RefusalAudit != "" || scan.RefusalAuditWarning {
		t.Errorf("audit fields should stay empty after failure: %+v", scan)
	}
	if !strings.Contains(scan.Log, "refusal audit failed") {
		t.Errorf("log = %q, want audit failure", scan.Log)
	}
}

func TestDoSkill_skipsRefusalAuditWithoutSession(t *testing.T) {
	runner := &sequenceRunner{results: []SkillResult{{Report: `{"findings":[]}`}}}
	w, scanID := newRefusalAuditWorker(t, runner, refusalAuditSkillName)
	runRefusalAuditScan(t, w, scanID)
	if len(runner.jobs) != 1 {
		t.Errorf("RunSkill calls = %d, want primary run only without a session", len(runner.jobs))
	}
}

func TestDoSkill_refusalAuditIsDeepDiveOnly(t *testing.T) {
	runner := &sequenceRunner{results: []SkillResult{{SessionID: "session-1", Report: `{"findings":[]}`}}}
	w, scanID := newRefusalAuditWorker(t, runner, "vuln-scan")
	runRefusalAuditScan(t, w, scanID)
	if len(runner.jobs) != 1 {
		t.Errorf("RunSkill calls = %d, want primary run only for a non-deep-dive skill", len(runner.jobs))
	}
}

func newRefusalAuditWorker(t *testing.T, runner SkillRunner, skillName string) (*Worker, uint) {
	t.Helper()
	gdb, err := db.Open(filepath.Join(t.TempDir(), "refusal-audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	repo := db.Repository{URL: "https://example.com/refusal-audit", Name: "refusal-audit"}
	if err := gdb.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}
	skill := db.Skill{Name: skillName, Description: "d", Body: "b", OutputFile: "report.json", OutputKind: "findings", Version: 1, Active: true, Source: "ui"}
	if err := gdb.Create(&skill).Error; err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RepositoryID: repo.ID, Kind: JobSkill, Status: db.ScanQueued, SkillID: &skill.ID, Model: "fake"}
	if err := gdb.Create(&scan).Error; err != nil {
		t.Fatal(err)
	}
	return &Worker{
		DB:             gdb,
		DataDir:        t.TempDir(),
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Runner:         runner,
		PrepareRepoSrc: stubPrepareRepoSrc,
	}, scan.ID
}

func runRefusalAuditScan(t *testing.T, w *Worker, scanID uint) {
	t.Helper()
	body, err := json.Marshal(struct {
		ScanID uint `json:"scan_id"`
	}{ScanID: scanID})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.wrap(w.doSkill)(context.Background(), body); err != nil {
		t.Fatal(err)
	}
}
