package worker

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
)

func TestDoSkillRepairsPoCFencesBeforePersisting(t *testing.T) {
	raw, err := os.ReadFile("../poc/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	invalid := strings.Replace(valid, "```text filename=input.txt", "--- input.txt ---", 1)
	schema := loadBundledSchema(t, "../../skills/audit-injection/schema.json")
	for _, tc := range []struct {
		name, repaired, session string
		status                  db.ScanStatus
		strict                  bool
		wantRuns, wantFindings  int
	}{
		{"repaired", valid, "session-1", db.ScanDone, true, 2, 1},
		{"still invalid strict", invalid, "session-1", db.ScanFailed, true, 2, 0},
		{"still invalid warning", invalid, "session-1", db.ScanDone, false, 2, 1},
		{"no session", "", "", db.ScanFailed, true, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &sequenceRunner{results: []SkillResult{
				{SessionID: tc.session, Report: invalid},
				{SessionID: tc.session, Report: tc.repaired},
			}}
			w, repoID, scanID := newQueuedSchemaSkillWorker(t, tc.strict, runner)
			var scan db.Scan
			if err := w.DB.First(&scan, scanID).Error; err != nil {
				t.Fatal(err)
			}
			if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Updates(map[string]any{
				"name": "audit-injection", "output_kind": "findings", "schema_json": schema,
			}).Error; err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(queue.Payload{ScanID: scanID})
			if err != nil {
				t.Fatal(err)
			}
			if err := w.wrap(w.doSkill)(context.Background(), payload); err != nil {
				t.Fatal(err)
			}
			if err := w.DB.First(&scan, scanID).Error; err != nil {
				t.Fatal(err)
			}
			if scan.Status != tc.status || len(runner.jobs) != tc.wantRuns {
				t.Fatalf("status = %s, runs = %d, error = %s", scan.Status, len(runner.jobs), scan.Error)
			}
			if tc.wantRuns == 2 && !strings.Contains(runner.jobs[1].ResumePrompt, "/findings/0/validation") {
				t.Fatalf("repair prompt = %q", runner.jobs[1].ResumePrompt)
			}
			wantReport := invalid
			if tc.repaired == valid {
				wantReport = valid
			}
			assertPersistedPoCReport(t, w, repoID, scan, wantReport, tc.wantFindings)
		})
	}
}

func assertPersistedPoCReport(t *testing.T, w *Worker, repoID uint, scan db.Scan, wantReport string, wantFindings int) {
	t.Helper()
	if scan.Report != wantReport {
		t.Fatalf("persisted report = %s, want %s", scan.Report, wantReport)
	}
	var findings []db.Finding
	if err := w.DB.Where("repository_id = ?", repoID).Find(&findings).Error; err != nil {
		t.Fatal(err)
	}
	if len(findings) != wantFindings {
		t.Fatalf("persisted %d findings, want %d", len(findings), wantFindings)
	}
	parsed, err := parseReport([]byte(wantReport))
	if err != nil {
		t.Fatal(err)
	}
	if wantFindings > 0 && findings[0].Validation != parsed.Findings[0].Validation {
		t.Fatalf("persisted validation = %q", findings[0].Validation)
	}
}

func TestValidateSkillReportPoCScope(t *testing.T) {
	for _, name := range []string{
		deepDiveSkillName, "advisory-deep-dive", "audit-injection", "audit-exfil",
		"audit-authz", "audit-pii", "audit-memory", "audit-package-manager", "audit-web", "audit-embedded",
	} {
		t.Run(name, func(t *testing.T) {
			report := `{"findings":[{"validation":"--- input.ml ---\nlet () = ()"}]}`
			if detail := ValidateSkillReport(name, `{"type":"object"}`, report); !strings.Contains(detail, "/findings/0/validation") {
				t.Fatalf("validation = %q", detail)
			}
			if detail := ValidateSkillReport("custom-skill", `{"type":"object"}`, report); detail != "" {
				t.Fatal(detail)
			}
		})
	}
}

func TestVerifyPoCFencesUseStrictValidation(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/verify/schema.json")
	report := strings.Replace(confirmedVerificationReport(t), "go run ./poc.go", "--- poc.go ---", 1)
	if detail := ValidateSkillReport(verifySkillName, schema, report); !strings.Contains(detail, "/reproducer") {
		t.Fatalf("validation = %q", detail)
	}
	detail, recoverable := reportValidationForParsing(&db.Skill{Name: verifySkillName, SchemaJSON: schema}, report)
	if !strings.Contains(detail, "/reproducer") || recoverable {
		t.Fatalf("PoC formatting error treated as recoverable rubric error: %q, %v", detail, recoverable)
	}
}
