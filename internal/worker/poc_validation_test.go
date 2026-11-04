package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/queue"
	"scrutineer/internal/skills"
)

func TestDoSkillRepairsPoCFencesBeforePersisting(t *testing.T) {
	raw, err := os.ReadFile("../poc/testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	valid := string(raw)
	invalid := strings.Replace(valid, "```text filename=input.txt", "--- input.txt ---", 1)
	atLimit := pocReportWithOutputFences(t, raw, 62)
	overLimit := pocReportWithOutputFences(t, raw, 63)
	schema := loadBundledSchema(t, "../../skills/audit-injection/schema.json")
	for _, tc := range []struct {
		name, original, repaired, session string
		status                            db.ScanStatus
		strict                            bool
		wantRuns, wantFindings            int
	}{
		{"repaired", invalid, valid, "session-1", db.ScanDone, true, 2, 1},
		{"still invalid strict", invalid, invalid, "session-1", db.ScanFailed, true, 2, 0},
		{"still invalid warning", invalid, invalid, "session-1", db.ScanDone, false, 2, 1},
		{"no session", invalid, "", "", db.ScanFailed, true, 1, 0},
		{"64 fences including output", atLimit, "", "session-1", db.ScanDone, true, 1, 1},
		{"65 fences repaired", overLimit, atLimit, "session-1", db.ScanDone, true, 2, 1},
		{"65 fences rejected", overLimit, overLimit, "session-1", db.ScanFailed, true, 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &sequenceRunner{results: []SkillResult{
				{SessionID: tc.session, Report: tc.original},
				{SessionID: tc.session, Report: tc.repaired},
			}}
			w, repoID, scanID := newQueuedSchemaSkillWorker(t, tc.strict, runner)
			var scan db.Scan
			if err := w.DB.First(&scan, scanID).Error; err != nil {
				t.Fatal(err)
			}
			if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Updates(map[string]any{
				"name": "audit-injection", "output_kind": "findings", "schema_json": schema, "poc_field": "validation",
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
			if tc.wantRuns == 2 {
				assertPoCRepairPrompt(t, runner.jobs[1].ResumePrompt, tc.original == overLimit)
			}
			wantReport := tc.original
			if tc.status == db.ScanDone && tc.repaired != "" {
				wantReport = tc.repaired
			}
			assertPersistedPoCReport(t, w, repoID, scan, wantReport, tc.wantFindings)
		})
	}
}

func assertPoCRepairPrompt(t *testing.T, prompt string, fenceLimit bool) {
	t.Helper()
	if !strings.Contains(prompt, "/findings/0/validation") {
		t.Fatalf("repair prompt = %q", prompt)
	}
	if fenceLimit && !strings.Contains(prompt, "more than 64 code fences") {
		t.Fatalf("repair prompt omits the fence limit: %q", prompt)
	}
}

func pocReportWithOutputFences(t *testing.T, raw []byte, namedFiles int) string {
	t.Helper()
	var report map[string][]map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	var markdown strings.Builder
	markdown.WriteString("```sh filename=run.sh\nprintf reproduced\n```\n")
	for i := 1; i < namedFiles; i++ {
		fmt.Fprintf(&markdown, "```text filename=inputs/file%d.txt\ncrafted input\n```\n", i)
	}
	markdown.WriteString("```console\n$ ./run.sh\nreproduced\n```\n```text\nexpected output\n```\n")
	report["findings"][0]["validation"] = markdown.String()
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
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
	report := `{"findings":[{"validation":"--- input.ml ---\nlet () = ()"}]}`
	if detail := ValidateSkillReport("custom-skill", `{"type":"object"}`, "validation", report); !strings.Contains(detail, "/findings/0/validation") {
		t.Fatalf("validation = %q", detail)
	}
	if detail := ValidateSkillReport(deepDiveSkillName, `{"type":"object"}`, "", report); detail != "" {
		t.Fatal(detail)
	}
}

func TestVerifyPoCFencesUseStrictValidation(t *testing.T) {
	schema := loadBundledSchema(t, "../../skills/verify/schema.json")
	report := strings.Replace(confirmedVerificationReport(t), "go run ./poc.go", "--- poc.go ---", 1)
	if detail := ValidateSkillReport(verifySkillName, schema, "reproducer", report); !strings.Contains(detail, "/reproducer") {
		t.Fatalf("validation = %q", detail)
	}
	detail, recoverable := reportValidationForParsing(&db.Skill{Name: verifySkillName, SchemaJSON: schema, PoCField: "reproducer"}, report)
	if !strings.Contains(detail, "/reproducer") || recoverable {
		t.Fatalf("PoC formatting error treated as recoverable rubric error: %q, %v", detail, recoverable)
	}
}

// Every bundled skill that reports findings either has its PoC Markdown
// validated or is listed here as exempt, so a new skill cannot skip
// validation unnoticed.
func TestBundledFindingSkillsChoosePoCValidation(t *testing.T) {
	exempt := map[string]bool{
		// Tool scanners write validation text from a script.
		"semgrep": true, "bandit": true, "zizmor": true, "betterleaks": true,
		// These model skills use their own finding formats.
		"ingest": true, "reachability": true, "variants": true, "vuln-scan": true,
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "skills", "*", "SKILL.md"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("glob skills: %v", err)
	}
	invalid := `{"findings":[{"validation":"--- run.sh ---\necho hi"}],"reproducer":"--- run.sh ---\necho hi"}`
	for _, path := range paths {
		skill, err := skills.ParseFile(path)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		switch skill.OutputKind {
		case "findings", "advisory_audit", "verify":
		default:
			continue
		}
		validated := validateReportPoC(skill.PoCField, invalid) != ""
		if validated == exempt[skill.Name] {
			t.Errorf("%s: PoC validation = %v; set scrutineer.poc_field or add it to the exempt list here", skill.Name, validated)
		}
	}
}
