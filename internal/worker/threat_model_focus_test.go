package worker

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/repoconfig"
)

func threatModelFocusReport(t *testing.T, count int) string {
	t.Helper()
	var report map[string]any
	err := json.Unmarshal([]byte(`{
		"spec_version":1,"repository":"https://example.com/focus","commit":"abc1234","date":"2026-11-04","description":"Input parser",
		"components":[{"name":"parser","entry_points":["parse"],"touches":[],"in_scope":true,"provenance":"inferred"}],
		"out_of_scope":{"not_applicable":true,"reason":"all source is in scope"},
		"trust_boundaries":[{"component":"parser","boundary":"public API","reachability_precondition":"caller supplies bytes","provenance":"inferred"}],
		"entry_points":[],"environment":{"assumes":[],"does_not":[],"provenance":"inferred"},
		"adversaries":{"in_scope":["input supplier"],"out_of_scope":[],"provenance":"inferred"},
		"properties_provided":[],"properties_not_provided":[],"downstream_responsibilities":[],
		"known_misuse":{"not_applicable":true,"reason":"no documented misuse"},"known_non_findings":[],
		"dispositions":["valid","valid_hardening","out_of_model_trusted_input","out_of_model_adversary","out_of_model_unsupported_component","out_of_model_non_default_build","by_design_disclaimed","known_non_finding","model_gap"],"open_questions":[]
	}`), &report)
	if err != nil {
		t.Fatal(err)
	}
	cfg := repoconfig.Config{KnownBugs: []string{"documented behavior"}, AttackSurface: "network inputs", Skip: []string{"tests/**"}}
	for i := range count {
		cfg.FocusAreas = append(cfg.FocusAreas, repoconfig.FocusArea{Name: fmt.Sprintf("area-%d", i), Paths: []string{fmt.Sprintf("p%d/**", i)}, Surface: "untrusted input"})
	}
	report["scan_config"] = cfg
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestDoSkillThreatModelRepairsOverCapFocusAreas(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprintf("strict=%v", strict), func(t *testing.T) {
			schema := loadBundledSchema(t, "../../skills/threat-model/schema.json")
			valid := threatModelFocusReport(t, repoconfig.MaxFocusAreas)
			if detail := ValidateReportSchema(schema, valid); detail != "" {
				t.Fatalf("valid report: %s", detail)
			}
			invalid := threatModelFocusReport(t, repoconfig.MaxFocusAreas+1)
			if detail := ValidateReportSchema(schema, invalid); !strings.Contains(detail, "/scan_config/focus_areas") {
				t.Fatalf("over-cap validation = %q", detail)
			}
			runner := &sequenceRunner{results: []SkillResult{{SessionID: "focus-session", Report: invalid}, {SessionID: "focus-session", Report: valid}}}
			w, scan := costCapFixture(t, 0)
			w.Runner = runner
			w.SchemaStrict = strict
			if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Updates(map[string]any{"name": threatModelSkillName, "output_kind": "threat_model", "schema_json": schema}).Error; err != nil {
				t.Fatal(err)
			}
			got := runCapScan(t, w, scan)
			if got.Status != db.ScanDone || got.Report != valid {
				t.Fatalf("scan=%s error=%s; repaired report retained=%v", got.Status, got.Error, got.Report == valid)
			}
			if len(runner.jobs) != 2 {
				t.Fatalf("runner calls=%d, want repair turn", len(runner.jobs))
			}
			if runner.jobs[1].ResumeSessionID != "focus-session" || !strings.Contains(runner.jobs[1].ResumePrompt, "/scan_config/focus_areas") {
				t.Fatalf("repair job = %+v", runner.jobs[1])
			}
			var report struct {
				ScanConfig repoconfig.Config `json:"scan_config"`
			}
			if err := json.Unmarshal([]byte(got.Report), &report); err != nil {
				t.Fatal(err)
			}
			cfg := report.ScanConfig
			if len(cfg.FocusAreas) != repoconfig.MaxFocusAreas || len(cfg.KnownBugs) != 1 || cfg.AttackSurface != "network inputs" || len(cfg.Skip) != 1 {
				t.Fatalf("repaired scan guidance = %+v", cfg)
			}
		})
	}
}
