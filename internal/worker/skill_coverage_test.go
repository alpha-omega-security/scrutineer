package worker

import (
	"context"
	"strings"
	"testing"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func TestParseSkillOutputIngestsCoverageClaim(t *testing.T) {
	initial, err := coverage.Marshal(coverage.Record{
		RequestedMode: db.ScanRescanModeDiff,
		ActualMode:    db.ScanRescanModeDiff,
		Completeness:  coverage.CompletenessPartial,
		Reason:        "scan has not reported receipts for the staged changed files",
		IncludedPaths: []string{"a.go", "b.go"},
		ThreatModel:   &coverage.ThreatModelState{Update: "updated", Material: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RescanMode: db.ScanRescanModeDiff, Coverage: initial, Completeness: coverage.CompletenessPartial}
	report := `{"coverage":{"receipts":[
		{"path":"a.go","disposition":"reviewed_clean"},
		{"path":"b.go","disposition":"reviewed_findings"}],
		"surfaces":[{"name":"parser","disposition":"reviewed_findings","evidence_ref":"b.go:12"}],
		"open_questions":[],"dropped_findings":[]}}`
	w := &Worker{}
	if err := w.parseSkillOutput(context.Background(), &db.Skill{}, &scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok {
		t.Fatalf("coverage did not parse: %q", scan.Coverage)
	}
	if scan.Completeness != coverage.CompletenessComplete || rec.Completeness != coverage.CompletenessComplete {
		t.Fatalf("completeness column=%q record=%q", scan.Completeness, rec.Completeness)
	}
	if rec.RequestedMode != db.ScanRescanModeDiff || rec.ActualMode != db.ScanRescanModeDiff || rec.ThreatModel == nil {
		t.Fatalf("worker-owned fields were not preserved: %+v", rec)
	}
	if len(rec.Receipts) != 2 || len(rec.Surfaces) != 1 {
		t.Fatalf("skill evidence was not stored: %+v", rec)
	}
}

func TestParseSkillOutputKeepsDiffPartialWhenReceiptIsMissing(t *testing.T) {
	initial, err := coverage.Marshal(coverage.Record{
		ActualMode:    db.ScanRescanModeDiff,
		Completeness:  coverage.CompletenessPartial,
		IncludedPaths: []string{"a.go", "b.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{RescanMode: db.ScanRescanModeDiff, Coverage: initial}
	report := `{"coverage":{"receipts":[{"path":"a.go","disposition":"reviewed_clean"}]}}`
	if err := (&Worker{}).parseSkillOutput(context.Background(), &db.Skill{}, &scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok {
		t.Fatal("coverage did not parse")
	}
	if rec.Completeness != coverage.CompletenessPartial || rec.Reason != "staged work items have no receipt" {
		t.Fatalf("reconciled state = %q (%q)", rec.Completeness, rec.Reason)
	}
}

func TestParseSkillOutputPersistsFindingsBeforeRejectingInvalidCoverage(t *testing.T) {
	w, repo := newStreamWorker(t)
	initial, err := coverage.Marshal(coverage.Record{
		ActualMode:    db.ScanRescanModeDiff,
		Completeness:  coverage.CompletenessPartial,
		IncludedPaths: []string{"a.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	scan := db.Scan{
		RepositoryID: repo.ID,
		Kind:         JobSkill,
		SkillName:    "security-deep-dive",
		Status:       db.ScanDone,
		RescanMode:   db.ScanRescanModeDiff,
		Coverage:     initial,
		Completeness: coverage.CompletenessPartial,
	}
	w.DB.Create(&scan)
	report := `{"findings":[{"id":"F1","title":"finding survives","severity":"High","location":"a.go:1"}],` +
		`"coverage":{"receipts":[{"path":"./a.go","disposition":"reviewed_findings"}]}}`
	err = w.parseSkillOutput(context.Background(), &db.Skill{OutputKind: "findings"}, &scan, report, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "repository-relative") {
		t.Fatalf("error = %v, want repository-relative validation", err)
	}
	var findingCount int64
	w.DB.Model(&db.Finding{}).Where("scan_id = ?", scan.ID).Count(&findingCount)
	if findingCount != 1 || scan.FindingsCount != 1 {
		t.Fatalf("persisted findings = %d, scan count = %d; want 1, 1", findingCount, scan.FindingsCount)
	}
	if scan.Coverage != initial || scan.Completeness != coverage.CompletenessPartial {
		t.Fatalf("invalid claim mutated scan: %+v", scan)
	}
}

func TestParseSkillOutputReportsStoredCoverageCorruption(t *testing.T) {
	const corrupted = `{"version":"invalid"}`
	scan := db.Scan{RescanMode: db.ScanRescanModeDiff, Coverage: corrupted, Completeness: coverage.CompletenessPartial}
	report := `{"coverage":{"receipts":[]}}`
	err := (&Worker{}).parseSkillOutput(context.Background(), &db.Skill{}, &scan, report, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "stored coverage record") {
		t.Fatalf("error = %v, want stored coverage corruption detail", err)
	}
	if scan.Coverage != corrupted || scan.Completeness != coverage.CompletenessPartial {
		t.Fatalf("corrupt stored coverage mutated scan: %+v", scan)
	}
}

func TestParseSkillOutputNeverClaimsCompleteWithoutWorkerScope(t *testing.T) {
	scan := db.Scan{RescanMode: db.ScanRescanModeDiff}
	report := `{"coverage":{"receipts":[{"path":"a.go","disposition":"reviewed_clean"}]}}`
	if err := (&Worker{}).parseSkillOutput(context.Background(), &db.Skill{}, &scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok {
		t.Fatal("coverage did not parse")
	}
	if scan.Completeness != coverage.CompletenessUnknown || rec.Completeness != coverage.CompletenessUnknown {
		t.Fatalf("completeness column=%q record=%q", scan.Completeness, rec.Completeness)
	}
}

func TestParseSkillOutputIgnoresCoverageOutsideDiffRescan(t *testing.T) {
	const initial = `{"producer":"other-skill"}`
	scan := db.Scan{Coverage: initial, Completeness: coverage.CompletenessUnknown}
	report := `{"coverage":{"format":"skill-specific"}}`
	if err := (&Worker{}).parseSkillOutput(context.Background(), &db.Skill{}, &scan, report, func(Event) {}); err != nil {
		t.Fatal(err)
	}
	if scan.Coverage != initial || scan.Completeness != coverage.CompletenessUnknown {
		t.Fatalf("non-diff report mutated coverage: %+v", scan)
	}
}

func TestParseSkillOutputLeavesMalformedCoverageEnvelopeToKindParser(t *testing.T) {
	scan := db.Scan{RescanMode: db.ScanRescanModeDiff}
	err := (&Worker{}).parseSkillOutput(context.Background(), &db.Skill{OutputKind: "maintainers"}, &scan, `{"coverage":`, func(Event) {})
	if err == nil || !strings.Contains(err.Error(), "parse maintainers report") {
		t.Fatalf("error = %v, want maintainers parser error", err)
	}
}
