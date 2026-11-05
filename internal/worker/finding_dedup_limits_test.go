package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/gorm"

	"scrutineer/internal/db"
)

type dedupLimitResult struct {
	scan     db.Scan
	findings []db.Finding
	notes    []db.FindingNote
	queries  int64
}

func runDedupLimitReport(t *testing.T, count int, report func([]db.Finding) map[string]any) dedupLimitResult {
	t.Helper()
	w, scan := costCapFixture(t, 0)
	schema, err := os.ReadFile("../../skills/finding-dedup/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Model(&db.Skill{}).Where("id = ?", *scan.SkillID).Updates(map[string]any{"name": findingDedupSkill, "output_kind": "finding_dedup", "schema_json": string(schema)}).Error; err != nil {
		t.Fatal(err)
	}
	findings := make([]db.Finding, count)
	for i := range findings {
		findings[i] = db.Finding{ScanID: scan.ID, RepositoryID: scan.RepositoryID, FindingID: fmt.Sprint(i), Title: fmt.Sprintf("finding %d", i), Severity: "High", Status: db.FindingNew}
		if err := w.DB.Create(&findings[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(report(findings))
	if err != nil {
		t.Fatal(err)
	}
	var queries atomic.Int64
	if err := w.DB.Callback().Query().Before("gorm:query").Register("dedup_limits", func(tx *gorm.DB) {
		if tx.Statement.Table == "findings" {
			queries.Add(1)
		}
	}); err != nil {
		t.Fatal(err)
	}
	w.Runner = &capRunner{first: func(context.Context, func(Event)) (SkillResult, error) { return SkillResult{Report: string(raw)}, nil }}
	got := runCapScan(t, w, scan)
	if err := w.DB.Callback().Query().Remove("dedup_limits"); err != nil {
		t.Fatal(err)
	}
	if got.Report != string(raw) {
		t.Fatal("scan did not retain its report")
	}
	var notes []db.FindingNote
	if err := w.DB.Order("id").Find(&notes).Error; err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Order("id").Find(&findings).Error; err != nil {
		t.Fatal(err)
	}
	return dedupLimitResult{scan: got, findings: findings, notes: notes, queries: queries.Load()}
}

func repeatedDedupIDs(id uint, count int) []uint {
	ids := make([]uint, count)
	for i := range ids {
		ids[i] = id
	}
	return ids
}

func TestDoSkillDedupRejectsOversizeReportsBeforeWrites(t *testing.T) {
	for _, kind := range []string{"groups", "mixed groups", "IDs", "mixed IDs"} {
		t.Run(kind, func(t *testing.T) {
			got := runDedupLimitReport(t, 2, func(fs []db.Finding) map[string]any {
				report := map[string]any{"duplicates": []any{}}
				switch kind {
				case "groups":
					groups := make([]any, maxDedupReportGroups+1)
					for i := range groups {
						groups[i] = map[string]any{"finding_ids": []uint{}, "reason": "x"}
					}
					report["chains"] = groups
				case "mixed groups":
					for _, shape := range []string{"duplicates", "subsumed", "chains"} {
						report[shape] = dedupTestGroups(shape, fs, 86, 1)
					}
				case "IDs":
					report["chains"] = dedupTestGroups("chains", fs, 17, 256)
				case "mixed IDs":
					report["duplicates"] = dedupTestGroups("duplicates", fs, 8, 256)
					report["subsumed"] = dedupTestGroups("subsumed", fs, 8, 256)
				}
				return report
			})
			if got.scan.Status != db.ScanFailed || !strings.Contains(got.scan.Error, "report exceeds") {
				t.Fatalf("scan = %s, error=%s", got.scan.Status, got.scan.Error)
			}
			if got.queries != 0 || len(got.notes) != 0 {
				t.Fatalf("rejected report made %d finding queries and %d notes", got.queries, len(got.notes))
			}
			for _, f := range got.findings {
				if f.Status != db.FindingNew {
					t.Fatalf("rejected report changed finding %d", f.ID)
				}
			}
		})
	}
}

func dedupTestGroups(shape string, fs []db.Finding, groups, members int) []any {
	out := make([]any, groups)
	for i := range out {
		ids := repeatedDedupIDs(fs[1].ID, members)
		g := map[string]any{"reason": "x"}
		switch shape {
		case "duplicates":
			g["canonical_id"], g["duplicate_ids"] = fs[0].ID, ids
		case "subsumed":
			g["parent_id"], g["subsumed_ids"] = fs[0].ID, ids
		case "chains":
			ids[0] = fs[0].ID
			g["finding_ids"] = ids
		}
		out[i] = g
	}
	return out
}

func TestDoSkillDedupAcceptsReportBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		groups, members, notes int
	}{
		{name: "group limit", groups: 256, members: 2, notes: 512},
		{name: "ID limit", groups: 16, members: 256, notes: 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runDedupLimitReport(t, 2, func(fs []db.Finding) map[string]any {
				return map[string]any{"duplicates": []any{}, "chains": dedupTestGroups("chains", fs, tc.groups, tc.members)}
			})
			if got.scan.Status != db.ScanDone || len(got.notes) != tc.notes || got.queries != int64(tc.notes) {
				t.Fatalf("scan=%s error=%s notes=%d queries=%d", got.scan.Status, got.scan.Error, len(got.notes), got.queries)
			}
		})
	}
}

func TestDoSkillDedupBoundsEveryRelationShape(t *testing.T) {
	for _, shape := range []string{"duplicates", "subsumed", "chains"} {
		for _, count := range []int{1, 256, 257} {
			t.Run(fmt.Sprintf("%s/%d", shape, count), func(t *testing.T) {
				members := count
				if shape == "chains" && count == 1 {
					members = 2
				}
				got := runDedupLimitReport(t, 2, func(fs []db.Finding) map[string]any {
					report := map[string]any{"duplicates": []any{}}
					report[shape] = dedupTestGroups(shape, fs, 1, members)
					return report
				})
				requireDedupShapeResult(t, got, shape, count)
				if shape == "duplicates" && count == 256 {
					baseline := runDedupLimitReport(t, 2, func(fs []db.Finding) map[string]any {
						return map[string]any{"duplicates": dedupTestGroups(shape, fs, 1, 1)}
					})
					if got.queries != baseline.queries {
						t.Fatalf("repeated IDs caused %d finding queries, want baseline %d", got.queries, baseline.queries)
					}
				}
			})
		}
	}
}

func requireDedupShapeResult(t *testing.T, got dedupLimitResult, shape string, count int) {
	t.Helper()
	if got.scan.Status != db.ScanDone {
		t.Fatalf("scan=%s error=%s", got.scan.Status, got.scan.Error)
	}
	if count == 257 {
		if got.queries != 0 || len(got.notes) != 0 || !strings.Contains(got.scan.Log, "skipped 257") {
			t.Fatalf("oversize group queries=%d notes=%d log=%s", got.queries, len(got.notes), got.scan.Log)
		}
		return
	}
	wantNotes, wantStatus := 1, db.FindingNew
	if shape == "chains" {
		wantNotes = 2
	}
	if shape == "duplicates" {
		wantStatus = db.FindingDuplicate
	}
	if len(got.notes) != wantNotes || got.findings[1].Status != wantStatus {
		t.Fatalf("notes=%d member status=%s", len(got.notes), got.findings[1].Status)
	}
	if shape != "duplicates" && got.queries != 2 {
		t.Fatalf("finding queries=%d, want 2", got.queries)
	}
	for _, note := range got.notes {
		other := got.findings[0].ID
		if note.FindingID == other {
			other = got.findings[1].ID
		}
		verb := map[string]string{"duplicates": dedupHeaderDuplicate, "subsumed": dedupHeaderSubsumed, "chains": dedupHeaderChains}[shape]
		want := fmt.Sprintf("finding-dedup: %s finding #%d\n\nx", verb, other)
		if note.Body != want {
			t.Fatalf("note=%q, want %q", note.Body, want)
		}
	}
}

func TestDoSkillDedupCountsAllRejectedChainMembers(t *testing.T) {
	for _, count := range []int{16, 20} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			got := runDedupLimitReport(t, count, func(fs []db.Finding) map[string]any {
				ids := make([]uint, len(fs))
				for i, f := range fs {
					ids[i] = f.ID
				}
				return map[string]any{"duplicates": []any{}, "chains": []any{map[string]any{"finding_ids": ids, "reason": "x"}}}
			})
			wantNotes, wantSkipped := count, 0
			if count > 16 {
				wantNotes, wantSkipped = 0, count
			}
			if got.scan.Status != db.ScanDone || len(got.notes) != wantNotes || !strings.Contains(got.scan.Log, fmt.Sprintf("skipped %d", wantSkipped)) {
				t.Fatalf("status=%s notes=%d log=%s", got.scan.Status, len(got.notes), got.scan.Log)
			}
		})
	}
}

func TestFindingDedupSchemaMemberLimits(t *testing.T) {
	schema, err := os.ReadFile("../../skills/finding-dedup/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range []string{"duplicates", "subsumed", "chains"} {
		limit := 256
		if shape == "chains" {
			limit = 16
		}
		for _, count := range []int{limit, limit + 1} {
			t.Run(fmt.Sprintf("%s/%d", shape, count), func(t *testing.T) {
				fs := []db.Finding{{ID: 1}, {ID: 2}}
				groups := dedupTestGroups(shape, fs, 1, count)
				field := map[string]string{"duplicates": "duplicate_ids", "subsumed": "subsumed_ids", "chains": "finding_ids"}[shape]
				ids := make([]uint, count)
				for i := range ids {
					ids[i] = uint(i + 2)
				}
				groups[0].(map[string]any)[field] = ids
				report := map[string]any{"duplicates": []any{}}
				report[shape] = groups
				raw, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				detail := ValidateReportSchema(string(schema), string(raw))
				if (detail == "") != (count == limit) {
					t.Fatalf("schema validation=%q at %d members", detail, count)
				}
			})
		}
	}
}
