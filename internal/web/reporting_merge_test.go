package web

import (
	"bytes"
	"fmt"
	"math"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"scrutineer/internal/db"
	"scrutineer/internal/reporting"
)

// mergeScan is one seeded run of a discrete instance's corpus, placed
// relative to the seeding test's own now so every server's rolling windows
// select the same subset of it.
type mergeScan struct {
	repo, model     string
	status          db.ScanStatus
	cost            float64
	in, out, cr, cw int
	// ago is how long before now the run finished, or started for a run
	// still going. A queued run has neither timestamp and ignores it.
	ago time.Duration
}

type mergeFinding struct {
	repo, model, severity string
	ago                   time.Duration
}

type mergeCorpus struct {
	scans    []mergeScan
	findings []mergeFinding
}

var (
	// Instance A: two repositories and two models, with a failed run (a
	// start and a spend, never a completion), a run still going (a start
	// only), an old completion the week does not see, and findings at
	// three severities.
	mergeCorpusA = mergeCorpus{
		scans: []mergeScan{
			{repo: "a-one", model: "model-a", status: db.ScanDone, cost: 2, in: 100, out: 10, cr: 1000, cw: 50, ago: 2 * time.Hour},
			{repo: "a-one", model: "model-a", status: db.ScanDone, cost: 4, in: 300, out: 30, cr: 3000, cw: 150, ago: 3 * reportDay},
			{repo: "a-two", model: "model-b", status: db.ScanDone, cost: 6, in: 200, out: 20, cr: 2000, cw: 100, ago: 10 * reportDay},
			{repo: "a-two", model: "model-a", status: db.ScanFailed, cost: 1, in: 10, out: 1, cr: 10, cw: 1, ago: time.Hour},
			{repo: "a-one", model: "model-b", status: db.ScanRunning, ago: 30 * time.Minute},
		},
		findings: []mergeFinding{
			{repo: "a-one", model: "model-a", severity: "Critical", ago: 2 * time.Hour},
			{repo: "a-one", model: "model-a", severity: "Low", ago: 2 * time.Hour},
			{repo: "a-one", model: "model-a", severity: "High", ago: 100 * reportDay},
		},
	}
	// Instance B: three repositories, a model A never ran, a completion
	// older than the month, and a queued run that counts nowhere.
	mergeCorpusB = mergeCorpus{
		scans: []mergeScan{
			{repo: "b-one", model: "model-b", status: db.ScanDone, cost: 3, in: 150, out: 15, cr: 1500, cw: 75, ago: 5 * time.Hour},
			{repo: "b-two", model: "model-a", status: db.ScanDone, cost: 5, in: 250, out: 25, cr: 2500, cw: 125, ago: reportDay + time.Hour},
			{repo: "b-three", model: "model-c", status: db.ScanDone, cost: 7, in: 350, out: 35, cr: 3500, cw: 175, ago: 2 * reportDay},
			{repo: "b-three", model: "model-c", status: db.ScanDone, cost: 9, in: 450, out: 45, cr: 4500, cw: 225, ago: 40 * reportDay},
			{repo: "b-one", model: "model-c", status: db.ScanQueued},
		},
		findings: []mergeFinding{
			{repo: "b-two", model: "model-a", severity: "Medium", ago: 5 * time.Hour},
			{repo: "b-two", model: "model-a", severity: "Medium", ago: 2 * reportDay},
			{repo: "b-three", model: "model-c", severity: "High", ago: 2 * reportDay},
			{repo: "b-three", model: "model-c", severity: "Low", ago: 40 * reportDay},
		},
	}
)

// seedMergeCorpus lays the corpora down in one server. Repositories are
// created by name, so seeding A and B together gives the union server
// exactly the repositories the two instances have between them.
func seedMergeCorpus(t *testing.T, s *Server, corpora ...mergeCorpus) {
	t.Helper()
	now := time.Now().UTC()
	repos := map[string]db.Repository{}
	repo := func(name string) db.Repository {
		if r, ok := repos[name]; ok {
			return r
		}
		r := db.Repository{URL: "https://example.test/" + name, Name: name, FullName: "acme/" + name}
		if err := s.DB.Create(&r).Error; err != nil {
			t.Fatal(err)
		}
		repos[name] = r
		return r
	}
	// Findings hang off a scan; the first run seeded for their repository
	// serves, since this report reads findings by created_at and model.
	anchors := map[string]uint{}
	const ranFor = 5 * time.Minute
	for _, c := range corpora {
		for _, sc := range c.scans {
			row := db.Scan{
				RepositoryID: repo(sc.repo).ID, Kind: "skill", Status: sc.status, SkillName: "vuln-scan",
				Model:   sc.model,
				CostUSD: sc.cost, InputTokens: sc.in, OutputTokens: sc.out,
				CacheReadTokens: sc.cr, CacheWriteTokens: sc.cw,
				CreatedAt: now.Add(-sc.ago - ranFor - time.Minute),
			}
			switch sc.status {
			case db.ScanQueued:
				// Enqueued only: neither timestamp, so counted in no window.
			case db.ScanRunning:
				started := now.Add(-sc.ago)
				row.StartedAt = &started
			default:
				finished := now.Add(-sc.ago)
				started := finished.Add(-ranFor)
				row.StartedAt, row.FinishedAt = &started, &finished
			}
			if err := s.DB.Create(&row).Error; err != nil {
				t.Fatal(err)
			}
			if _, ok := anchors[sc.repo]; !ok {
				anchors[sc.repo] = row.ID
			}
		}
		for _, f := range c.findings {
			row := db.Finding{
				RepositoryID: repo(f.repo).ID, ScanID: anchors[f.repo], Title: "x",
				Model: f.model, Severity: f.severity, CreatedAt: now.Add(-f.ago),
			}
			if err := s.DB.Create(&row).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
}

// exportReport downloads report.json through the handler and reads it
// back with the merge tool's own decoder, so the test merges exactly what
// an operator's curl would have fetched.
func exportReport(t *testing.T, s *Server, query string) reporting.Export {
	t.Helper()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, localReq("GET", "/reporting/report.json?"+query))
	if w.Code != 200 {
		t.Fatalf("report.json?%s: status %d: %s", query, w.Code, w.Body)
	}
	export, err := reporting.Decode(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("report.json?%s: %v\n%s", query, err, w.Body)
	}
	return export
}

func mergeInputs(a, b reporting.Export) []reporting.Input {
	return []reporting.Input{{Name: "a.json", Export: a}, {Name: "b.json", Export: b}}
}

// The merge tool's promise is that the union of two discrete instances'
// exports reads as if one instance had scanned both corpora. Hold it to
// exactly that: seed two servers with disjoint corpora and a third with
// both, export all three through the handler, and require merge(A, B) to
// match the third's export figure for figure, over every window and under
// a severity floor.
//
// This is also what ties the tool to the exporter. A field added to the
// export without a merge rule fails Merge outright; one given the wrong
// rule (a median summed, a rate averaged) disagrees with the
// single-instance figure here.
func TestMergeReportsMatchesSingleInstance(t *testing.T) {
	a, cleanupA := newTestServer(t)
	defer cleanupA()
	seedMergeCorpus(t, a, mergeCorpusA)
	b, cleanupB := newTestServer(t)
	defer cleanupB()
	seedMergeCorpus(t, b, mergeCorpusB)
	union, cleanupUnion := newTestServer(t)
	defer cleanupUnion()
	seedMergeCorpus(t, union, mergeCorpusA, mergeCorpusB)

	for _, query := range []string{"interval=day", "interval=week", "interval=all", "interval=week&severity=medium"} {
		t.Run(query, func(t *testing.T) {
			requireMergeMatchesUnion(t, exportReport(t, a, query), exportReport(t, b, query), exportReport(t, union, query))
		})
	}
}

// requireMergeMatchesUnion merges two instances' exports and holds the
// result to want, the export of one instance that scanned both corpora.
// exportA was taken first, so its window starts no later than exportB's.
func requireMergeMatchesUnion(t *testing.T, exportA, exportB, want reporting.Export) {
	t.Helper()
	if exportA.Activity.ScansStarted == 0 || exportB.Activity.ScansStarted == 0 || want.Activity.Findings == 0 {
		t.Fatalf("an instance exported no activity, so the comparison would be vacuous: a=%+v b=%+v", exportA.Activity, exportB.Activity)
	}

	merged, warnings, err := reporting.Merge(mergeInputs(exportA, exportB), reporting.Options{})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("two discrete instances warned: %q", warnings)
	}

	// The one figure the merged file words differently: it says its
	// repository count is a sum of distinct counts.
	if wantNote := want.Activity.MeasuredBy + "; " + reporting.ReposScannedCaveat; merged.Activity.MeasuredBy != wantNote {
		t.Errorf("measured_by = %q, want %q", merged.Activity.MeasuredBy, wantNote)
	}
	merged.Activity.MeasuredBy = want.Activity.MeasuredBy
	for _, diff := range exportDiffs(merged, want) {
		t.Error(diff)
	}

	// The period is the union of the two windows, not either one's.
	if merged.Period.Key != "merged" || merged.Period.EndsAt != exportB.Period.EndsAt {
		t.Errorf("period = %+v", merged.Period)
	}
	switch {
	case exportA.Period.StartsAt == nil:
		if merged.Period.StartsAt != nil {
			t.Errorf("starts_at = %q, want null for unbounded inputs", *merged.Period.StartsAt)
		}
	case merged.Period.StartsAt == nil || *merged.Period.StartsAt != *exportA.Period.StartsAt:
		t.Errorf("starts_at = %v, want the earlier instance's %q", merged.Period.StartsAt, *exportA.Period.StartsAt)
	}
	if len(merged.Sources) != 2 || merged.Sources[0].File != "a.json" || merged.Sources[1].PeriodKey != want.Period.Key {
		t.Errorf("sources = %+v", merged.Sources)
	}
}

// The floor an export was taken under is recorded in it and cannot be
// re-applied, so a merge under -severity has to be able to read the
// server's spelling and refuse an input exported without it.
func TestMergeReportsSeverityFloor(t *testing.T) {
	a, cleanupA := newTestServer(t)
	defer cleanupA()
	seedMergeCorpus(t, a, mergeCorpusA)
	b, cleanupB := newTestServer(t)
	defer cleanupB()
	seedMergeCorpus(t, b, mergeCorpusB)

	mediumA := exportReport(t, a, "interval=week&severity=medium")
	mediumB := exportReport(t, b, "interval=week&severity=medium")
	plainB := exportReport(t, b, "interval=week")
	if mediumA.Filters.MinimumSeverity == nil || *mediumA.Filters.MinimumSeverity != "Medium" || plainB.Filters.MinimumSeverity != nil {
		t.Fatalf("exports do not record their floors: %v, %v", mediumA.Filters.MinimumSeverity, plainB.Filters.MinimumSeverity)
	}

	// The level is accepted the way the export URL accepts it: any case,
	// and moderate for Medium.
	for _, level := range []string{"medium", "Medium", "moderate"} {
		merged, _, err := reporting.Merge(mergeInputs(mediumA, mediumB), reporting.Options{Severity: level})
		if err != nil {
			t.Errorf("Severity %q: %v", level, err)
			continue
		}
		if merged.Filters.MinimumSeverity == nil || *merged.Filters.MinimumSeverity != "Medium" {
			t.Errorf("Severity %q: merged minimum_severity = %v, want Medium", level, merged.Filters.MinimumSeverity)
		}
	}
	// It is checked against the levels the server names in the export.
	_, _, err := reporting.Merge(mergeInputs(mediumA, mediumB), reporting.Options{Severity: "bananas"})
	if err == nil || !strings.Contains(err.Error(), "one of: "+strings.Join(db.SeverityLevels, ", ")) {
		t.Errorf("unknown level: err = %v, want the server's levels listed", err)
	}

	// An unfiltered input beside a filtered one is refused by name under
	// the option, and merged as "mixed" without it, each floor recorded.
	_, _, err = reporting.Merge(mergeInputs(mediumA, plainB), reporting.Options{Severity: "medium"})
	if err == nil || !strings.Contains(err.Error(), "b.json was exported with no severity floor") {
		t.Errorf("laxer input: err = %v, want it refused by name", err)
	}
	merged, warnings, err := reporting.Merge(mergeInputs(mediumA, plainB), reporting.Options{})
	if err != nil {
		t.Fatalf("Merge without a floor: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "filters in b.json differ from a.json") {
		t.Errorf("warnings = %q", warnings)
	}
	if merged.Filters.MinimumSeverity == nil || *merged.Filters.MinimumSeverity != reporting.MixedSeverity {
		t.Errorf("minimum_severity = %v, want %q", merged.Filters.MinimumSeverity, reporting.MixedSeverity)
	}
	if s := merged.Sources; len(s) != 2 || s[0].MinimumSeverity == nil || *s[0].MinimumSeverity != "Medium" || s[1].MinimumSeverity != nil {
		t.Errorf("sources = %+v, want Medium then null", s)
	}
	if merged.Activity.Findings != mediumA.Activity.Findings+plainB.Activity.Findings {
		t.Errorf("findings = %d, want the two inputs' %d + %d", merged.Activity.Findings, mediumA.Activity.Findings, plainB.Activity.Findings)
	}
}

// The CSV and JSON exports describe the same rows, so every JSON row field
// must have a CSV column of the same name; a column renamed in one export
// and not the other shows up here.
func TestReportingJSONMatchesCSVColumns(t *testing.T) {
	for _, row := range []any{reporting.DayRow{}, reporting.ModelRow{}} {
		typ := reflect.TypeOf(row)
		for i := range typ.NumField() {
			field := typ.Field(i)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if !slices.Contains(reportCSVHeader, name) {
				t.Errorf("%s.%s exports as %q, which is not a CSV column", typ.Name(), field.Name, name)
			}
		}
	}
}

// exportDiffs lists where two exports' figures differ, section by section.
// Floats are compared to within a tolerance: a mean pooled from two
// instances' means and the same mean computed directly round differently
// in the last bit.
func exportDiffs(got, want reporting.Export) []string {
	var diffs []string
	for _, section := range []struct {
		name      string
		got, want any
	}{
		{"filters", got.Filters, want.Filters},
		{"activity_in_period", got.Activity, want.Activity},
		{"cost_averages_per_scan", got.CostAverages, want.CostAverages},
		{"activity_by_model", got.ByModel, want.ByModel},
		{"activity_by_day", got.ByDay, want.ByDay},
	} {
		diffs = append(diffs, valueDiffs(section.name, reflect.ValueOf(section.got), reflect.ValueOf(section.want))...)
	}
	return diffs
}

func valueDiffs(path string, got, want reflect.Value) []string {
	switch want.Kind() {
	case reflect.Struct:
		var diffs []string
		for i := range want.NumField() {
			diffs = append(diffs, valueDiffs(path+"."+want.Type().Field(i).Name, got.Field(i), want.Field(i))...)
		}
		return diffs
	case reflect.Slice:
		if got.Len() != want.Len() {
			return []string{fmt.Sprintf("%s: %d rows, want %d\n got: %+v\nwant: %+v", path, got.Len(), want.Len(), got.Interface(), want.Interface())}
		}
		var diffs []string
		for i := range want.Len() {
			diffs = append(diffs, valueDiffs(fmt.Sprintf("%s[%d]", path, i), got.Index(i), want.Index(i))...)
		}
		return diffs
	case reflect.Pointer:
		if got.IsNil() || want.IsNil() {
			if got.IsNil() != want.IsNil() {
				return []string{fmt.Sprintf("%s: %v, want %v", path, got, want)}
			}
			return nil
		}
		return valueDiffs(path, got.Elem(), want.Elem())
	case reflect.Float64:
		const tolerance = 1e-9
		g, w := got.Float(), want.Float()
		if math.Abs(g-w) > tolerance*math.Max(1, math.Max(math.Abs(g), math.Abs(w))) {
			return []string{fmt.Sprintf("%s: %v, want %v", path, g, w)}
		}
		return nil
	default:
		if !reflect.DeepEqual(got.Interface(), want.Interface()) {
			return []string{fmt.Sprintf("%s: %v, want %v", path, got.Interface(), want.Interface())}
		}
		return nil
	}
}
