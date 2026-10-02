package reporting

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Fixtures: two overlapping week exports from discrete instances (weekB
// carries a second model), an all-time export (null starts_at), and
// Medium-floor variants. Weights and averages are chosen so every weighted
// mean is an exact binary float and the expectations compare with ==.

func ptr(s string) *string { return &s }

func weekA() Export {
	return Export{
		GeneratedAt: "2026-09-14T14:00:00Z",
		Period: Period{
			Key: "week", Label: "Week", Meaning: "rolling 7 days ending at generated_at",
			StartsAt: ptr("2026-09-07T14:00:00Z"), EndsAt: "2026-09-14T14:00:00Z",
		},
		Filters: Filters{
			AppliesTo:        []string{"findings"},
			SeverityOrdering: []string{"Low", "Medium", "High", "Critical"},
		},
		Activity: Activity{
			ReposScanned: 3, ScansStarted: 10, ScansCompleted: 8, Findings: 5,
			MeasuredBy: "scans_started at started_at",
		},
		CostAverages: CostAverages{
			Population: "completed scans with a recorded cost",
			InPeriod:   Averages{ScansAveraged: 6, AvgCostUSD: 2, AvgTotalTokens: 18},
			AllTime:    Averages{ScansAveraged: 100, AvgCostUSD: 3, AvgTotalTokens: 18},
		},
		ByModel: []ModelRow{
			{Model: "model-x", ScansStarted: 10, ScansCompleted: 8, Findings: 5, CostUSD: 16, TotalTokens: 140,
				ScansAveraged: 6, AvgCostUSD: 2, AvgTotalTokens: 18},
		},
		ByDay: []DayRow{
			{Date: "2026-09-14", ReposScanned: 2, ScansStarted: 10, ScansCompleted: 8, Findings: 5, CostUSD: 16, TotalTokens: 140,
				ScansAveraged: 6, AvgCostUSD: 2, AvgTotalTokens: 18},
			{Date: "2026-09-12", ReposScanned: 1, ScansStarted: 1, ScansCompleted: 1, CostUSD: 1, TotalTokens: 10,
				ScansAveraged: 1, AvgCostUSD: 1, AvgTotalTokens: 10},
		},
	}
}

func weekB() Export {
	e := weekA()
	e.GeneratedAt = "2026-09-14T15:00:00Z"
	e.Period.StartsAt = ptr("2026-09-07T15:00:00Z")
	e.Period.EndsAt = "2026-09-14T15:00:00Z"
	e.Activity = Activity{ReposScanned: 1, ScansStarted: 4, ScansCompleted: 4, Findings: 20, MeasuredBy: e.Activity.MeasuredBy}
	e.CostAverages.InPeriod = Averages{ScansAveraged: 2, AvgCostUSD: 4, AvgTotalTokens: 22}
	e.CostAverages.AllTime = Averages{ScansAveraged: 50, AvgCostUSD: 6, AvgTotalTokens: 24}
	e.ByModel = []ModelRow{
		{Model: "model-x", ScansStarted: 4, ScansCompleted: 4, Findings: 7, CostUSD: 16, TotalTokens: 60,
			ScansAveraged: 2, AvgCostUSD: 4, AvgTotalTokens: 22},
		{Model: "model-y", ScansStarted: 1, ScansCompleted: 1, Findings: 13, CostUSD: 0.5, TotalTokens: 5,
			ScansAveraged: 1, AvgCostUSD: 0.5, AvgTotalTokens: 5},
	}
	e.ByDay = []DayRow{
		{Date: "2026-09-14", ReposScanned: 1, ScansStarted: 4, ScansCompleted: 4, Findings: 7, CostUSD: 8, TotalTokens: 60,
			ScansAveraged: 2, AvgCostUSD: 4, AvgTotalTokens: 22},
		{Date: "2026-09-13", ReposScanned: 1, ScansStarted: 1, ScansCompleted: 1, Findings: 13, CostUSD: 0.5, TotalTokens: 5,
			ScansAveraged: 1, AvgCostUSD: 0.5, AvgTotalTokens: 5},
	}
	return e
}

func allC() Export {
	e := weekA()
	e.GeneratedAt = "2026-09-21T09:00:00Z"
	e.Period = Period{Key: "all", Label: "All time", Meaning: "every scan and finding on record", EndsAt: "2026-09-21T09:00:00Z"}
	e.CostAverages.AllTime = Averages{ScansAveraged: 7, AvgCostUSD: 1, AvgTotalTokens: 9}
	return e
}

// medium is weekA exported under a Medium floor. allTimeScans varies the
// all-time fingerprint so two Medium fixtures do not read as duplicates.
func medium(stamp string, allTimeScans int) Export {
	e := weekA()
	e.GeneratedAt = stamp
	e.Filters.MinimumSeverity = ptr("Medium")
	e.CostAverages.AllTime.ScansAveraged = allTimeScans
	return e
}

func mediumA() Export { return medium("2026-09-14T14:30:00Z", 30) }
func mediumB() Export { return medium("2026-09-14T15:30:00Z", 40) }

func in(name string, e Export) Input { return Input{Name: name, Export: e} }

func mustMerge(t *testing.T, opts Options, inputs ...Input) (Export, []string) {
	t.Helper()
	merged, warnings, err := Merge(inputs, opts)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	return merged, warnings
}

func TestMergeTwoWeekExports(t *testing.T) {
	merged, warnings := mustMerge(t, Options{}, in("a.json", weekA()), in("b.json", weekB()))
	if len(warnings) != 0 {
		t.Errorf("clean merge warned: %q", warnings)
	}
	if len(merged.ByDay) != 3 || len(merged.ByModel) != 2 {
		t.Fatalf("got %d day rows and %d model rows, want 3 and 2: %+v", len(merged.ByDay), len(merged.ByModel), merged)
	}
	// Weights 6 and 2 (in-period, shared day, shared model) and 100 and 50
	// (all-time) make every weighted mean below an exact binary float.
	sharedDay := DayRow{Date: "2026-09-14", ReposScanned: 3, ScansStarted: 14, ScansCompleted: 12, Findings: 12, CostUSD: 24, TotalTokens: 200,
		ScansAveraged: 8, AvgCostUSD: 2.5, AvgTotalTokens: 19}
	sharedModel := ModelRow{Model: "model-x", ScansStarted: 14, ScansCompleted: 12, Findings: 12, CostUSD: 32, TotalTokens: 200,
		ScansAveraged: 8, AvgCostUSD: 2.5, AvgTotalTokens: 19}
	for _, tc := range []struct {
		name      string
		got, want any
	}{
		{"period counts summed, caveat appended", merged.Activity,
			Activity{ReposScanned: 4, ScansStarted: 14, ScansCompleted: 12, Findings: 25, MeasuredBy: "scans_started at started_at; " + ReposScannedCaveat}},
		{"in-period averages weighted, weights summed", merged.CostAverages.InPeriod, Averages{ScansAveraged: 8, AvgCostUSD: 2.5, AvgTotalTokens: 19}},
		{"all-time averages pooled", merged.CostAverages.AllTime, Averages{ScansAveraged: 150, AvgCostUSD: 4, AvgTotalTokens: 20}},
		{"population kept", merged.CostAverages.Population, "completed scans with a recorded cost"},
		{"shared day summed and weighted", merged.ByDay[0], sharedDay},
		{"other days newest first, single-source rows unchanged", merged.ByDay[1:], []DayRow{weekB().ByDay[1], weekA().ByDay[1]}},
		{"models by findings then cost, shared model merged", merged.ByModel, []ModelRow{weekB().ByModel[1], sharedModel}},
		{"latest generated_at", merged.GeneratedAt, "2026-09-14T15:00:00Z"},
		{"period is the union of the windows", merged.Period, Period{
			Key: "merged", Label: "Merged", StartsAt: ptr("2026-09-07T14:00:00Z"), EndsAt: "2026-09-14T15:00:00Z",
			Meaning: "union of 2 source reports (period keys: week) assumed to come from discrete scanner instances " +
				"with disjoint corpora; totals summed; rows present in more than one source have averages weighted " +
				"by scans_averaged; all_time averages pooled across sources",
		}},
		{"agreeing filters kept, floor stays null", merged.Filters, weekA().Filters},
		{"sources name the inputs as given", merged.Sources, []Source{
			{File: "a.json", GeneratedAt: "2026-09-14T14:00:00Z", PeriodKey: "week", StartsAt: ptr("2026-09-07T14:00:00Z"), EndsAt: "2026-09-14T14:00:00Z"},
			{File: "b.json", GeneratedAt: "2026-09-14T15:00:00Z", PeriodKey: "week", StartsAt: ptr("2026-09-07T15:00:00Z"), EndsAt: "2026-09-14T15:00:00Z"},
		}},
	} {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, asJSON(t, tc.got), asJSON(t, tc.want))
		}
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestMergeRefusesMixedPeriods(t *testing.T) {
	_, _, err := Merge([]Input{in("a.json", weekA()), in("c.json", allC())}, Options{})
	if !errors.Is(err, ErrMixedPeriods) || !strings.Contains(err.Error(), "all, week") {
		t.Fatalf("err = %v, want ErrMixedPeriods naming the keys", err)
	}

	merged, warnings := mustMerge(t, Options{AllowMixedPeriods: true}, in("a.json", weekA()), in("c.json", allC()))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "all, week") {
		t.Errorf("warnings = %q, want one naming the mixed keys", warnings)
	}
	// An interval=all export has a null starts_at; the union is unbounded.
	if merged.Period.StartsAt != nil {
		t.Errorf("starts_at = %q, want null with an unbounded source", *merged.Period.StartsAt)
	}
	if merged.Period.EndsAt != "2026-09-21T09:00:00Z" {
		t.Errorf("ends_at = %q", merged.Period.EndsAt)
	}

	// A merged file counts for the windows folded into it, not for "merged",
	// so re-merging it beside another week export is not a mismatch...
	ab, _ := mustMerge(t, Options{}, in("a.json", weekA()), in("b.json", weekB()))
	if _, _, err := Merge([]Input{in("ab.json", ab), in("b2.json", mediumB())}, Options{}); err != nil {
		t.Errorf("re-merge of week sources with a week export: %v", err)
	}
	// ...while one that pooled a week and an all-time export still is.
	ac, _ := mustMerge(t, Options{AllowMixedPeriods: true}, in("a.json", weekA()), in("c.json", allC()))
	if _, _, err := Merge([]Input{in("ac.json", ac), in("b.json", weekB())}, Options{}); !errors.Is(err, ErrMixedPeriods) {
		t.Errorf("re-merge of mixed sources: err = %v, want ErrMixedPeriods", err)
	}
}

func TestMergeWarnsAboutLikelyDuplicate(t *testing.T) {
	// Two downloads of one instance a minute apart differ in generated_at
	// and period but share the all-time averages, and would double every
	// figure.
	again := weekA()
	again.GeneratedAt = "2026-09-14T14:01:00Z"
	again.Period.StartsAt = ptr("2026-09-07T14:01:00Z")
	again.Period.EndsAt = "2026-09-14T14:01:00Z"
	_, warnings := mustMerge(t, Options{}, in("a.json", weekA()), in("a-again.json", again))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "a-again.json and a.json have identical all-time cost averages") {
		t.Errorf("warnings = %q, want a duplicate warning", warnings)
	}
}

func TestMergeMixedSeverityFloors(t *testing.T) {
	merged, warnings := mustMerge(t, Options{}, in("medium_a.json", mediumA()), in("week_a.json", weekA()))
	if len(warnings) != 1 || !strings.Contains(warnings[0], "filters in week_a.json differ from medium_a.json") {
		t.Errorf("warnings = %q, want the filters warning", warnings)
	}
	// No single floor is true of the mixed counts, and null would read as
	// unfiltered, so the merged file carries a distinct marker and each
	// source records its own floor.
	if merged.Filters.MinimumSeverity == nil || *merged.Filters.MinimumSeverity != MixedSeverity {
		t.Errorf("minimum_severity = %v, want %q", merged.Filters.MinimumSeverity, MixedSeverity)
	}
	if s := merged.Sources; len(s) != 2 || s[0].MinimumSeverity == nil || *s[0].MinimumSeverity != "Medium" || s[1].MinimumSeverity != nil {
		t.Errorf("sources = %+v, want Medium then null", s)
	}

	// Merged again, the file can satisfy no floor and keeps its provenance.
	if _, _, err := Merge([]Input{in("mixed.json", merged), in("week_b.json", weekB())}, Options{Severity: "all"}); err == nil ||
		!strings.Contains(err.Error(), `mixed.json was exported with a minimum severity of "mixed"`) {
		t.Errorf("re-merge under -severity all: err = %v, want the mixed file refused", err)
	}
	if _, _, err := Merge([]Input{in("mixed.json", merged), in("medium_b.json", mediumB())}, Options{Severity: "medium"}); err == nil {
		t.Error("re-merge under -severity medium accepted the mixed file")
	}
	again, _ := mustMerge(t, Options{}, in("mixed.json", merged), in("week_b.json", weekB()))
	if again.Filters.MinimumSeverity == nil || *again.Filters.MinimumSeverity != MixedSeverity {
		t.Errorf("re-merged minimum_severity = %v, want %q", again.Filters.MinimumSeverity, MixedSeverity)
	}
	var files []string
	for _, s := range again.Sources {
		files = append(files, s.File)
	}
	if want := []string{"medium_a.json", "week_a.json", "week_b.json"}; !reflect.DeepEqual(files, want) {
		t.Errorf("re-merged sources = %v, want the originals %v", files, want)
	}
}

func TestMergeIsAssociative(t *testing.T) {
	ab, _ := mustMerge(t, Options{}, in("a.json", weekA()), in("b.json", weekB()))
	abc, _ := mustMerge(t, Options{}, in("ab.json", ab), in("c.json", mediumB()))
	flat, _ := mustMerge(t, Options{}, in("a.json", weekA()), in("b.json", weekB()), in("c.json", mediumB()))
	if !reflect.DeepEqual(abc, flat) {
		t.Errorf("merge(merge(a, b), c) != merge(a, b, c):\n%+v\n%+v", abc, flat)
	}
	if n := strings.Count(abc.Activity.MeasuredBy, ReposScannedCaveat); n != 1 {
		t.Errorf("caveat appears %d times in %q", n, abc.Activity.MeasuredBy)
	}
}

func TestMergeSeverityOption(t *testing.T) {
	for _, tc := range []struct {
		name     string
		severity string
		inputs   []Input
		wantErr  string
	}{
		{"agreeing floors", "medium", []Input{in("medium_a.json", mediumA()), in("medium_b.json", mediumB())}, ""},
		{"case folded", "MEDIUM", []Input{in("medium_a.json", mediumA()), in("medium_b.json", mediumB())}, ""},
		// The server folds ?severity=moderate into Medium, so the option
		// accepts what the export URL accepts.
		{"moderate alias", "moderate", []Input{in("medium_a.json", mediumA()), in("medium_b.json", mediumB())}, ""},
		{"laxer input", "medium", []Input{in("medium_a.json", mediumA()), in("week_a.json", weekA())},
			"week_a.json was exported with no severity floor; a merged Medium report needs every input exported with ?severity=medium"},
		{"unfiltered inputs", "all", []Input{in("week_a.json", weekA()), in("week_b.json", weekB())}, ""},
		{"filtered input under all", "all", []Input{in("medium_a.json", mediumA())},
			`medium_a.json was exported with a minimum severity of "Medium"`},
		{"unknown level", "bananas", []Input{in("week_a.json", weekA())}, `unknown severity "bananas" (one of: Low, Medium, High, Critical, or all)`},
		{"mixed is not a level", MixedSeverity, []Input{in("week_a.json", weekA())}, "unknown severity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged, _, err := Merge(tc.inputs, Options{Severity: tc.severity})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Merge: %v", err)
				}
				if tc.severity != "all" && (merged.Filters.MinimumSeverity == nil || *merged.Filters.MinimumSeverity != "Medium") {
					t.Errorf("minimum_severity = %v, want the agreed Medium kept", merged.Filters.MinimumSeverity)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestMergeRejectsNothing(t *testing.T) {
	if _, _, err := Merge(nil, Options{}); err == nil {
		t.Error("Merge(nil) succeeded")
	}
}

// reencode round-trips an export through JSON with a mutation applied to
// the untyped tree, so a test can add or remove one field.
func reencode(t *testing.T, e Export, mutate func(doc map[string]any)) []byte {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	mutate(doc)
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecode(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		for _, e := range []Export{weekA(), allC()} {
			got, err := Decode(strings.NewReader(string(reencode(t, e, func(map[string]any) {}))))
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !reflect.DeepEqual(got, e) {
				t.Errorf("round trip changed the export:\n%+v\n%+v", got, e)
			}
		}
	})

	t.Run("merged export round trips with its sources", func(t *testing.T) {
		merged, _ := mustMerge(t, Options{}, in("a.json", weekA()), in("b.json", weekB()))
		got, err := Decode(strings.NewReader(string(reencode(t, merged, func(map[string]any) {}))))
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !reflect.DeepEqual(got, merged) {
			t.Errorf("round trip changed the merged export:\n%+v\n%+v", got, merged)
		}
	})

	for _, tc := range []struct {
		name    string
		doc     string
		wantErr string
	}{
		{"not an object", `[]`, "not a /reporting JSON export"},
		{"empty object", `{}`, "expected an object with generated_at and period.ends_at"},
		{"not JSON", `{`, "not a /reporting JSON export"},
		{"bad timestamp", string(reencode(t, weekA(), func(doc map[string]any) { doc["generated_at"] = "yesterday" })),
			`generated_at: "yesterday" is not an RFC 3339 timestamp`},
		// A field this tool does not know would be dropped from the merge;
		// one it knows but the file lacks would be merged as zero. Both are
		// a version mismatch and both are refused before any merge.
		{"unknown field", string(reencode(t, weekA(), func(doc map[string]any) {
			doc["cost_averages_per_scan"].(map[string]any)["in_period"].(map[string]any)["median_cost_usd"] = 1
		})), "unknown field cost_averages_per_scan.in_period.median_cost_usd"},
		{"unknown field in a row", string(reencode(t, weekA(), func(doc map[string]any) {
			doc["activity_by_day"].([]any)[1].(map[string]any)["rate"] = 0.5
		})), "unknown field activity_by_day[1].rate"},
		{"missing field", string(reencode(t, weekA(), func(doc map[string]any) {
			delete(doc["cost_averages_per_scan"].(map[string]any)["all_time"].(map[string]any), "avg_total_tokens")
		})), "missing field cost_averages_per_scan.all_time.avg_total_tokens"},
		{"missing section", string(reencode(t, weekA(), func(doc map[string]any) { delete(doc, "activity_by_model") })),
			"missing field activity_by_model"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tc.doc))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// Every figure the export carries must say how it merges. The row types
// say so per field in their merge tags, which planFor checks; the sections
// Merge combines by hand are listed here, so a section added to Export
// without a rule in Merge fails this test rather than vanishing from every
// merged report.
func TestEveryExportFieldHasAMergeRule(t *testing.T) {
	for _, row := range []any{Activity{}, Averages{}, DayRow{}, ModelRow{}} {
		if _, err := planFor(reflect.TypeOf(row)); err != nil {
			t.Errorf("%T: %v", row, err)
		}
	}
	handled := map[reflect.Type][]string{
		reflect.TypeOf(Export{}):       {"GeneratedAt", "Period", "Filters", "Activity", "CostAverages", "ByModel", "ByDay", "Sources"},
		reflect.TypeOf(Period{}):       {"Key", "Label", "Meaning", "StartsAt", "EndsAt"},
		reflect.TypeOf(Filters{}):      {"MinimumSeverity", "AppliesTo", "SeverityOrdering"},
		reflect.TypeOf(CostAverages{}): {"Population", "InPeriod", "AllTime"},
	}
	for typ, fields := range handled {
		var names []string
		for i := range typ.NumField() {
			names = append(names, typ.Field(i).Name)
		}
		if !reflect.DeepEqual(names, fields) {
			t.Errorf("%s has fields %v; Merge handles %v -- add a rule to Merge and list the field here", typ.Name(), names, fields)
		}
	}
}

func TestMergeRowsRejectsUntaggedField(t *testing.T) {
	type row struct {
		Model     string  `json:"model" merge:"key"`
		Findings  int     `json:"findings" merge:"sum"`
		MedianUSD float64 `json:"median_cost_usd"`
	}
	_, err := mergeRows([]row{{Model: "m", Findings: 1, MedianUSD: 2}, {Model: "m", Findings: 3, MedianUSD: 4}})
	if err == nil || !strings.Contains(err.Error(), "row.MedianUSD: float64 field has no merge rule") {
		t.Errorf("err = %v, want the untagged field named", err)
	}

	type meanWithoutWeight struct {
		Avg float64 `merge:"mean"`
	}
	if _, err := mergeRows([]meanWithoutWeight{{Avg: 1}}); err == nil || !strings.Contains(err.Error(), "need a weight field") {
		t.Errorf("err = %v, want a mean without a weight refused", err)
	}

	type mistyped struct {
		Count string `merge:"sum"`
	}
	if _, err := mergeRows([]mistyped{{Count: "1"}}); err == nil || !strings.Contains(err.Error(), "string field has no merge rule") {
		t.Errorf("err = %v, want a sum-tagged string refused", err)
	}
}

func TestMergeRowsEdgeCases(t *testing.T) {
	// No weight anywhere leaves the mean at zero rather than NaN, as the
	// server reports an empty population.
	empty, err := mergeRows([]Averages{{}, {}})
	if err != nil || empty != (Averages{}) {
		t.Errorf("mergeRows(empty, empty) = %+v, %v", empty, err)
	}
	// A weightless row contributes nothing to a mean but its counts still
	// add, and a lone row comes back as it went in.
	rows := []DayRow{{Date: "2026-09-14", ScansStarted: 1}, weekA().ByDay[0]}
	got, err := mergeRows(rows)
	if err != nil || got.AvgCostUSD != 2 || got.ScansStarted != 11 {
		t.Errorf("mergeRows = %+v, %v", got, err)
	}
	// Rows with different keys are a grouping bug, not data to average.
	if _, err := mergeRows([]DayRow{{Date: "2026-09-14"}, {Date: "2026-09-15"}}); err == nil {
		t.Error("rows with different keys merged")
	}
	only, _ := mergeRows([]ModelRow{weekB().ByModel[1]})
	if only != weekB().ByModel[1] {
		t.Errorf("single row changed: %+v", only)
	}
}
