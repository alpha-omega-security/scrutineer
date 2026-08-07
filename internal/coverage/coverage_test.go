package coverage

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseEmptyIsNotARecord(t *testing.T) {
	for _, raw := range []string{"", "   ", "not json"} {
		if _, ok := Parse(raw); ok {
			t.Fatalf("Parse(%q) reported a record where none was stored", raw)
		}
	}
}

// The diff-rescan path wrote {requested_mode, actual_mode, fallback_reason}
// with no version. Those rows must keep their meaning, and must not be read
// as a completeness claim they never made.
func TestParseLegacyDiffBlob(t *testing.T) {
	rec, ok := Parse(`{"requested_mode":"diff","actual_mode":"full","fallback_reason":"baseline commit is unreachable"}`)
	if !ok {
		t.Fatal("legacy diff blob did not parse")
	}
	if rec.RequestedMode != "diff" || rec.ActualMode != "full" {
		t.Fatalf("modes lost: %+v", rec)
	}
	if rec.FallbackReason != "baseline commit is unreachable" {
		t.Fatalf("fallback reason lost: %q", rec.FallbackReason)
	}
	if rec.Completeness != CompletenessUnknown {
		t.Fatalf("completeness = %q, want %q — a legacy row makes no claim",
			rec.Completeness, CompletenessUnknown)
	}
}

// markThreatModelUpdate merged three untyped keys into the same column.
// Those rows exist in every deployment that has run a diff threat-model
// scan, so the typed record has to read them back rather than drop them.
func TestParseLegacyThreatModelKeys(t *testing.T) {
	rec, ok := Parse(`{"threat_model_update":"skipped_small_diff","threat_model_material":false,"threat_model_update_reason":"diff below threshold"}`)
	if !ok {
		t.Fatal("legacy threat-model blob did not parse")
	}
	if rec.ThreatModel == nil {
		t.Fatal("threat-model state dropped")
	}
	if rec.ThreatModel.Update != "skipped_small_diff" || rec.ThreatModel.Material {
		t.Fatalf("threat-model state wrong: %+v", *rec.ThreatModel)
	}
	if rec.ThreatModel.Reason != "diff below threshold" {
		t.Fatalf("threat-model reason lost: %q", rec.ThreatModel.Reason)
	}
}

// A false negative here would be silent: threat_model_material is false on
// four of the five call sites, so "absent" and "present but false" have to be
// told apart by the key's presence, not by its value.
func TestParseWithoutThreatModelKeysLeavesItNil(t *testing.T) {
	rec, ok := Parse(`{"requested_mode":"diff","actual_mode":"diff"}`)
	if !ok {
		t.Fatal("blob did not parse")
	}
	if rec.ThreatModel != nil {
		t.Fatalf("invented threat-model state: %+v", *rec.ThreatModel)
	}
}

func TestMarshalStampsVersionAndCompleteness(t *testing.T) {
	raw, err := Marshal(Record{RequestedMode: "full"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != float64(Version) {
		t.Fatalf("version = %v, want %d", got["version"], Version)
	}
	if got["completeness"] != CompletenessUnknown {
		t.Fatalf("completeness = %v, want %q", got["completeness"], CompletenessUnknown)
	}
}

func TestReconcileCompleteWhenEveryScopedPathIsSettled(t *testing.T) {
	rec := Record{Receipts: []Receipt{
		{Path: "a.go", Disposition: DispositionReviewedClean},
		{Path: "b.go", Disposition: DispositionReviewedFindings},
		{Path: "vendor/c.go", Disposition: DispositionExcluded, Reason: "vendored"},
	}}
	if gaps := rec.Reconcile([]string{"a.go", "b.go", "vendor/c.go"}); gaps != nil {
		t.Fatalf("gaps = %v, want none", gaps)
	}
	if rec.Completeness != CompletenessComplete {
		t.Fatalf("completeness = %q, want %q", rec.Completeness, CompletenessComplete)
	}
	if rec.Reason != "" {
		t.Fatalf("complete scan carries a reason: %q", rec.Reason)
	}
}

func TestReconcileReportsUnreceiptedPaths(t *testing.T) {
	rec := Record{Receipts: []Receipt{{Path: "a.go", Disposition: DispositionReviewedClean}}}
	gaps := rec.Reconcile([]string{"a.go", "z.go", "m.go"})
	if want := []string{"m.go", "z.go"}; !reflect.DeepEqual(gaps, want) {
		t.Fatalf("gaps = %v, want %v", gaps, want)
	}
	if rec.Completeness != CompletenessPartial {
		t.Fatalf("completeness = %q, want %q", rec.Completeness, CompletenessPartial)
	}
	if rec.Reason == "" {
		t.Fatal("partial scan must carry a reason")
	}
}

// The reason the disposition set was split: a receipt is not the same as
// finished work. A failed or cost-capped unit is fully receipted and still
// leaves the scan partial.
func TestReconcileTreatsUnfinishedReceiptsAsGaps(t *testing.T) {
	for _, disposition := range []string{DispositionFailed, DispositionCostCapped, DispositionDeferred} {
		rec := Record{Receipts: []Receipt{
			{Path: "a.go", Disposition: DispositionReviewedClean},
			{Path: "b.go", Disposition: disposition},
		}}
		gaps := rec.Reconcile([]string{"a.go", "b.go"})
		if want := []string{"b.go"}; !reflect.DeepEqual(gaps, want) {
			t.Fatalf("%s: gaps = %v, want %v", disposition, gaps, want)
		}
		if rec.Completeness != CompletenessPartial {
			t.Fatalf("%s: completeness = %q, want %q", disposition, rec.Completeness, CompletenessPartial)
		}
	}
}

// The anti-trust property this contract exists for: with no scope of its own
// to check against, the worker cannot upgrade the skill's word into a
// completeness claim, however many receipts arrive.
func TestReconcileWithoutScopeNeverClaimsComplete(t *testing.T) {
	rec := Record{Receipts: []Receipt{
		{Path: "a.go", Disposition: DispositionReviewedClean},
		{Path: "b.go", Disposition: DispositionReviewedClean},
	}}
	if gaps := rec.Reconcile(nil); gaps != nil {
		t.Fatalf("gaps = %v, want none", gaps)
	}
	if rec.Completeness != CompletenessUnknown {
		t.Fatalf("completeness = %q, want %q", rec.Completeness, CompletenessUnknown)
	}
	if rec.Reason == "" {
		t.Fatal("unknown completeness must say why it is unknown")
	}
}

func TestRoundTripPreservesRecord(t *testing.T) {
	want := Record{
		RequestedMode: "diff",
		ActualMode:    "diff",
		Completeness:  CompletenessPartial,
		Reason:        "staged work items have no receipt",
		IncludedPaths: []string{"a.go"},
		ExcludedPaths: []PathReason{{Path: "vendor/x.go", Reason: "vendored"}},
		Receipts:      []Receipt{{Path: "a.go", Disposition: DispositionReviewedFindings}},
		OpenQuestions: []string{"is the parser reachable from the CLI?"},
		ThreatModel:   &ThreatModelState{Update: "updated", Material: true},
	}
	raw, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Parse(raw)
	if !ok {
		t.Fatal("marshalled record did not parse")
	}
	want.Version = Version
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", got, want)
	}
}
