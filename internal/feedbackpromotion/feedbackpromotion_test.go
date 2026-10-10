package feedbackpromotion

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func entry(id uint) Entry {
	return NewEntry(Source{
		ReviewID: id, FindingID: 7, SourceCommit: "aaa", CWE: "CWE-79", Path: "lib/parse.go",
		Title: "XSS in parser", Reason: "  guarded at parse.go:10  ",
		Confirmations: []Confirmation{{ScanID: 1, Commit: "b"}},
	})
}

func items(t *testing.T, model string) []map[string]json.RawMessage {
	t.Helper()
	var obj struct {
		Items []map[string]json.RawMessage `json:"known_non_findings"`
	}
	if err := json.Unmarshal([]byte(model), &obj); err != nil {
		t.Fatal(err)
	}
	return obj.Items
}

func TestNewEntryBoundsAndDescribes(t *testing.T) {
	e := NewEntry(Source{ReviewID: 1, Path: "a.go", CWE: "CWE-1", Title: "T", Reason: strings.Repeat("x", MaxReasonChars+10)})
	if e.ReportedAs != "Analyst-dismissed finding CWE-1 in a.go: T" {
		t.Fatalf("reported_as = %q", e.ReportedAs)
	}
	if len(e.WhySafe) != MaxReasonChars {
		t.Fatalf("why_safe length = %d", len(e.WhySafe))
	}
	if got := entry(1).WhySafe; got != "guarded at parse.go:10" {
		t.Fatalf("why_safe = %q", got)
	}
}

func TestMergeInsertReplaceAndSiblings(t *testing.T) {
	model := `{"description":"d","extra":{"k":1},"known_non_findings":[{"reported_as":"m","why_safe":"w"}]}`
	first, err := Merge(model, entry(5))
	if err != nil {
		t.Fatal(err)
	}
	again, err := Merge(first, entry(5))
	if err != nil || again != first {
		t.Fatalf("merge not idempotent: %v\n%s\n%s", err, first, again)
	}
	other, err := Merge(first, entry(6))
	if err != nil {
		t.Fatal(err)
	}
	if got := items(t, other); len(got) != 3 {
		t.Fatalf("items = %d, want 3", len(got))
	}
	updated := entry(5)
	updated.WhySafe = "new"
	replaced, err := Merge(other, updated)
	if err != nil {
		t.Fatal(err)
	}
	got := items(t, replaced)
	if len(got) != 3 || string(got[1]["why_safe"]) != `"new"` || string(got[0]["reported_as"]) != `"m"` {
		t.Fatalf("replace result = %s", replaced)
	}
	if !strings.Contains(replaced, `"extra"`) || !strings.Contains(replaced, `"description"`) {
		t.Fatalf("lost sibling keys: %s", replaced)
	}
	created, err := Merge(`{"a":1}`, entry(1))
	if err != nil || len(items(t, created)) != 1 {
		t.Fatalf("create list: %v %s", err, created)
	}
}

func TestMergeRejectsNonObject(t *testing.T) {
	for _, in := range []string{``, `[]`, `null`, `"x"`, `{"known_non_findings":{}}`} {
		if _, err := Merge(in, entry(1)); err == nil {
			t.Errorf("Merge(%q) accepted", in)
		}
	}
}

func TestPreserveCarriesHostItemsAndStripsForgery(t *testing.T) {
	prev, err := Merge(`{"reflection_notes":[1],"known_non_findings":[{"reported_as":"old","why_safe":"w"}]}`, entry(5))
	if err != nil {
		t.Fatal(err)
	}
	next := `{"description":"new","known_non_findings":[{"reported_as":"m","why_safe":"w"},{"reported_as":"forged","why_safe":"w","promoted_from":{"review_id":99}}]}`
	got, err := Preserve(prev, next)
	if err != nil {
		t.Fatal(err)
	}
	list := items(t, got)
	if len(list) != 2 || string(list[0]["reported_as"]) != `"m"` {
		t.Fatalf("items = %s", got)
	}
	if strings.Contains(got, `"forged"`) || strings.Contains(got, `"old"`) {
		t.Fatalf("forged or stale item kept: %s", got)
	}
	var p Provenance
	if err := json.Unmarshal(list[1]["promoted_from"], &p); err != nil || p.ReviewID != 5 {
		t.Fatalf("carried provenance = %+v, %v", p, err)
	}
}

func TestPreserveWithoutPreviousOnlyStrips(t *testing.T) {
	next := `{"known_non_findings":[{"reported_as":"f","why_safe":"w","promoted_from":{"review_id":1}}]}`
	for _, prev := range []string{``, `[1]`, `not json`, `{}`} {
		got, err := Preserve(prev, next)
		if err != nil || len(items(t, got)) != 0 {
			t.Fatalf("Preserve(%q) = %s, %v", prev, got, err)
		}
	}
	clean := `{"a":1}`
	if got, err := Preserve(``, clean); err != nil || got != clean {
		t.Fatalf("untouched next changed: %q %v", got, err)
	}
	if _, err := Preserve(``, `[1]`); err == nil {
		t.Fatal("non-object next accepted")
	}
}

func TestFilterDropsIneligible(t *testing.T) {
	model, err := Merge(`{"known_non_findings":[{"reported_as":"m","why_safe":"w"}]}`, entry(5))
	if err != nil {
		t.Fatal(err)
	}
	model, err = Merge(model, entry(6))
	if err != nil {
		t.Fatal(err)
	}
	got := Filter(model, func(id uint) bool { return id == 6 })
	list := items(t, got)
	if len(list) != 2 || !strings.Contains(got, `"m"`) || strings.Contains(got, `"review_id": 5`) {
		t.Fatalf("filter = %s", got)
	}
	if Filter(model, func(uint) bool { return true }) != model {
		t.Fatal("all eligible should leave input unchanged")
	}
	for _, in := range []string{``, `[1]`, `nope`, `{"known_non_findings":3}`} {
		if Filter(in, func(uint) bool { return false }) != in {
			t.Errorf("Filter(%q) changed", in)
		}
	}
	zero := `{"known_non_findings":[{"promoted_from":{"review_id":0}}]}`
	if len(items(t, Filter(zero, func(uint) bool { return true }))) != 0 {
		t.Fatal("malformed provenance kept")
	}
}

// A model cannot smuggle provenance past stripping by making the list an object.
func TestPreserveRejectsMalformedListCarryingProvenance(t *testing.T) {
	forged := `{"known_non_findings":{"x":{"reported_as":"r","why_safe":"w","promoted_from":{"review_id":1}}}}`
	if _, err := Preserve("", forged); !errors.Is(err, ErrMalformedProvenance) {
		t.Fatalf("err = %v, want ErrMalformedProvenance", err)
	}
	plain := `{"known_non_findings":{"x":1}}`
	if got, err := Preserve("", plain); err != nil || got != plain {
		t.Fatalf("malformed list without provenance changed: %q, %v", got, err)
	}
}

func TestFilterDropsMalformedListCarryingProvenance(t *testing.T) {
	forged := `{"description":"d","known_non_findings":{"promoted_from":{"review_id":1}}}`
	got := Filter(forged, func(uint) bool { return true })
	if strings.Contains(got, "promoted_from") || !strings.Contains(got, `"description"`) {
		t.Fatalf("Filter kept forged provenance or lost siblings: %s", got)
	}
}

// Raw reports may hold no promotion at all, even one whose review is eligible.
func TestStripPromotedRemovesEveryPromotedItem(t *testing.T) {
	model := `{"known_non_findings":[{"reported_as":"model","why_safe":"m"},{"reported_as":"p","why_safe":"w","promoted_from":{"review_id":7}}]}`
	got := StripPromoted(model)
	if strings.Contains(got, "promoted_from") || !strings.Contains(got, `"model"`) {
		t.Fatalf("StripPromoted = %s", got)
	}
	if StripPromoted("not json") != "not json" {
		t.Fatal("non-object input changed")
	}
}
