package reflection

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func fixture() (Input, Report) {
	return Input{TriageScanID: 1, Sources: []Source{{ScanID: 2, Stage: "verify", Commit: "abc", Excerpt: "error: missing libfoo"}}},
		Report{Notes: []Note{{Stage: "verify", ScanID: 2, Kind: "missing_dependency", Summary: "libfoo was unavailable", Evidence: "missing libfoo"}}}
}

func TestValidate(t *testing.T) {
	for _, name := range []string{"valid", "foreign_scan", "wrong_stage", "duplicate", "omitted", "invented_evidence", "unknown_kind", "blank_summary", "long_summary", "missing", "hidden_missing", "no_observation"} {
		t.Run(name, func(t *testing.T) {
			in, out := fixture()
			valid := false
			switch name {
			case "valid":
				valid = true
			case "foreign_scan":
				out.Notes[0].ScanID = 3
			case "wrong_stage":
				out.Notes[0].Stage = "other"
			case "duplicate":
				out.Notes = append(out.Notes, out.Notes[0])
			case "omitted":
				out.Notes = nil
			case "invented_evidence":
				out.Notes[0].Evidence = "success"
			case "unknown_kind":
				out.Notes[0].Kind = "known_non_finding"
			case "blank_summary":
				out.Notes[0].Summary = " "
			case "long_summary":
				out.Notes[0].Summary = strings.Repeat("x", MaxText+1)
			case "missing":
				in.Sources[0].Missing = true
				out.Notes[0].Kind, out.Notes[0].Evidence = "missing_transcript", ""
				valid = true
			case "hidden_missing":
				in.Sources = append(in.Sources, Source{ScanID: 3, Stage: "verify", Missing: true})
			case "no_observation":
				out.Notes[0].Kind, out.Notes[0].Evidence = "no_observation", ""
				valid = true
			}
			if err := Validate(in, out); (err == nil) != valid {
				t.Fatalf("valid=%v, err=%v", valid, err)
			}
		})
	}
}

func TestExcerpt(t *testing.T) {
	prefix := "hello\nerror: missing libfoo\n" + strings.Repeat("unimportant\n", Window)
	tail := strings.Repeat("x", Window) + "\nfinal result"
	got := Excerpt(prefix, tail)
	if len(got) > MaxExcerpt || !strings.Contains(got, "missing libfoo") || !strings.HasSuffix(got, "final result") {
		t.Fatalf("bad excerpt: %q", got)
	}
}

func TestMergePreservesContractAndBoundsNotes(t *testing.T) {
	in, out := fixture()
	model := `{"known_non_findings":[{"why_safe":"operator"}],"controls":[{"id":"keep"}],"extra":{"nested":true}}`
	for id := uint(1); id <= MaxNotes+2; id++ {
		in.TriageScanID = id
		var err error
		model, err = Merge(model, in, out, id+1000)
		if err != nil {
			t.Fatal(err)
		}
	}
	first := model
	model, err := Merge(model, in, out, in.TriageScanID+1000)
	if err != nil || first != model {
		t.Fatalf("merge not idempotent: %v", err)
	}
	var parsed struct {
		ReflectionNotes []StoredNote        `json:"reflection_notes"`
		Controls        []map[string]string `json:"controls"`
		Extra           map[string]bool     `json:"extra"`
	}
	if err := json.Unmarshal([]byte(model), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.ReflectionNotes) != MaxNotes || parsed.ReflectionNotes[0].TriageScanID != MaxNotes+2 || parsed.Controls[0]["id"] != "keep" || !parsed.Extra["nested"] {
		t.Fatalf("unexpected merge: %+v", parsed)
	}
	fresh, err := Preserve(model, `{"description":"new","reflection_notes":[{"invented":true}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fresh, "invented") || !strings.Contains(fresh, fmt.Sprint(MaxNotes+2)) || !strings.Contains(fresh, "new") {
		t.Fatalf("bad preservation: %s", fresh)
	}
}

func TestMergeKeepsNewerReflection(t *testing.T) {
	in, out := fixture()
	newer, err := Merge(`{"controls":[]}`, in, out, 20)
	if err != nil {
		t.Fatal(err)
	}
	out.Notes[0].Summary = "older attempt completed late"
	got, err := Merge(newer, in, out, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got != newer {
		t.Fatalf("older reflection replaced newer notes: %s", got)
	}
}

func TestPreserveAllowsReplacingLegacyNonObject(t *testing.T) {
	for _, previous := range []string{`[]`, `"legacy"`, `null`, `true`, `1`} {
		got, err := Preserve(previous, `{"description":"fresh"}`)
		if err != nil || !strings.Contains(got, `"fresh"`) {
			t.Fatalf("previous=%s result=%s err=%v", previous, got, err)
		}
	}
	if _, err := Preserve(`{"broken":`, `{"description":"fresh"}`); err == nil {
		t.Fatal("silently discarded corrupt JSON")
	}
}

func TestValidateInputRejectsCorruptSnapshots(t *testing.T) {
	for _, name := range []string{"empty", "wrong_id", "duplicate", "empty_stage", "oversized"} {
		t.Run(name, func(t *testing.T) {
			input, _ := fixture()
			switch name {
			case "empty":
				input.Sources = nil
			case "wrong_id":
				input.Sources[0].ScanID = 0
			case "duplicate":
				input.Sources = append(input.Sources, input.Sources[0])
			case "empty_stage":
				input.Sources[0].Stage = " "
			case "oversized":
				input.Sources[0].Excerpt = strings.Repeat("x", MaxExcerpt+1)
			}
			if err := ValidateInput(input); err == nil {
				t.Fatal("accepted invalid snapshot")
			}
		})
	}
}
