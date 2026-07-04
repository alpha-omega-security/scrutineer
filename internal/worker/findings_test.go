package worker

import (
	"testing"

	"scrutineer/internal/db"
)

func TestToFindings_carriesReachabilityAndQualityTier(t *testing.T) {
	raw := []byte(`{
	  "findings": [{
	    "id": "F1", "sinks": ["S1"], "title": "heap overflow in parse",
	    "severity": "High", "cwe": "CWE-787", "location": "src/parse.c:42",
	    "reachability": "harness_only", "quality_tier": "high",
	    "trace": "t", "boundary": "b", "validation": "v", "rating": "r"
	  }]
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.toFindings(1, 1, "abc", "")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Reachability != "harness_only" {
		t.Errorf("Reachability = %q, want harness_only", got[0].Reachability)
	}
	if got[0].QualityTier != "high" {
		t.Errorf("QualityTier = %q, want high", got[0].QualityTier)
	}
}

func TestToFindings_carriesDupCheck(t *testing.T) {
	raw := []byte(`{
	  "findings": [
	    {"id": "F1", "title": "with note", "severity": "Low", "location": "a.go:1",
	     "dup_check": "compared against F0 (same file); distinct sink, different CWE"},
	    {"id": "F2", "title": "without note", "severity": "Low", "location": "b.go:1"}
	  ]
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.toFindings(1, 1, "abc", "")
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}
	if got[0].DupCheck != "compared against F0 (same file); distinct sink, different CWE" {
		t.Errorf("DupCheck = %q, want the emitted sentence", got[0].DupCheck)
	}
	if got[1].DupCheck != "" {
		t.Errorf("DupCheck = %q, want empty when the field is absent", got[1].DupCheck)
	}
}

func TestToFindings_carriesReferences(t *testing.T) {
	raw := []byte(`{
	  "findings": [{
	    "id": "F1", "title": "artipacked", "severity": "Medium",
	    "location": ".github/workflows/x.yml:18",
	    "references": [
	      {"url": "https://docs.zizmor.sh/audits/#artipacked", "summary": "zizmor docs: artipacked", "tags": "docs"},
	      {"url": "  ", "summary": "blank"},
	      {"url": "https://example.com/  ", "summary": " trimmed "}
	    ]
	  }]
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.toFindings(1, 1, "abc", "")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	refs := got[0].References
	if len(refs) != 2 {
		t.Fatalf("references = %d, want 2 (blank URL dropped)", len(refs))
	}
	if refs[0].URL != "https://docs.zizmor.sh/audits/#artipacked" || refs[0].Tags != "docs" {
		t.Errorf("first reference = %+v", refs[0])
	}
	if refs[1].URL != "https://example.com/" || refs[1].Summary != "trimmed" {
		t.Errorf("second reference whitespace not trimmed: %+v", refs[1])
	}
}

func TestParseReport_toleratesNonStringTopLevelFields(t *testing.T) {
	// #172: models sometimes copy context.json's repository object (and invent
	// an artefact object) into report.json. Only findings[] is consumed, so
	// the parser must not fail on the shape of fields it never reads.
	raw := []byte(`{
		"repository": {"url": "https://github.com/x/y.git", "name": "y"},
		"artefact": {"name": "y", "version": "1.2.3"},
		"languages": "rust",
		"spec_version": "10",
		"findings": [
			{"id": "F1", "title": "t", "severity": "Low", "cwe": "CWE-20",
			 "location": "src/a.rs:10", "sinks": ["S1"],
			 "trace": "x", "boundary": "x", "validation": "x", "rating": "x"}
		]
	}`)
	r, err := parseReport(raw)
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(r.Findings))
	}
	if r.Findings[0].ID != "F1" || r.Findings[0].Title != "t" {
		t.Errorf("finding not extracted: %+v", r.Findings[0])
	}
}

func TestMergeLocations(t *testing.T) {
	cases := []struct {
		base string
		more []string
		want string
	}{
		{"", []string{"a:1"}, "a:1"},
		{"a:1", []string{"a:1"}, "a:1"},
		{"a:1\nb:2", []string{"b:2", "c:3"}, "a:1\nb:2\nc:3"},
		{"a:1", []string{"", "  ", "a:1\n\nb:2"}, "a:1\nb:2"},
		{"", []string{"", ""}, ""},
	}
	for _, tc := range cases {
		if got := mergeLocations(tc.base, tc.more...); got != tc.want {
			t.Errorf("mergeLocations(%q, %v) = %q, want %q", tc.base, tc.more, got, tc.want)
		}
	}
}

func TestGroupByFingerprint(t *testing.T) {
	in := []db.Finding{
		{CWE: "CWE-79", Location: "a.html:5", Title: "x"},
		{CWE: "CWE-79", Location: "a.html:12", Title: "x"},
		{CWE: "CWE-79", Location: "b.html:3", Title: "x"},
		{CWE: "CWE-79", Location: "b.html:3", Title: "x"},
		{CWE: "CWE-89", Location: "a.html:5", Title: "y"},
	}
	out := groupByFingerprint(in, "semgrep")
	if len(out) != 3 {
		t.Fatalf("got %d groups, want 3 (a.html cwe-79, b.html cwe-79, a.html cwe-89)", len(out))
	}
	if out[0].Location != "a.html:5" || out[0].Locations != "a.html:5\na.html:12" {
		t.Errorf("group 0: loc=%q locs=%q", out[0].Location, out[0].Locations)
	}
	if out[1].Location != "b.html:3" || out[1].Locations != "b.html:3" {
		t.Errorf("group 1: exact duplicate should dedupe to one location, got %q", out[1].Locations)
	}
	if out[2].CWE != "CWE-89" {
		t.Errorf("group 2: different CWE should not merge with group 0")
	}
	if out[0].Fingerprint == "" || out[0].Fingerprint == out[1].Fingerprint {
		t.Error("fingerprints should be set and distinct per group")
	}
}

func TestGroupByFingerprint_preservesPreGroupedLocations(t *testing.T) {
	in := []db.Finding{
		{CWE: "CWE-79", Location: "a.html:5", Locations: "a.html:5\na.html:12\nb.html:3", Title: "x"},
	}
	out := groupByFingerprint(in, "semgrep")
	if len(out) != 1 || out[0].Locations != "a.html:5\na.html:12\nb.html:3" {
		t.Errorf("pre-grouped locations should pass through: %q", out[0].Locations)
	}
}

func TestParseReport_stringTopLevelFieldsStillWork(t *testing.T) {
	raw := []byte(`{
		"repository": "https://github.com/x/y.git",
		"artefact": "pkg:cargo/y@1.2.3",
		"findings": []
	}`)
	r, err := parseReport(raw)
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(r.Findings))
	}
}
