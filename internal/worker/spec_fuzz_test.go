package worker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"scrutineer/internal/db"
	"scrutineer/internal/db/dbtest"
	"scrutineer/internal/specfuzz"
)

// buildSpecFuzzReport runs the given adapter over the clause's inputs
// and returns a report.json body the skill would produce.
func buildSpecFuzzReport(t *testing.T, clauseID string, adapt func([]byte) specfuzz.AdapterVerdict) string {
	t.Helper()
	c, err := specfuzz.LoadClause(clauseID)
	if err != nil {
		t.Fatal(err)
	}
	verdicts := map[string]specfuzz.AdapterVerdict{}
	for _, in := range c.Corpus {
		b, _ := hex.DecodeString(in.Hex)
		verdicts[in.ID] = adapt(b)
	}
	for _, ctrl := range append(c.Controls.MustAccept, c.Controls.MustReject...) {
		b, _ := hex.DecodeString(ctrl.Hex)
		verdicts[ctrl.ID] = adapt(b)
	}
	rep := map[string]any{
		"clause_id":  clauseID,
		"entrypoint": "src/parser.py:42",
		"verdicts":   verdicts,
	}
	out, _ := json.Marshal(rep)
	return string(out)
}

// lenientAdapter mimics h11 0.15.0: any two bytes after chunk-data.
func lenientAdapter(buf []byte) specfuzz.AdapterVerdict {
	body, ok := parseChunkedH11(buf, false)
	if !ok {
		return specfuzz.AdapterVerdict{Accept: false, Error: "reject"}
	}
	return specfuzz.AdapterVerdict{Accept: true, BodyHex: hex.EncodeToString(body)}
}

// strictAdapterFn rejects everything the oracle rejects.
func strictAdapterFn(buf []byte) specfuzz.AdapterVerdict {
	body, ok := parseChunkedH11(buf, true)
	if !ok {
		return specfuzz.AdapterVerdict{Accept: false, Error: "reject"}
	}
	return specfuzz.AdapterVerdict{Accept: true, BodyHex: hex.EncodeToString(body)}
}

func TestParseSpecFuzzOutputDeviates(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/h11"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "spec-fuzz",
		Commit: "abc", Status: db.ScanRunning}
	gdb.Create(&scan)
	w := &Worker{DB: gdb}

	report := buildSpecFuzzReport(t, "rfc9112-7.1", lenientAdapter)
	var events []Event
	err := w.parseSpecFuzzOutput(context.Background(),
		&db.Skill{Name: "spec-fuzz", OutputKind: "spec_fuzz"},
		&scan, report, func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}

	var findings []db.Finding
	gdb.Where("scan_id = ?", scan.ID).Find(&findings)
	if len(findings) == 0 {
		t.Fatal("no findings persisted")
	}
	sawCVE := false
	for _, f := range findings {
		if strings.Contains(f.Title, "data_crlf:v4") {
			sawCVE = true
			if f.CWE != "CWE-444" {
				t.Errorf("CWE = %q, want CWE-444", f.CWE)
			}
			if f.Confidence != "high" {
				t.Errorf("Confidence = %q", f.Confidence)
			}
			if !strings.Contains(f.Validation, "accept-vs-error") {
				t.Errorf("Validation missing peer class: %q", f.Validation)
			}
			if !strings.Contains(f.Trace, "lean-rfcs") {
				t.Errorf("Trace missing lean-rfcs source: %q", f.Trace)
			}
		}
		if f.Fingerprint == "" {
			t.Errorf("finding %q has no fingerprint", f.Title)
		}
	}
	if !sawCVE {
		t.Errorf("no data_crlf:v4 finding among %d", len(findings))
	}
}

func TestParseSpecFuzzOutputConformant(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/strict"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "spec-fuzz",
		Commit: "abc", Status: db.ScanRunning}
	gdb.Create(&scan)
	w := &Worker{DB: gdb}

	report := buildSpecFuzzReport(t, "rfc9112-7.1", strictAdapterFn)
	err := w.parseSpecFuzzOutput(context.Background(),
		&db.Skill{Name: "spec-fuzz", OutputKind: "spec_fuzz"},
		&scan, report, func(Event) {})
	if err != nil {
		t.Fatal(err)
	}
	var findings []db.Finding
	gdb.Where("scan_id = ?", scan.ID).Find(&findings)
	if len(findings) != 0 {
		t.Errorf("strict adapter produced %d findings, want 0", len(findings))
	}
}

func TestParseSpecFuzzOutputControlFail(t *testing.T) {
	gdb := dbtest.Open(t)
	repo := db.Repository{URL: "https://example.com/broken"}
	gdb.Create(&repo)
	scan := db.Scan{RepositoryID: repo.ID, Kind: "skill", SkillName: "spec-fuzz",
		Commit: "abc", Status: db.ScanRunning}
	gdb.Create(&scan)
	w := &Worker{DB: gdb}

	// Adapter rejects everything → fails must_accept controls.
	report := buildSpecFuzzReport(t, "rfc9112-7.1", func([]byte) specfuzz.AdapterVerdict {
		return specfuzz.AdapterVerdict{Accept: false, Error: "nope"}
	})
	var events []Event
	err := w.parseSpecFuzzOutput(context.Background(),
		&db.Skill{Name: "spec-fuzz", OutputKind: "spec_fuzz"},
		&scan, report, func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	var findings []db.Finding
	gdb.Where("scan_id = ?", scan.ID).Find(&findings)
	if len(findings) != 0 {
		t.Errorf("control-failed adapter produced %d findings", len(findings))
	}
	found := false
	for _, e := range events {
		if strings.Contains(e.Text, "must_accept") {
			found = true
		}
	}
	if !found {
		t.Error("no event about failed must_accept controls")
	}
}

func TestParseSpecFuzzOutputMissingClause(t *testing.T) {
	w := &Worker{}
	err := w.parseSpecFuzzOutput(context.Background(),
		&db.Skill{OutputKind: "spec_fuzz"},
		&db.Scan{}, `{"clause_id":""}`, func(Event) {})
	if err == nil {
		t.Fatal("expected error for missing clause_id")
	}
}

func TestParseSpecFuzzOutputSkillError(t *testing.T) {
	w := &Worker{}
	var events []Event
	err := w.parseSpecFuzzOutput(context.Background(),
		&db.Skill{OutputKind: "spec_fuzz"},
		&db.Scan{}, `{"error":"could not build adapter"}`,
		func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatalf("skill-reported error should not fail the parse: %v", err)
	}
	if len(events) == 0 || !strings.Contains(events[0].Text, "could not build adapter") {
		t.Errorf("expected skill error event, got %v", events)
	}
}
