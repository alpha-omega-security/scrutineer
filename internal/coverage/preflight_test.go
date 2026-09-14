package coverage

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreflightCapsReconciledCoverage(t *testing.T) {
	for _, status := range []string{PreflightReady, PreflightBlocked, PreflightDegraded} {
		for _, scope := range [][]string{nil, {"a.go"}} {
			rec := Record{Preflight: &Preflight{Status: status, Missing: []string{"command:cargo"}, Degraded: status == PreflightDegraded}}
			rec.ApplyClaim(Claim{Receipts: []Receipt{{Path: "a.go", Disposition: DispositionReviewedClean}}}, scope)
			if status != PreflightReady {
				if rec.Completeness != CompletenessPartial || !strings.Contains(rec.Reason, "command:cargo") {
					t.Fatalf("preflight lost after reconciliation: %+v", rec)
				}
			} else if len(scope) > 0 && rec.Completeness != CompletenessComplete {
				t.Fatalf("ready scan capped: %+v", rec)
			}
			raw, err := Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			parsed, ok := Parse(raw)
			if !ok || parsed.Preflight == nil || parsed.Preflight.Status != status {
				t.Fatalf("preflight round trip failed: %s", raw)
			}
		}
	}
	if _, err := ParseClaim(json.RawMessage(`{"receipts":[],"preflight":{"status":"ready"}}`)); err == nil {
		t.Fatal("skill could overwrite preflight")
	}
}
