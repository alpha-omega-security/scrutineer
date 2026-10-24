package worker

import (
	"encoding/json"
	"fmt"
	"strings"

	"scrutineer/internal/coverage"
	"scrutineer/internal/db"
)

func extractSkillCoverageClaim(report string) (coverage.Claim, bool, error) {
	if !strings.HasPrefix(strings.TrimSpace(report), "{") {
		return coverage.Claim{}, false, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(report), &envelope); err != nil {
		return coverage.Claim{}, false, nil
	}
	raw, present := envelope[coverage.ReportMetadataKey]
	if !present {
		return coverage.Claim{}, false, nil
	}
	claim, err := coverage.ParseClaim(raw)
	if err != nil {
		return coverage.Claim{}, false, err
	}
	return claim, true, nil
}

func applySkillCoverageClaim(scan *db.Scan, claim coverage.Claim) error {
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok && strings.TrimSpace(scan.Coverage) != "" {
		return fmt.Errorf("stored coverage record %q did not decode", scan.Coverage)
	}
	var scope []string
	if rec.ActualMode == db.ScanRescanModeDiff {
		scope = rec.IncludedPaths
	}
	rec.ApplyClaim(claim, scope)
	setCoverage(scan, rec)
	return nil
}

// applyHistoryCoverage lifts the history report's partial flag and gaps into
// the scan's coverage record, so a pass over truncated history reads as partial.
func applyHistoryCoverage(scan *db.Scan, report string) error {
	var out struct {
		Partial *bool    `json:"partial"`
		Gaps    []string `json:"gaps"`
	}
	if err := json.Unmarshal([]byte(report), &out); err != nil || out.Partial == nil || !*out.Partial {
		return nil
	}
	rec, ok := coverage.Parse(scan.Coverage)
	if !ok && strings.TrimSpace(scan.Coverage) != "" {
		return fmt.Errorf("stored coverage record %q did not decode", scan.Coverage)
	}
	var gaps []string
	for _, g := range out.Gaps {
		if g = strings.TrimSpace(g); g != "" {
			gaps = append(gaps, g)
		}
	}
	rec.Completeness = coverage.CompletenessPartial
	rec.Reason = "history report marked partial"
	if len(gaps) > 0 {
		rec.Reason = strings.Join(gaps, "; ")
	}
	setCoverage(scan, rec)
	return nil
}
