//go:build evals

package evals

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

const (
	assertionShouldFind    = "should_find"
	assertionShouldNotFind = "should_not_find"
)

// Judge scores a skill report against one scenario. Model-backed judges can
// implement this interface; the default judge is deterministic and local.
type Judge interface {
	Judge(sc Scenario, report string) ([]AssertionResult, error)
}

type HeuristicJudge struct{}

func (HeuristicJudge) Judge(sc Scenario, raw string) ([]AssertionResult, error) {
	findings, err := parseFindings(raw)
	if err != nil {
		return nil, err
	}
	results := make([]AssertionResult, 0, len(sc.ShouldFind)+len(sc.ShouldNotFind))
	for _, a := range sc.ShouldFind {
		match := matchingFinding(a, findings)
		results = append(results, AssertionResult{
			Assertion: a,
			Kind:      assertionShouldFind,
			Matched:   match != nil,
			Required:  a.Required,
			Reason:    matchReason(a, match),
		})
	}
	for _, a := range sc.ShouldNotFind {
		match := matchingFinding(a, findings)
		results = append(results, AssertionResult{
			Assertion: a,
			Kind:      assertionShouldNotFind,
			Matched:   match == nil,
			Required:  true,
			Reason:    notFindReason(match),
		})
	}
	return results, nil
}

func parseFindings(raw string) ([]Finding, error) {
	var r report
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return nil, fmt.Errorf("parse report.json: %w", err)
	}
	return r.Findings, nil
}

func matchingFinding(a Assertion, findings []Finding) *Finding {
	for i := range findings {
		if assertionMatchesFinding(a, findings[i]) {
			return &findings[i]
		}
	}
	return nil
}

func assertionMatchesFinding(a Assertion, f Finding) bool {
	if a.Finding != "" && !containsFold(f.Title, a.Finding) {
		return false
	}
	if a.Severity != "" && !strings.EqualFold(strings.TrimSpace(f.Severity), strings.TrimSpace(a.Severity)) {
		return false
	}
	if a.CWE != "" && !strings.EqualFold(strings.TrimSpace(f.CWE), strings.TrimSpace(a.CWE)) {
		return false
	}
	if a.Path != "" && !findingHasPath(f, a.Path) {
		return false
	}
	return true
}

func findingHasPath(f Finding, want string) bool {
	want = cleanReportPath(want)
	for _, loc := range append([]string{f.Location}, f.Locations...) {
		if strings.HasPrefix(cleanReportPath(loc), want) {
			return true
		}
	}
	return false
}

func cleanReportPath(s string) string {
	s = strings.TrimSpace(s)
	if before, _, ok := strings.Cut(s, ":"); ok {
		s = before
	}
	return filepath.ToSlash(filepath.Clean(s))
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(strings.TrimSpace(needle)))
}

func matchReason(a Assertion, f *Finding) string {
	if f == nil {
		return "no finding matched " + a.label()
	}
	return fmt.Sprintf("matched %q at %s", f.Title, f.Location)
}

func notFindReason(f *Finding) string {
	if f == nil {
		return "no matching finding emitted"
	}
	return fmt.Sprintf("unexpected finding %q at %s", f.Title, f.Location)
}
