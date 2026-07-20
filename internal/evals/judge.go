//go:build evals

package evals

import (
	"encoding/json"
	"fmt"
	"strings"

	"scrutineer/internal/findingnorm"
)

const (
	assertionShouldFind     = "should_find"
	assertionShouldNotFind  = "should_not_find"
	assertionMustNotContain = "must_not_contain"
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
	results := make([]AssertionResult, 0, len(sc.ShouldFind)+len(sc.ShouldNotFind)+len(sc.MustNotContain))
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
	for _, term := range sc.MustNotContain {
		results = append(results, AssertionResult{
			Assertion: Assertion{Finding: term},
			Kind:      assertionMustNotContain,
			Matched:   !containsFold(raw, term),
			Required:  true,
			Reason:    mustNotContainReason(raw, term),
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
	if a.CWE != "" && findingnorm.CWE(f.CWE) != findingnorm.CWE(a.CWE) {
		return false
	}
	if a.Path != "" && !findingHasPath(f, a.Path) {
		return false
	}
	if !findingHasEvidence(f, a.Evidence) {
		return false
	}
	return true
}

func findingHasEvidence(f Finding, terms []string) bool {
	if len(terms) == 0 {
		return true
	}
	evidence := strings.Join([]string{
		f.Title, f.Location, strings.Join(f.Locations, "\n"),
		f.Trace, f.Boundary, f.Validation, f.Rating, f.Description,
		f.Affected, f.PriorArt, f.Reach,
	}, "\n")
	for _, term := range terms {
		if !containsFold(evidence, term) {
			return false
		}
	}
	return true
}

func findingHasPath(f Finding, want string) bool {
	want = findingnorm.RepoPath(want)
	for _, loc := range append([]string{f.Location}, f.Locations...) {
		got := findingnorm.LocationFile(loc)
		if got == want || strings.HasPrefix(got, want+"/") {
			return true
		}
	}
	return false
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

func mustNotContainReason(report, term string) string {
	if !containsFold(report, term) {
		return fmt.Sprintf("report does not contain %q", term)
	}
	return fmt.Sprintf("report unexpectedly contains %q", term)
}
