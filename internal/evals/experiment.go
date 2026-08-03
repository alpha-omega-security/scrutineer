//go:build evals

package evals

import "sort"

// ExperimentSummary aggregates comparable scenario results for one prompt
// variant. Scenarios without experiment metadata are intentionally omitted.
type ExperimentSummary struct {
	Experiment     string
	Variant        string
	ScenarioTotal  int
	Passed         int
	Errors         int
	AssertionTotal int
	FailedRequired int
	OptionalMisses int
	Unexpected     int
	Cost           Cost
}

// SummarizeExperiments groups results by experiment and variant so a live eval
// run reports quality and cost for the production baseline and candidate using
// the same fixtures and model.
func SummarizeExperiments(results []Result) []ExperimentSummary {
	type key struct {
		experiment string
		variant    string
	}
	summaries := make(map[key]ExperimentSummary)
	for _, result := range results {
		if result.Scenario.Experiment == "" {
			continue
		}
		k := key{experiment: result.Scenario.Experiment, variant: result.Scenario.Variant}
		summary := summaries[k]
		summary.Experiment = k.experiment
		summary.Variant = k.variant
		summary.ScenarioTotal++
		summary.AssertionTotal += result.AssertionTotal
		summary.FailedRequired += result.FailedRequired
		summary.OptionalMisses += result.OptionalMisses
		summary.Unexpected += result.Unexpected
		addCost(&summary.Cost, result.Cost)
		if result.Error != "" {
			summary.Errors++
		} else if result.FailedRequired == 0 && result.Unexpected == 0 {
			summary.Passed++
		}
		summaries[k] = summary
	}

	out := make([]ExperimentSummary, 0, len(summaries))
	for _, summary := range summaries {
		out = append(out, summary)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Experiment != out[j].Experiment {
			return out[i].Experiment < out[j].Experiment
		}
		return out[i].Variant < out[j].Variant
	})
	return out
}
