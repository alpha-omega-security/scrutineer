package worker

import "github.com/alpha-omega-security/harness"

// CostFromUsage computes the dollar cost of one result event's token usage
// against the given model's list price. The pricing table lives in
// github.com/alpha-omega-security/harness alongside each backend's
// DefaultModels(); the coverage tripwire that every DefaultModels() id is
// priced is upstream in that module's tests.
func CostFromUsage(model string, u Usage) float64 { return harness.CostFromUsage(model, u) }
