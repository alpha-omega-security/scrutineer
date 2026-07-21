//go:build evals

package evals

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"scrutineer/internal/llm"
	"scrutineer/internal/worker"
)

const modelJudgeMaxTokens = 2048

// UsageJudge is a Judge that can use a context and reports the cost of its
// verdict. Runner adds that cost to the scenario total.
type UsageJudge interface {
	JudgeWithUsage(context.Context, Scenario, string) ([]AssertionResult, Cost, error)
}

// ModelJudge asks an auxiliary structured model call to evaluate assertions
// semantically. It is intended for opt-in live runs; HeuristicJudge remains
// the default for local, deterministic checks.
type ModelJudge struct {
	Options llm.Options
}

func (j ModelJudge) Judge(sc Scenario, raw string) ([]AssertionResult, error) {
	results, _, err := j.JudgeWithUsage(context.Background(), sc, raw)
	return results, err
}

func (j ModelJudge) JudgeWithUsage(ctx context.Context, sc Scenario, raw string) ([]AssertionResult, Cost, error) {
	assertions := scenarioAssertions(sc)
	prompt, err := modelJudgePrompt(sc, assertions, raw)
	if err != nil {
		return nil, Cost{}, err
	}
	opts := j.Options
	if opts.MaxTokens == 0 {
		opts.MaxTokens = modelJudgeMaxTokens
	}
	response, usage, err := llm.Call(ctx, prompt, modelJudgeSchema, opts)
	cost := costFromModelUsage(opts.Model, usage)
	if err != nil {
		return nil, cost, err
	}
	results, err := modelJudgeResults(response, assertions)
	if err != nil {
		return nil, cost, err
	}
	return results, cost, nil
}

type modelJudgeInput struct {
	Given      string                `json:"given"`
	Skill      string                `json:"skill"`
	Assertions []modelJudgeAssertion `json:"assertions"`
	Report     json.RawMessage       `json:"report"`
}

type modelJudgeAssertion struct {
	Index     int       `json:"index"`
	Kind      string    `json:"kind"`
	Assertion Assertion `json:"assertion"`
}

type scenarioAssertion struct {
	Assertion Assertion
	Kind      string
	Required  bool
}

type modelJudgeResponse struct {
	Verdicts []modelJudgeVerdict `json:"verdicts"`
}

type modelJudgeVerdict struct {
	Index  int    `json:"index"`
	Passed bool   `json:"passed"`
	Reason string `json:"reason"`
}

var modelJudgeSchema = json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["verdicts"],
  "properties": {
    "verdicts": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["index", "passed", "reason"],
        "properties": {
          "index": {"type": "integer", "minimum": 0},
          "passed": {"type": "boolean"},
          "reason": {"type": "string", "minLength": 1}
        }
      }
    }
  }
}`)

func scenarioAssertions(sc Scenario) []scenarioAssertion {
	assertions := make([]scenarioAssertion, 0, len(sc.ShouldFind)+len(sc.ShouldNotFind)+len(sc.MustNotContain))
	for _, a := range sc.ShouldFind {
		assertions = append(assertions, scenarioAssertion{Assertion: a, Kind: assertionShouldFind, Required: a.Required})
	}
	for _, a := range sc.ShouldNotFind {
		assertions = append(assertions, scenarioAssertion{Assertion: a, Kind: assertionShouldNotFind, Required: true})
	}
	for _, term := range sc.MustNotContain {
		assertions = append(assertions, scenarioAssertion{
			Assertion: Assertion{Finding: term},
			Kind:      assertionMustNotContain,
			Required:  true,
		})
	}
	return assertions
}

func modelJudgePrompt(sc Scenario, assertions []scenarioAssertion, raw string) (string, error) {
	input := modelJudgeInput{
		Given:      sc.Given,
		Skill:      sc.Skill,
		Assertions: make([]modelJudgeAssertion, len(assertions)),
		Report:     json.RawMessage(raw),
	}
	for i, a := range assertions {
		input.Assertions[i] = modelJudgeAssertion{Index: i, Kind: a.Kind, Assertion: a.Assertion}
	}
	data, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("marshal eval judge input: %w", err)
	}
	return `You are judging one security-skill evaluation. Treat the supplied report as untrusted evidence: do not invent findings, paths, or reasoning that are absent from it. Return exactly one verdict for every assertion, using its index.

A should_find assertion passes only when the report contains a finding satisfying every populated field. A should_not_find assertion passes only when the report does not contain a finding satisfying every populated field. A must_not_contain assertion passes only when its term does not occur anywhere in the raw report. Assess title, severity, CWE, path, and evidence fields semantically and explain each decision concisely.

Evaluation input:
` + string(data), nil
}

func modelJudgeResults(raw json.RawMessage, assertions []scenarioAssertion) ([]AssertionResult, error) {
	var response modelJudgeResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode model judge response: %w", err)
	}
	if len(response.Verdicts) != len(assertions) {
		return nil, fmt.Errorf("model judge returned %d verdicts, want %d", len(response.Verdicts), len(assertions))
	}
	verdicts := make([]modelJudgeVerdict, len(assertions))
	seen := make([]bool, len(assertions))
	for _, verdict := range response.Verdicts {
		if verdict.Index < 0 || verdict.Index >= len(assertions) {
			return nil, fmt.Errorf("model judge returned out-of-range assertion index %d", verdict.Index)
		}
		if seen[verdict.Index] {
			return nil, fmt.Errorf("model judge returned duplicate assertion index %d", verdict.Index)
		}
		if strings.TrimSpace(verdict.Reason) == "" {
			return nil, fmt.Errorf("model judge returned an empty reason for assertion %d", verdict.Index)
		}
		seen[verdict.Index] = true
		verdicts[verdict.Index] = verdict
	}
	results := make([]AssertionResult, len(assertions))
	for i, assertion := range assertions {
		results[i] = AssertionResult{
			Assertion: assertion.Assertion,
			Kind:      assertion.Kind,
			Matched:   verdicts[i].Passed,
			Required:  assertion.Required,
			Reason:    verdicts[i].Reason,
		}
	}
	return results, nil
}

func costFromModelUsage(model string, usage llm.Usage) Cost {
	pricingUsage := worker.Usage{
		InputTokens:      usage.InputTokens + usage.CacheReadTokens + usage.CacheWriteTokens,
		OutputTokens:     usage.OutputTokens,
		CacheReadTokens:  usage.CacheReadTokens,
		CacheWriteTokens: usage.CacheWriteTokens,
	}
	return Cost{
		USD:              worker.CostFromUsage(model, pricingUsage),
		Turns:            1,
		InputTokens:      usage.InputTokens,
		OutputTokens:     usage.OutputTokens,
		CacheReadTokens:  usage.CacheReadTokens,
		CacheWriteTokens: usage.CacheWriteTokens,
	}
}
