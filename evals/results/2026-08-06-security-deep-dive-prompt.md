# Security deep-dive prompt A/B: 2026-08-06

## Decision

Do not promote the `reference-driven` prompt variant to production based on
this run. It reduced model usage and cost, but it also regressed the required
finding assertions: the production prompt passed one of three paired scenarios,
while the candidate passed none.

The production `skills/security-deep-dive/SKILL.md` remains unchanged. A future
candidate should recover the authentication-omission, mass-assignment, and SQL
injection assertions before another promotion decision.

## Setup

- Scrutineer revision: `233ae7cb9b5c65e0f5e6c7eb41f64b3fb107fd5c`
- Model: `claude-sonnet-5`
- Claude Code: `2.1.121`
- Go: `go1.26.5 darwin/arm64`
- Judge: deterministic (default)
- Experiment: `security-deep-dive-prompt`
- Variants: `production`, `reference-driven`

The documented command reached Go's default 10-minute test timeout while its
first model-backed scenario was still running. The timed-out Claude process
group was terminated, and the experiment was restarted from fresh temporary
workspaces with only the Go test deadline extended:

```sh
SCRUTINEER_RUN_EVALS=1 \
SCRUTINEER_EVAL_MODEL=claude-sonnet-5 \
go test -timeout 2h -tags evals ./internal/evals/... -run TestRunFixtures -v
```

## Paired results

| Variant | Scenario | Assertions | Required misses | Unexpected | Cost | Turns |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| production | auth omission | 2 | 1 | 0 | $0.5648 | 19 |
| production | mass assignment | 2 | 0 | 0 | $0.8835 | 20 |
| production | SQL injection | 3 | 1 | 0 | $0.9069 | 25 |
| reference-driven | auth omission | 2 | 1 | 0 | $0.4157 | 19 |
| reference-driven | mass assignment | 2 | 1 | 0 | $0.6548 | 26 |
| reference-driven | SQL injection | 3 | 1 | 0 | $0.3774 | 16 |

## Aggregate

| Variant | Passed | Errors | Assertions | Required misses | Unexpected | Cost | Turns | Input tokens | Output tokens | Cache read | Cache write |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| production | 1/3 | 0 | 7 | 2 | 0 | $2.3552 | 64 | 118 | 65,891 | 2,670,877 | 150,293 |
| reference-driven | 0/3 | 0 | 7 | 3 | 0 | $1.4480 | 61 | 116 | 37,752 | 1,879,771 | 84,237 |

Compared with production, the reference-driven candidate used 3 fewer turns,
28,139 fewer output tokens, and cost $0.9072 less (38.5%). Those efficiency
gains do not offset the quality regression: it added a required miss on the
mass-assignment fixture and produced no passing paired scenario.

## Non-experiment fixtures

The same invocation also ran the standalone Semgrep and Zizmor scenarios, which
are excluded from `SummarizeExperiments` and therefore do not affect the A/B
comparison. Semgrep hit its 30-turn cap before producing a report. Zizmor ran
for 12 turns at a reported cost of $0.1639 and missed one required assertion.
These failures caused the overall `go test` command to exit non-zero, but all
six paired deep-dive scenarios completed without runner errors and produced the
aggregate above.

## Limitations

This is one live run of a stochastic model over three fixtures. It is enough to
reject promotion of this candidate, but not to estimate stable effect sizes.
Additional fixtures and repeated runs would be needed before concluding that a
reference-driven prompt cannot outperform production after refinement.
