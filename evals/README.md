# Skill evals

Fixture-driven skill evals live here. CI runs the deterministic loader, schema,
judge, staging, and experiment checks under the race detector. Run the same
deterministic checks locally with:

```sh
go test -tags evals ./internal/evals/...
```

The actual model-backed skills remain off by default. To run them against every
fixture, opt in explicitly:

```sh
SCRUTINEER_RUN_EVALS=1 SCRUTINEER_EVAL_MODEL=claude-sonnet-5 go test -timeout 2h -tags evals ./internal/evals/... -run TestRunFixtures -v
```

Each scenario YAML names:

- `given`: short description of the bug or non-bug.
- `fixture`: directory under `evals/fixtures/`.
- `skill`: bundled skill to execute.
- `schema_skill`: optional bundled skill whose JSON schema should validate the
  report. Use this for eval-only prompt variants that must keep the production
  output contract.
- `experiment` and `variant`: optional paired identifiers used to compare
  multiple prompt variants over the same fixture set. Set both or neither.
  Every variant must use byte-for-byte identical `given:` text and semantically
  identical assertions for each fixture; the order of `should_find` and
  `should_not_find` entries does not matter.
- `should_find`: required findings the report must include.
- `should_not_find`: false positives the report must not include.
- `must_not_contain`: repo-level terms that must not appear anywhere in the
  report, such as an out-of-scope framework or nonexistent file.

By default `skill` resolves from the bundled `skills/` directory. A scenario can
also point at an eval-only variant in `evals/skills/<name>/SKILL.md`; this keeps
prompt experiments out of the production skill set while still letting the same
fixture harness compare them. Pair those variants with `schema_skill` when the
variant should emit the same report shape as a production skill.

Live runs print an aggregate line for every `experiment`/`variant` pair after
the per-scenario results. The aggregate includes scenario passes, runner
errors, assertion misses, unexpected findings, turns, tokens, and cost. Use the
same model and the same paired fixtures in one invocation so the production
baseline and candidate are directly comparable. For example, the
`security-deep-dive-prompt` experiment compares `production` with
`reference-driven`; the latter keeps intent and phase order in `SKILL.md` and
loads sink taxonomy and report policy from `references/` when needed.

Committed experiment decisions live under [`results/`](results/). Each report
records the tested revision, model, environment, aggregate metrics, and whether
the candidate was promoted.

Each `should_find` or `should_not_find` assertion may include
`evidence_contains`:

```yaml
should_find:
  - finding: SQL injection
    evidence_contains:
      - buildQuery
      - request.args
```

Every evidence term must appear in the matched finding's title, location,
locations, or narrative fields: `trace`, `boundary`, `validation`, `rating`,
`description`, `affected`, `prior_art`, or `reach`. CWE values are match
criteria, not evidence.

Those fields are folded into one string and each term is matched against it as
a case-insensitive substring, so keep a term specific enough that only the
thing it tests can satisfy it. A bare number is a poor term: `rating` carries a
CVSS score while every location carries a line number, so `9` passes on either
without the finding having recorded anything. Write `9 hits` instead.

An assertion may also key on how the run classified the sink behind a finding:

```yaml
should_find:
  - path: client.py
    sink_class: API misuse
```

`sink_class` resolves each id in the finding's `sinks` against `inventory[].id`
then compares the class the report assigned there, so it asserts what the run
decided the sink is rather than what the write-up happened to call it. An id
the inventory does not hold carries no class, so it never satisfies the
assertion.

The default judge matches findings by title substring plus optional severity,
CWE, path, sink class and evidence. These assertions define a minimum bar:
additional findings do not fail an eval unless they match `should_not_find` or
the report contains a `must_not_contain` term.

For a semantic, model-backed verdict during a live run, opt in explicitly. The
judge uses the Anthropic Messages API and its cost is included in each
scenario's reported cost:

```sh
SCRUTINEER_RUN_EVALS=1 \
  SCRUTINEER_EVAL_MODEL=claude-sonnet-5 \
  SCRUTINEER_EVAL_JUDGE=model \
  SCRUTINEER_EVAL_JUDGE_MODEL=claude-haiku-4-5 \
  ANTHROPIC_API_KEY=sk-ant-... \
  go test -timeout 2h -tags evals ./internal/evals/... -run TestRunFixtures -v
```

`SCRUTINEER_EVAL_JUDGE` is unset by default, so ordinary local and CI checks
continue to use the deterministic judge without an API call.
