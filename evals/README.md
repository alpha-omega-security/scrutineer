# Skill evals

Fixture-driven skill evals live here. They are off by default in normal CI;
run the harness explicitly with:

```sh
go test -tags evals ./internal/evals/...
```

That command validates scenario loading and the deterministic judge. To run the
actual model-backed skills against every fixture, opt in:

```sh
SCRUTINEER_RUN_EVALS=1 SCRUTINEER_EVAL_MODEL=claude-sonnet-5 go test -tags evals ./internal/evals/... -run TestRunFixtures -v
```

Each scenario YAML names:

- `given`: short description of the bug or non-bug.
- `fixture`: directory under `evals/fixtures/`.
- `skill`: bundled skill to execute.
- `should_find`: required findings the report must include.
- `should_not_find`: false positives the report must not include.
- `must_not_contain`: repo-level terms that must not appear anywhere in the
  report, such as an out-of-scope framework or nonexistent file.

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

The default judge matches findings by title substring plus optional severity,
CWE, path, and evidence. These assertions define a minimum bar: additional
findings do not fail an eval unless they match `should_not_find` or the report
contains a `must_not_contain` term. Model-backed judging can be plugged in by
implementing `evals.Judge`.
