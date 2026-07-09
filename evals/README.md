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

The default judge matches findings by title substring plus optional severity,
CWE, and path. Model-backed judging can be plugged in by implementing
`evals.Judge`.
