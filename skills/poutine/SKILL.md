---
name: poutine
description: Audit CI/CD pipelines with poutine and map hits into the findings shape.
license: MIT
compatibility: Requires `poutine` (https://github.com/boostsecurityio/poutine) and `python3` on PATH.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.model: mid
---

# poutine

Run poutine against `./src` and map each finding into scrutineer's findings shape.

poutine is a supply-chain scanner for build pipelines. It overlaps the zizmor skill on
GitHub Actions but is aimed at high-risk pipeline findings rather than lint — the rules
that fire at `error` are things like arbitrary code execution from an untrusted checkout —
and it also reads GitLab CI, Azure Pipelines and Tekton, which zizmor does not.

## Workspace

- `./src` — the cloned repository
- `./scripts/scan.py` — the wrapper
- `./report.json` — write the findings report here
- `./schema.json` — output shape

## Available scripts

- `scripts/scan.py` — invokes `poutine analyze_local . --format json` and converts the output. If the repo has no CI pipeline definitions it writes an empty result so the scan succeeds cleanly. Findings are grouped by rule, so one rule firing across several jobs becomes one finding carrying every `file:line` in `locations`. poutine's levels are mapped to scrutineer's: `note` → `Low`, `warning` → `Medium`, `error` → `High`.

## What to do

```bash
python3 scripts/scan.py > ./report.json
```

The script handles a repo with no pipelines, a missing poutine binary and malformed output
gracefully — don't add retry or error handling on top.
