---
name: zizmor
description: Audit GitHub Actions workflows with zizmor and map hits into the findings shape.
license: MIT
compatibility: Requires `zizmor` (https://github.com/zizmorcore/zizmor) and `python3` on PATH.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
---

# zizmor

Run zizmor against `./src/.github/workflows` and map each issue into scrutineer's findings shape.

## Workspace

- `./src` — the cloned repository
- `./scripts/scan.py` — the wrapper
- `./report.json` — write the findings report here
- `./schema.json` — output shape

## Available scripts

- `scripts/scan.py` — invokes `zizmor --format json .github/workflows` and converts the output. If the repo has no workflows directory, it writes an empty result so the scan succeeds cleanly. zizmor's severity values are mapped to scrutineer's: `unknown`/`informational`/`low` → `Low`, `medium` → `Medium`, `high` → `High`, `critical` → `Critical`.

## What to do

```bash
python3 scripts/scan.py > ./report.json
```

The script handles missing workflows directories, a missing zizmor binary, and zizmor's non-zero "I found something" exit code gracefully — don't add retry or error handling on top.
