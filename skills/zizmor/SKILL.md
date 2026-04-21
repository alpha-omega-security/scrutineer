---
name: zizmor
description: Audit the repository's GitHub Actions workflows for common security issues (credential mishandling, untrusted inputs, template injection, overly permissive tokens) and convert findings to scrutineer's shape. Use on any repo with a .github/workflows directory.
license: MIT
compatibility: Requires `zizmor` (https://github.com/woodruffw/zizmor) and `python3` on PATH.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# zizmor

Run zizmor against `./src/.github/workflows` and map each issue into scrutineer's findings shape.

## Workspace

- `./src` — the cloned repository
- `./scripts/scan.py` — the wrapper
- `./report.json` — write the findings report here
- `./schema.json` — output shape

## Available scripts

- `scripts/scan.py` — invokes `zizmor --format json .github/workflows` and converts the output. If the repo has no workflows directory, it writes an empty result so the scan succeeds cleanly. zizmor's severity values (`unknown`, `low`, `medium`, `high`, `critical`) are mapped to scrutineer's `Low`/`Medium`/`High`/`Critical`.

## What to do

```bash
python3 scripts/scan.py > ./report.json
```

The script handles missing workflows directories, a missing zizmor binary, and zizmor's non-zero "I found something" exit code gracefully — don't add retry or error handling on top. If stderr is noisy that's fine, scrutineer only reads the JSON on stdout.
