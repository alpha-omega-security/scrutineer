---
name: semgrep
description: Run semgrep static analysis with the security-audit and secrets rulesets, then map each hit into scrutineer's findings shape so it surfaces alongside model-driven audits. Use as a fast deterministic pass before or alongside deeper skills.
license: MIT
compatibility: Requires `semgrep` (https://semgrep.dev) and `python3` on PATH.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# semgrep

Run semgrep against `./src` using the `p/security-audit` and `p/secrets` rulesets, then convert each hit into the findings-report shape scrutineer's parser understands.

## Workspace

- `./src` — the cloned repository
- `./scripts/scan.py` — the wrapper
- `./report.json` — write the findings report here
- `./schema.json` — output shape

## Available scripts

- `scripts/scan.py` — runs semgrep, maps results into findings with the fields we actually populate (`id`, `title`, `severity`, `cwe`, `location`, `trace`, `rating`). Severity maps: `ERROR` → High, `WARNING` → Medium, `INFO`/`INVENTORY`/`EXPERIMENT` → Low.

## What to do

```bash
python3 scripts/scan.py > ./report.json
```

The script self-reports tool-missing errors into the JSON envelope so failures are visible on the scan page rather than silent. Don't post-process its output.
