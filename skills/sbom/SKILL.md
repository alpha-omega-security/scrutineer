---
name: sbom
description: Generate a CycloneDX SBOM for the repository via `git-pkgs sbom`. Stored verbatim on the scan.
license: MIT
compatibility: Requires the `git-pkgs` CLI on PATH.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
  scrutineer.paths:
    - "**"
  scrutineer.ignore_paths:
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/generated/**"
    - "**/__generated__/**"
    - "**/*.min.js"
    - "**/*.min.css"
---

# sbom

## Workspace

- `./src` — the cloned repository
- `./scripts/generate.sh` — the wrapper script
- `./report.json` — write the SBOM here

## Available scripts

- `scripts/generate.sh` — runs `git-pkgs sbom --format json` inside `./src` and emits the CycloneDX JSON document to stdout.

## What to do

```bash
bash scripts/generate.sh > ./report.json
```

If the script exits non-zero, write `{"error": "<stderr message>"}` to `./report.json` so the failure is visible on the scan page.

The output is consumed as freeform (stored verbatim; no post-processing) so the CycloneDX document is preserved exactly as git-pkgs produced it.
