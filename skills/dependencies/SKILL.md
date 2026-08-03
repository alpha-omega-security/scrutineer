---
name: dependencies
description: Run git-pkgs list, sbom, licenses, vulns, outdated, and deprecated against the repository and emit one envelope with per-section status.
license: MIT
compatibility: Requires `git-pkgs` (https://github.com/git-pkgs/git-pkgs) and `python3` on PATH.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: dependencies
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

# dependencies

Run six git-pkgs analyses after one `git-pkgs init` and assemble the results into a versioned envelope. `analyses.inventory` is the manifest occurrence list from `git-pkgs list`; `analyses.sbom` is the CycloneDX document from `git-pkgs sbom`; `licenses`, `vulnerabilities`, `outdated`, and `deprecated` carry the per-dependency rows from the matching commands. Each section has its own `status` so a failed registry lookup does not discard a valid inventory. Scrutineer's worker resolves Maven requirements from local `pom.xml` files with `git-pkgs/pom`, fills `requirement_resolution`, and marks unresolved placeholders with `requirement_unresolved`.

## Workspace

- `./src` — the cloned repository
- `./scripts/index.sh` — the wrapper script
- `./report.json` — write the final report here
- `./schema.json` — output shape

## Available scripts

- `scripts/index.sh` — runs `git-pkgs init` inside `./src`, then `list`, `sbom`, `licenses`, `vulns`, `outdated`, and `deprecated` in turn, capturing stdout, stderr, and exit code per command, and writes the assembled envelope to stdout.

## What to do

Run the script and capture its stdout as the report:

```bash
bash scripts/index.sh > ./report.json
```

If the script exits non-zero, read its stderr, then write `{"schema_version": 1, "analyses": {}, "error": "..."}` to `./report.json` so the caller sees why nothing was collected.

The wrapper already emits the exact schema the parser expects, including per-section `status: "error"` for a failed command. Do not post-process, merge sections, or hand-author dependency rows. Do not inspect manifests yourself or infer dependencies from files that `git-pkgs` did not report. An empty `analyses.inventory.result` means git-pkgs found no manifests; write that report and stop.
