---
name: dependencies
description: Index dependencies reported by git-pkgs for the repository's manifest and lockfile files (package.json, Gemfile, go.mod, requirements.txt, etc.) and record each one with its manifest path, ecosystem, and requirement string. Use to populate the Dependencies tab.
license: MIT
compatibility: Requires `git-pkgs` (https://github.com/ecosyste-ms/git-pkgs) and `python3` on PATH.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: dependencies
---

# dependencies

Wrap `git-pkgs list --format json` so scrutineer can read the result as a dependencies report.

## Workspace

- `./src` — the cloned repository
- `./scripts/index.sh` — the wrapper script
- `./report.json` — write the final report here
- `./schema.json` — output shape

## Available scripts

- `scripts/index.sh` — runs `git-pkgs init` then `git-pkgs list --format json` inside `./src`, normalises empty or `null` output to an empty array, and writes `{"dependencies": [...]}`.

## What to do

Run the script and capture its stdout as the report:

```bash
bash scripts/index.sh > ./report.json
```

If the script exits non-zero, read its stderr, then write a short `{"dependencies": [], "error": "..."}` document to `./report.json` so the caller sees why no dependencies were indexed.

The wrapper already emits the exact schema the parser expects — no post-processing needed.

Do not inspect manifests yourself, infer dependencies from files that `git-pkgs` did not report, or hand-author dependency rows. If the wrapper returns `{"dependencies":[]}`, write that exact report and stop. Missing coverage in `git-pkgs` should produce an empty dependency report, not model-authored package data.
