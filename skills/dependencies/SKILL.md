---
name: dependencies
description: Index every dependency declared in the repository's manifest and lockfile files (package.json, Gemfile, go.mod, requirements.txt, etc.) and record each one with its manifest path, ecosystem, and requirement string. Use to populate the Dependencies tab.
license: MIT
compatibility: Requires the `git-pkgs` CLI (https://github.com/ecosyste-ms/git-pkgs) on PATH.
metadata:
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

- `scripts/index.sh` — runs `git-pkgs init` then `git-pkgs list --format json` inside `./src` and wraps the array in `{"dependencies": [...]}`.

## What to do

Run the script and capture its stdout as the report:

```bash
bash scripts/index.sh > ./report.json
```

If the script exits non-zero, read its stderr, then write a short `{"dependencies": [], "error": "..."}` document to `./report.json` so the caller sees why no dependencies were indexed.

The wrapper already emits the exact schema the parser expects — no post-processing needed.
