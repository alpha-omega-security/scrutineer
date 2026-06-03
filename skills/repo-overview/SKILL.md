---
name: repo-overview
description: Run `brief --json` to produce a structured overview of the repository. Used by other skills as orientation.
license: MIT
compatibility: Requires the `brief` CLI (https://github.com/ecosyste-ms/brief) on PATH.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: repo_overview
---

# repo-overview

Produce an overview of the repository cloned at `./src` by invoking the `brief` tool and writing its output verbatim as the report. `brief` already does the reading, summarising, and structured-output work; this skill is the thin harness around it.

## Workspace

- `./src` — the cloned repository
- `./context.json` — read `scrutineer.scan_subpath`; other fields are unused
- `./report.json` — write the final report here

## What to run

If `./context.json` has `scrutineer.scan_subpath` set, run `brief` against that sub-folder instead of the repo root:

```bash
brief --json ./src/$(jq -r '.scrutineer.scan_subpath // ""' ./context.json | sed 's:^/*::') > ./report.json
```

If `scan_subpath` points at a directory that does not exist under `./src`, write `{"error": "scan_subpath not found: <path>"}` and stop. For a root scan (no `scan_subpath`), the command reduces to:

```bash
brief --json ./src > ./report.json
```

That is the whole workflow. If `brief` exits non-zero (including when it is missing), read its stderr and write a short `{"error": "..."}` JSON document to `./report.json` so the caller can see what went wrong rather than getting an empty file. Do not post-process brief's output; the consumer expects its native schema. Do not try to install `brief`; it is pinned by the deployment.
