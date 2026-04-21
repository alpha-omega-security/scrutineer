---
name: repo-overview
description: Produce a structured plain-language overview of what a repository does, who maintains it, its activity level, and the shape of its codebase. Use when you want a quick orientation before deeper analysis.
license: MIT
compatibility: Requires the `brief` CLI (https://github.com/ecosyste-ms/brief) on PATH.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# repo-overview

Produce an overview of the repository cloned at `./src` by invoking the `brief` tool and writing its output verbatim as the report. `brief` already does the reading, summarising, and structured-output work; this skill is the thin harness around it.

## Workspace

- `./src` — the cloned repository
- `./context.json` — repository url and metadata (not needed for this skill)
- `./report.json` — write the final report here

## What to run

If `./context.json` has `scrutineer.scan_subpath` set, run `brief` against that sub-folder instead of the repo root:

```bash
brief --json ./src/$(jq -r '.scrutineer.scan_subpath // ""' ./context.json | sed 's:^/*::') > ./report.json
```

For a root scan (no `scan_subpath`), that reduces to the original:

```bash
brief --json ./src > ./report.json
```

That is the whole workflow. If `brief` exits non-zero, read its stderr and write a short `{"error": "..."}` JSON document to `./report.json` so the caller can see what went wrong rather than getting an empty file.

## Notes

- `brief` is pinned by the deployment (container image or host install). Do not try to install it here.
- Do not post-process the output. The consumer of this report expects brief's native schema.
- If the tool is missing, say so clearly in the error JSON rather than inventing content.
