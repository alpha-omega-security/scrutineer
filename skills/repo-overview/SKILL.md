---
name: repo-overview
description: Run `brief --json` to produce a structured overview of the repository. Used by other skills as orientation.
license: MIT
compatibility: Requires the `brief` CLI (https://github.com/git-pkgs/brief) on PATH.
metadata:
  scrutineer.model: mid
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: repo_overview
---

# repo-overview

Produce an overview of the repository cloned at `./src` by invoking the `brief` tool and writing its output verbatim as the report. `brief` already does the reading, summarising, and structured-output work; this skill is the thin harness around it.

## Workspace

- `./src` — the cloned repository
- `./report.json` — write the final report here

## What to run

Run `brief` against the whole repository and write its output verbatim:

```bash
brief --json ./src > ./report.json
```

This skill always describes the whole repository, even on a scan scoped to a monorepo sub-package. It deliberately ignores `scrutineer.scan_subpath`: its output populates repository-level fields (languages, default branch, license) that have no per-sub-package home, so running `brief` against one sub-folder would overwrite the repository's metadata with a single sub-package's. Enumerating a monorepo's sub-packages is the `subprojects` skill's job, not this one's.

That is the whole workflow. If `brief` exits non-zero (including when it is missing), read its stderr and write a short `{"error": "..."}` JSON document to `./report.json` so the caller can see what went wrong rather than getting an empty file. Do not post-process brief's output; the consumer expects its native schema. Do not try to install `brief`; it is pinned by the deployment.
