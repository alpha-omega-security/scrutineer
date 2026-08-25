---
name: embedded-native
description: Map native languages, extension bridges, build tools, manifests, and dependencies after shallow Git submodules have been initialized. Runs when triage finds native-extension, submodule, or mixed native-language signals.
license: MIT
compatibility: Requires `brief` v0.12.0 or later on PATH. Shallow submodule initialization is available for remote repository scans.
metadata:
  scrutineer.model: mid
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
  scrutineer.recurse_submodules: true
  scrutineer.paths:
    - "**"
---

# embedded-native

Run Brief after Scrutineer has prepared the repository with recursive, depth-one Git submodules. Brief v0.12 does not include every initialized submodule consistently in a root scan, so the bundled script runs it separately at each submodule root and keeps every Brief report unchanged inside one envelope.

Run:

```bash
bash ./scripts/scan.sh ./src ./report.json
```

The report contains `schema_version`, the root Brief report under `root`, and an array of Brief reports under `submodules`. Each submodule report's `path` identifies its checkout. Do not summarize, filter, merge, or infer components from these results.

If Brief exits non-zero, read stderr and write `{"error":"brief: ..."}` to `./report.json`. Do not install or modify Brief.
