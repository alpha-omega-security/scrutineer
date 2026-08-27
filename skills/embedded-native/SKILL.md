---
name: embedded-native
description: Map native languages, extension bridges, build tools, manifests, and dependencies after shallow Git submodules have been initialized. Runs when triage finds native-extension, submodule, or mixed native-language signals.
license: MIT
compatibility: Requires the `brief` CLI (https://github.com/git-pkgs/brief) on PATH. Shallow submodule initialization is available for remote repository scans.
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

Run Brief after Scrutineer has prepared the repository with recursive, depth-one Git submodules. A root Brief scan can omit files inside initialized submodules, so the bundled script runs Brief separately at each submodule root and keeps every report unchanged inside one envelope.

Run:

```bash
bash ./scripts/scan.sh ./src ./report.json
```

The report contains `schema_version`, the root Brief report under `root`, and an array of Brief reports under `submodules`. Each submodule report's `path` identifies its checkout. Do not summarize, filter, merge, or infer components from these results.

If Brief exits non-zero, read stderr and write `{"error":"brief: ..."}` to `./report.json`. Do not install or modify Brief.
