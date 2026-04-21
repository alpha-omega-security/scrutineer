---
name: subprojects
description: Enumerate scannable sub-folders inside a repository. Identifies monorepo packages, workspaces, and discrete modules so the analyst can scope deep-dive scans to a specific sub-path instead of treating a huge tree as one unit. Runs at repo level; writes back a list that surfaces on the repo overview.
license: MIT
compatibility: Needs network access to the scrutineer API only for logging; the enumeration itself is filesystem-only against ./src.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: subprojects
---

# subprojects

List the discrete scannable units inside a repository so the analyst can scope security scans to a sub-path instead of the whole tree. A repository with a single package at the root gets an empty list — that is the expected shape for the common case. A monorepo like apache/airflow or kubernetes/kubernetes gets a row per sub-package.

## Workspace

- `./src` — the repository at HEAD. Read-only.
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`. Not finding-scoped, not sub-path-scoped (this skill *produces* sub-paths; it does not consume one).
- `./report.json` — write the enumeration here.
- `./schema.json` — output shape.

## How to identify subprojects

A subproject is a sub-folder that looks like an independently buildable, scannable unit. Heuristics, in descending order of signal strength:

1. **Explicit monorepo declarations.** If the repo has any of these at the root, the file names the workspaces directly — use them verbatim:
   - `pnpm-workspace.yaml` — `packages:` glob list
   - `lerna.json` — `packages:` array
   - `nx.json` / `workspace.json` — NX workspace layout
   - `turbo.json` alongside a root `package.json` with a `workspaces` field
   - `go.work` — `use (...)` list
   - root `Cargo.toml` with `[workspace].members`
   - `pyproject.toml` with `[tool.uv.workspace].members` or Rye/hatch equivalents

2. **Sub-folder package manifests.** When no workspace declaration exists, scan sub-folders (depth ≤ 3, skip `node_modules`, `vendor`, `.git`, `dist`, `build`, `target`) for any of:
   - `go.mod` → go-module
   - `package.json` with a `name` field → npm-package
   - `pyproject.toml` / `setup.py` / `setup.cfg` → python-package
   - `Cargo.toml` with `[package]` → rust-crate
   - `composer.json` → composer-package
   - `pom.xml` or `build.gradle[.kts]` → maven/gradle-module
   - `Gemfile` and/or `*.gemspec` → ruby-gem
   - `Package.swift` → swift-package
   - `Dockerfile` alongside a README in a `services/` or `apps/` tree → service

3. **Cluster by top-level directory.** If heuristic 2 produces many hits under a common parent (e.g. `providers/amazon`, `providers/google` each has its own `pyproject.toml`), keep each sub-folder as its own row rather than rolling them up — an analyst may want to scan just one cloud provider's code.

## What NOT to emit

- **The root as a subproject.** A repo with one package at the root has zero subprojects; scrutineer already treats root as the default scan scope.
- **Test fixtures, examples, vendored deps.** Folders called `testdata/`, `fixtures/`, `examples/`, `vendor/`, `third_party/`, `external/` almost always ship code that is not the project itself — skip them.
- **Build outputs.** `dist/`, `build/`, `out/`, `target/`, `node_modules/`, `.venv/`, `__pycache__/` — same.
- **Nested workspaces with no independent manifest.** If a sub-folder has no manifest and is not named by a workspace declaration, it is not a subproject; it is just a sub-folder.

## Output

Write `./report.json`:

```json
{
  "subprojects": [
    {
      "path": "airflow-core",
      "name": "airflow-core",
      "kind": "python-package",
      "description": "Core Airflow scheduler, webserver, and DAG runtime."
    },
    {
      "path": "airflow-ctl",
      "name": "airflow-ctl",
      "kind": "python-package",
      "description": "Airflow CLI distributed as a separate package."
    },
    {
      "path": "providers/amazon",
      "name": "apache-airflow-providers-amazon",
      "kind": "python-package",
      "description": "AWS provider package. Ships operators, hooks, and sensors for S3, EMR, Glue, and other AWS services."
    }
  ]
}
```

Fields:

- `path` — required, relative to repo root, no leading slash. This is what scrutineer stores on `Scan.sub_path` when the analyst scans it.
- `name` — short human label. Use the package's own name when the manifest has one (`name` in package.json, `module` path in go.mod, `[package].name` in Cargo.toml); otherwise the last segment of `path`.
- `kind` — the detection hit: `go-module`, `npm-package`, `python-package`, `rust-crate`, `composer-package`, `maven-module`, `gradle-module`, `ruby-gem`, `swift-package`, `service`, `monorepo-root`, etc. Free-form; the UI renders it as a badge.
- `description` — one or two sentences. Read the README in the sub-folder if present, or infer from the package name and directory structure. Keep it specific ("AWS provider package", not "code for AWS").

## Constraints

- Empty list is the correct output for a single-package repo. Do not invent subprojects to avoid an empty array.
- Do not include the root directory as a row. Root is implicit.
- Do not add more than ~50 rows. If a monorepo is bigger than that, pick the 50 most significant (largest manifests, deepest tree, or named in a workspace declaration) and note the truncation in a `notes` field (the schema allows it).
- Scrutineer replaces the full set on each re-run, so missing rows from a previous run will disappear — do not try to merge with prior output.
