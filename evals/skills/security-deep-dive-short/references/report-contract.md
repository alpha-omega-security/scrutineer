# Deep-dive report contract

`schema.json` is authoritative for field types and required fields. This reference covers the semantic rules that JSON Schema cannot express.

## Identity and scope

- Set `repository` from `context.json`'s repository URL, `commit` from `git -C ./src rev-parse HEAD`, `spec_version` to `14`, and `date` to today.
- Keep every location repository-relative, or relative to `scan_subpath` when one is set. Use `path:line` when a line is known.
- Describe the actual source-tree or diff scope in `method.scope`. Do not claim coverage outside a focus area, scan subpath, or diff rescan.
- Populate `boundaries` from the supplied threat model when available. Preserve its labels, provenance, and source instead of inventing replacements.

## Inventory reconciliation

- Give every inventory entry a unique stable id, location, class, boundary, and consumed value.
- Every inventory id must appear exactly once by disposition: referenced by a real finding or by a `ruled_out` entry. Resolve gaps before writing the report.
- `method.inventory_count` equals the number of inventory entries. `method.ruled_out_count` equals the number of inventory sink ids assigned to `ruled_out`, not the number of grouped ruled-out entries. `method.unresolved_count` must be zero in a completed report.
- Record search commands and hit counts in `method.grep_patterns` when the schema requests them. A raw source hit excluded as a comment, fixture, generated file, or third-party code needs its location and reason.
- When combining subagent output, union all slices and deduplicate only identical location/class/boundary entries. Different boundaries at one source location remain distinct.

## Findings

Report only concrete, high-signal vulnerabilities:

- `reachability` is `reachable`; `quality_tier` is `high`.
- `sinks` references the applicable inventory ids.
- `trace` names the attacker-controlled source, data path, sink, and missing control.
- `boundary` names the crossed trust boundary.
- `validation` contains reproducible evidence, including commands or scripts and their output when execution is practical.
- `rating` explains severity, impact, and preconditions.
- `prior_art` carries the repository's own prevalence alongside any advisory: the literal grep command that counted the pattern across the tree plus its hit count written as `<n> hits`, so a reader can tell a slip from a house idiom without re-running the sweep.
- `dup_check` states which existing or sibling findings were compared.
- `discovered_via` records the first useful source: `source`, `issue-tracker`, `advisory`, or `documentation`.
- `artifacts` contains short evidence strings such as `path:line command/result`.

Consolidate one root cause at one sink and boundary into one finding. Split only when boundaries or impacts are materially different.

## Ruled out

Each rejected candidate identifies its sink ids, the audit step that rejected it, and a specific reason with code or threat-model evidence. A candidate the project repeats deliberately across the tree cites the literal grep command and its `<n> hits` count in `reason`, so the next run inherits the count instead of re-deriving it. Prefer the vocabulary consumed by the threat workbench: `not_reachable`, `validated`, `out_of_scope`, `duplicate`, `dependency_only`, `known_wontfix`, `insufficient_evidence`, or `expected_safe_behavior`. When a loaded threat model supplies a more specific disposition label, preserve that label and cite its source.

A clean audit uses `findings: []`; it does not omit boundaries, inventory, method evidence, or ruled-out entries.
