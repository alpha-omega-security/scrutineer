---
name: exposure
description: For one (finding, dependent) pair, decide whether the dependent's code reaches the upstream finding. Emits a CSAF 2.0 product_status verdict with VEX justification.
license: MIT
allowed-tools: Read,Write,Glob,Grep,WebFetch,LS
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: exposure
  scrutineer.requires_remote: true
---

# exposure

Scrutineer just finished a `security-deep-dive` on a library and is now walking that library's top dependents. For each dependent, this skill answers the same question `reachability` asks application-side, but scoped to a single upstream finding: does this dependent's code path the bug requires actually exist?

Your verdict feeds CSAF VEX export, so use the CSAF product_status vocabulary. The four legal status values are `known_affected`, `known_not_affected`, `under_investigation`, `fixed`. `justification` is a CSAF VEX flag label and only applies when status is `known_not_affected`.

## Workspace

- `./src` — a per-scan copy of the dependent's cloned source
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.finding_id`, `scrutineer.dependent_id`
- `./report.json` — write your verdict here
- `./schema.json` — output shape

## Inputs

Fetch the upstream finding so you know what to look for:

```
GET {api_base}/findings/{finding_id}
Authorization: Bearer {token}
```

Read `title`, `location`, `sinks`, `trace`, `boundary` and `affected`. These tell you which call inside the library is dangerous, the input shape it needs, and which versions are vulnerable.

## Procedure

1. **Find how this dependent uses the library.** Grep `./src` for imports/requires of the library package (the finding's `repository_url` / `affected` field name it). If the lockfile lists the lib but no source file uses the dangerous symbol, status is `known_not_affected` with justification `vulnerable_code_not_in_execute_path`.

2. **Check the pinned version against `affected`.** If the dependent pins a version outside the affected range, status is `known_not_affected` with justification `vulnerable_code_not_present` (the consumer ships the library, but the build it ships does not contain the vulnerable code). `component_not_present` is reserved for the case where the library itself is not in the dependent at all.

3. **Trace from a public entry point to the call.** Use the same heuristics `reachability` uses: request handlers, CLI entry points, library exports. If the only callers are test fixtures or admin-only tooling, status is `known_not_affected` with justification `vulnerable_code_not_in_execute_path`.

4. **Check the dependent's own validation around the call.** A size cap, schema check, or safe-mode flag the dependent applies before forwarding to the library may neutralise the bug. If you can show that, status is `known_not_affected` with justification `inline_mitigations_already_exist`.

5. **If a real call path exists and reaches the sink with attacker-controlled input**, status is `known_affected`. Leave `justification` empty.

6. **If the upstream finding has a `fix_version` set and the dependent pins at or above it**, status is `fixed`. Leave `justification` empty.

7. **If the dependent's code base is too large to be confident in two-pass triage**, status is `under_investigation`. Say so in `rationale`.

## Output

Write `./report.json`:

```json
{
  "status": "known_not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "rationale": "Dependent foo imports bar but only calls bar.SafeParse(). The vulnerable bar.UnsafeParse() is never referenced.",
  "spec_version": 1
}
```

Keep `rationale` to one paragraph, citing the file paths you checked. The scrutineer UI displays it under the per-dependent table on the finding page.
