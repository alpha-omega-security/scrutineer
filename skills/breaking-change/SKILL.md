---
name: breaking-change
description: Decide whether a finding's suggested fix is a breaking change for top dependents. Reads the unified-diff fix on the finding, identifies the public API surface that changes (signatures, exports, removed fields, renamed types), and lists which top dependents are most likely to break. Static analysis on the diff and the dependent metadata from the scrutineer API; never executes dependent code.
license: MIT
compatibility: Needs network access to the scrutineer skill API to read the finding and its dependents list. Read-only against `./src` (the upstream library at the scanned commit); never runs the reproduction or any dependent code.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: breaking_change
  scrutineer.model: mid
  scrutineer.requires_remote: true
---

# breaking-change

Scrutineer has a proposed fix for a finding and wants to know whether shipping it would break the library's top dependents. Read the fix diff, identify what changes in the library's public API surface, and name the dependents whose call sites likely break. Never assume; quote the diff lines you reasoned from, and prefer `unknown` over a confident wrong call.

Read-only static analysis. Reason from the diff, the finding prose, and the dependent metadata returned by the scrutineer API. Do not install, build, or run any code.

## Workspace

- `./src` — the library at the scanned commit, before the fix is applied
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, and `scrutineer.finding_id` (this skill is finding-scoped)
- `./report.json` — write your verdict here
- `./schema.json` — output shape

## Inputs

1. Fetch the finding for the suggested fix and the bug context:

   ```
   GET {api_base}/findings/{finding_id}
   Authorization: Bearer {token}
   ```

   You need `suggested_fix` (the unified diff) and `suggested_fix_commit` (what it applies to). If `suggested_fix` is empty, write `{"verdict": "unknown", "rationale": "no suggested_fix on finding; nothing to analyse"}` and exit.

2. Fetch the dependents the analyst cares about:

   ```
   GET {api_base}/repositories/{repository_id}/dependents
   Authorization: Bearer {token}
   ```

   Take the top 20 by `dependent_repos` / `downloads`. The endpoint already returns them ranked.

## Procedure

1. **Read the diff.** Identify what changes in *public API surface*: function signatures, exported types, removed fields, renamed methods, behaviour changes in default arguments. Internal refactors (private helpers, additional input validation that returns the same value on the happy path) are not breaking on their own.

2. **Bucket the change.** One of:
   - **Pure addition.** New optional parameter with a default, new method, new exported field. Generally non-breaking on its own.
   - **Tightened contract.** Same signature, narrower accepted inputs (a guard added). Breaks callers that relied on the looser contract; flag specifically.
   - **Signature change.** Renamed export, removed export, parameter reordered, return type changed. Breaks every caller.
   - **Behavioural change with same signature.** Same shape, different result (an output encoding flipped). Breaks callers that depended on the old behaviour.

3. **For each top dependent, check exposure.** Without cloning, read the dependent's package name and registry URL from the API response. The question is "does this dependent plausibly call the changed symbols". Be honest about what you cannot tell from name alone: a dependent that is a CLI wrapper around the library probably uses everything; a dependent that uses only one entry point may be untouched. When the diff changes a widely-used symbol (a top-level export, the constructor, a default config field), assume every dependent is exposed unless you can argue otherwise.

4. **Emit one of three verdicts.**
   - `non_breaking` — the changed surface is private, or every public change is a pure addition. Say so and cite the diff lines.
   - `breaking` — at least one signature change, removed/renamed export, or tightened contract on a symbol typical dependents reach. List the affected_dependents the analyst should warn.
   - `unknown` — the diff is too large or too ambiguous to call. Say what you would need (a per-dependent build, a real test run) to decide.

## Output

Write `./report.json` matching `./schema.json`:

```json
{
  "verdict": "breaking" | "non_breaking" | "unknown",
  "rationale": "one paragraph plus a bulleted list of cited diff lines",
  "api_changes": [
    {"kind": "signature_change" | "removed_export" | "tightened_contract" | "behavioural_change" | "addition",
     "symbol": "package.path.Symbol", "before": "...", "after": "...", "diff_lines": "src/foo.go:42-58"}
  ],
  "affected_dependents": [
    {"name": "@scope/pkg", "registry": "npm", "reason": "imports the renamed function"}
  ]
}
```

Scrutineer writes `verdict` to the finding's `breaking_change` field with the change recorded in history, and writes the prose plus the affected-dependents list to `breaking_change_rationale`. Both feed the disclosure draft and the upstream conversation.

If the diff is itself empty, partial, or evidently a stub, the right answer is `unknown` with a specific reason — not `non_breaking` by default.
