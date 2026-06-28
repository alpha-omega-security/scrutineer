---
name: revalidate
description: Cheap finding classifier. Reads a finding's six-step trace plus git history at its location and decides true_positive, false_positive, already_fixed, or uncertain, with an optional adjusted severity. Read-only; never executes the reproduction. Run automatically over High and Critical findings from security-deep-dive so the human queue is pre-sorted, and over imported findings whose severity is an external tool's unvalidated claim.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Read-only against ./src; runs git log over the finding's location and never executes any reproduction.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: revalidate
  scrutineer.model: mid
---

# revalidate

A scan finished; a new High or Critical finding landed, or a finding came in from an external import. Before it sits in the human queue, judge it cheaply: is this likely a real bug, almost certainly noise, already fixed by a later commit, or do we need a human to look? This is the cheap pre-sort that keeps `verify` (and human attention) focused on findings worth either.

This skill never runs the finding's reproduction. Use the prose, the code at the location, and the git log over that file. If you cannot decide from those alone, that is `uncertain` — say why, and a human will pick it up.

## Workspace

- `./src` — the repository at its current HEAD
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, and `scrutineer.finding_id` (required; this skill only makes sense finding-scoped)
- `./report.json` — write the report here
- `./schema.json` — output shape

## What to do

1. Read `./context.json`. If `scrutineer.finding_id` is missing, write `{"verdict": "uncertain", "reason": "no finding_id in context.json; revalidate is finding-scoped"}` and exit.

2. Fetch the finding: `GET {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}`. You get title, severity, location, cwe, affected, imported_from, and the six-step prose (trace, boundary, validation, prior_art, reach, rating). If the fetch returns non-200, write `{"verdict": "uncertain", "reason": "fetch failed: <status>"}` and exit.

3. Read the location and load the file. `Location` is `path:line` or `path:line:column`; strip the line and column to get the file path, relative to `./src`. If the file does not exist, that may be `already_fixed` (the code was deleted in a commit that addressed this) — check the git log before deciding.

4. Read the git log over that file since the original scan:

   ```
   git -C ./src log -p -- <file>
   ```

   Bound it by date if there is too much. Look for commits since the scanned commit (it's in the finding's `commit` field) that touch the relevant lines, add a guard, sanitise input, remove the sink, or rename the function out of existence.

5. Decide one of:

   - **true_positive** — the prose describes a real issue, the code at the location still matches the trace, and nothing in the git log has changed it. This is worth a human's time, and probably a `verify` run.
   - **false_positive** — the prose describes something the code does not actually do, or the threat-model contract disclaims this (the disclaimed-properties list in any loaded threat model is the canonical source). Examples: a finding against test fixtures, a finding that confuses two functions with the same name, a finding against a deprecated path the project marks as no-warranty.
   - **already_fixed** — the file or the relevant lines have changed since the scanned commit in a way that addresses the trace. Cite the commit SHA and what changed in `reason`.
   - **uncertain** — you cannot decide on prose plus git history alone. Maybe the trace is incomplete; maybe the fix is partial; maybe the code is genuinely opaque without running it. Be specific about what would let a human decide.

6. Optionally adjust the severity. If the prose pitches the finding higher or lower than the evidence supports, set `adjusted_severity` to one of `Critical`/`High`/`Medium`/`Low`, with one line of justification in `adjusted_severity_reason`. Apply scrutineer's precondition rubric, not CVSS:

   - **Critical**: works on a fresh install with no preconditions. Any precondition disqualifies it.
   - **High**: realistic preconditions a normal deployment satisfies.
   - **Medium**: significant attacker positioning, unusual configuration, or a chain of conditions.
   - **Low**: unrealistic preconditions, or mitigated by the default deployment.

   Leave the severity alone if the original looks right; this is "I want to challenge the grade", not a mandatory step. Adjusting toward `Low` is fine when the prose mentions strong preconditions the original rating ignored.

## Output

Write `./report.json` matching `./schema.json`:

```json
{
  "verdict": "true_positive" | "false_positive" | "already_fixed" | "uncertain",
  "reason": "one paragraph",
  "adjusted_severity": "Critical" | "High" | "Medium" | "Low",
  "adjusted_severity_reason": "one line"
}
```

`adjusted_severity` and `adjusted_severity_reason` are optional and either both present or both absent.

Scrutineer applies this:

- `verdict` and `reason` are appended to the finding's notes as a timestamped revalidate record.
- `true_positive` moves a `new` finding to `enriched`. Any other verdict leaves status alone (rejection is a human act).
- `adjusted_severity` overwrites the finding's severity field, with the change recorded in finding history (so the original is preserved and auditable). The analyst can always change it back.
- When `verdict` is `true_positive` AND the post-adjustment severity is `High` or `Critical`, scrutineer chains the `verify` skill: a finding-scoped run that actually executes the reproduction against HEAD. The chain reads the adjusted severity, so a Critical you mark down to Medium correctly stops at revalidate.

If you cannot decide cleanly, say so in `reason`; an `uncertain` verdict with a sharp question is more useful than a confident wrong guess.
