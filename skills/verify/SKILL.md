---
name: verify
description: Re-run a finding's reproduction against current HEAD and record whether it is confirmed, fixed, or inconclusive.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Expects the finding's reproduction instructions to be runnable against ./src with commonly available tooling.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: verify
---

# verify

Take an existing finding produced by a prior audit skill and check whether it still holds against the current code. A verify run answers one question: does the reproduction in the finding's validation step still trigger the dangerous behaviour?

## Workspace

- `./src` — the repository at its current HEAD
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, and `scrutineer.finding_id` (required; this skill only makes sense finding-scoped)
- `./report.json` — write the verify report here
- `./schema.json` — output shape

## What to do

1. Read `./context.json`. If `scrutineer.finding_id` is missing, write `{"status": "inconclusive", "notes": "no finding_id in context.json; verify is finding-scoped"}` and exit.

2. Fetch the finding: `GET {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}`. You get back title, severity, location, cwe, affected, and the six-step prose (trace, boundary, validation, prior_art, reach, rating). If the fetch returns non-200, write `{"status": "inconclusive", "evidence": "", "notes": "fetch failed: <status>"}` and exit.

3. Read the `validation` field. This is the original reproduction instructions: how to run it, what it looked like when it worked, what dangerous behaviour was observed.

4. Re-run the reproduction against `./src` at HEAD. The point of this skill is to check whether the finding still holds against the current code, so always test HEAD. Be conservative:
   - Only run what the validation field describes. Do not improvise a new attack vector.
   - If the validation is prose-only (no concrete script), try to execute what it describes literally. If you cannot turn the prose into a runnable check, that is `inconclusive` — say why.
   - If the validation installs the package from a registry (`gem install foo`, `pip install foo`), build and install from `./src` instead so you are testing HEAD, not the last release. If the package cannot be built locally, status is `inconclusive` with the build error in `notes`.
   - Capture stdout, stderr, exit code. Paste relevant excerpts into `evidence`.

5. Decide the status:
   - **confirmed** — the reproduction produces the same dangerous behaviour as the original. The finding is still live.
   - **fixed** — the reproduction does not reproduce, AND you can identify what stopped it (a guard, a sanitiser, a refactor that removed the sink). Cite the commit or file:line that fixed it in `notes`.
   - **inconclusive** — one of:
     - the reproduction couldn't run (missing tool, platform mismatch, network dependency)
     - the code has drifted enough that the original trace no longer maps cleanly onto the current tree
     - the reproduction ran but produced a different outcome you cannot classify

   Do not mark `fixed` just because the reproduction failed; "I ran it and nothing happened" is `inconclusive` unless you can point at why.

## Output

Write `./report.json`:

```json
{
  "status": "confirmed" | "fixed" | "inconclusive",
  "evidence": "...",
  "notes": "..."
}
```

Scrutineer updates the finding's lifecycle status based on your answer:
- `confirmed` moves a `new` finding to `enriched`
- `fixed` moves any finding to `fixed`
- `inconclusive` leaves the status alone

Evidence and notes are appended to the finding's Notes field with a timestamp header so the analyst can read your trail later.
