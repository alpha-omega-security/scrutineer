---
name: verify
description: Re-run a finding's reproduction against current HEAD and record whether it is confirmed, fixed, inconclusive, or deferred.
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

4. Preflight the reproduction without executing it. Read every command, script, and input the `validation` field names and classify the trigger phase into exactly one of:
   - **local-safe** — uses only stdin or file input, or connects only to `127.0.0.1` / `::1` / `localhost` / a Unix socket / a server the reproduction itself starts on loopback; writes only under the workspace or OS temp.
   - **external-reach** — resolves or connects to any other host (including link-local metadata addresses, DNS lookups of attacker-chosen names, or an interactsh/Burp collaborator domain); reads any of `~/.ssh`, `~/.aws`, `~/.docker`, `~/.npmrc`, `~/.netrc`, `~/.pypirc`, `~/.cargo/credentials`, or a credential env var; or writes outside the workspace and temp.

   Record the classification and the exact justifying lines (quoted verbatim from the reproduction) into `preflight`. If external-reach, do not execute anything: status is `deferred`, put the offending lines in `notes`, and skip to Output. The egress proxy would block the connection anyway, so running it produces `inconclusive` for the wrong reason; `deferred` tells the operator to run it somewhere with a callback listener rather than to debug the container.

5. Re-run the reproduction against `./src` at HEAD. The point of this skill is to check whether the finding still holds against the current code, so always test HEAD. Be conservative:
   - Only run what the validation field describes. Do not improvise a new attack vector.
   - If the validation is prose-only (no concrete script), try to execute what it describes literally. If you cannot turn the prose into a runnable check, that is `inconclusive` — say why.
   - If the validation installs the package from a registry (`gem install foo`, `pip install foo`), build and install from `./src` instead so you are testing HEAD, not the last release. If the package cannot be built locally, or the container profile lacks the runtime the reproduction needs, status is `inconclusive` with `notes` starting `env-blocked:` followed by the error, so the operator knows to fix the profile rather than re-read the finding.
   - Wrap the trigger so it cannot depend on state an earlier step left in `$HOME`, cannot run forever, and cannot allocate unbounded memory:

     ```sh
     mkdir -p .fakehome .tmp
     env -i PATH="$PATH" HOME="$PWD/.fakehome" LANG=C.UTF-8 TMPDIR="$PWD/.tmp" \
       bash -c 'ulimit -v 4194304; ulimit -t 180; exec timeout --kill-after=10s 180s <trigger>' 2>&1 | tee .verify.log
     ```

     If the runtime refuses to start under `ulimit -v 4194304` (the JVM and node reserve address space up front), drop `ulimit -v`, keep `ulimit -t` and `timeout`, rely on the reproduction's own `-Xmx` / `--max-old-space-size` cap, and record that in `notes`.
   - Record the exact reproduction you ran into `reproducer`, verbatim: the full script contents, command line, or crafted input — not a description of it. If you wrote a file to disk, paste its contents; if you ran shell commands, paste them. A report whose `evidence` shows output but whose `reproducer` only says "ran the repro" is useless: the analyst cannot tell what was executed or re-run it.
   - Capture the result of running it — stdout, stderr, exit code — into `evidence`. Paste relevant excerpts.

6. Decide the status:
   - **confirmed** — the reproduction produces the same dangerous behaviour as the original. The finding is still live. For resource-exhaustion findings (CWE-400, 405, 674, 770, 789, 834, 835, 1333, or the title says hang / loop / ReDoS / OOM / billion-laughs / decompression bomb / stack overflow), the wrapper's `timeout` firing (exit 124) or a `Killed` from the memory limit is the confirmation: record which limit fired in `evidence` and set `confirmed`. A quick clean exit with no fingerprint on such a finding is not `fixed` unless you can cite the guard that bounds it.
   - **fixed** — the reproduction does not reproduce, AND you can identify what stopped it (a guard, a sanitiser, a refactor that removed the sink). Cite the commit or file:line that fixed it in `notes`.
   - **deferred** — preflight classified the reproduction external-reach and it was not run. The finding may well be live; a human needs to run it somewhere the callback can land.
   - **inconclusive** — one of:
     - the reproduction could not run (`env-blocked:` missing tool or platform mismatch)
     - the code has drifted enough that the original trace no longer maps cleanly onto the current tree
     - the reproduction ran but produced a different outcome you cannot classify

   Do not mark `fixed` just because the reproduction failed; "I ran it and nothing happened" is `inconclusive` unless you can point at why.

## Output

Write `./report.json`:

```json
{
  "status": "confirmed" | "fixed" | "inconclusive" | "deferred",
  "preflight": {
    "classification": "local-safe" | "external-reach",
    "justification": "the exact lines that decided it"
  },
  "reproducer": "...",
  "evidence": "...",
  "notes": "..."
}
```

`reproducer` is the verbatim script/commands/input you ran; `evidence` is the output they produced. Both belong in the report — the output alone, without the thing that generated it, cannot be acted on. `preflight` is present whenever step 4 ran (that is, on every status except the early-exit `inconclusive` cases in steps 1 and 2); on `deferred` it is required and is the whole answer.

Scrutineer updates the finding's lifecycle status based on your answer:
- `confirmed` moves a `new` finding to `enriched`
- `fixed` moves any finding to `fixed`
- `inconclusive` and `deferred` leave the status alone

The reproducer, evidence, and notes are appended to the finding's Notes field with a timestamp header so the analyst can read your trail later — and re-run the reproducer.
