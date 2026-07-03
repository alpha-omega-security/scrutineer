---
name: advisory-deep-dive
description: Re-audit every past GHSA/CVE advisory published against this repository, anchored on each advisory's fix commit, for three failure modes — a bypass of the fix, an incomplete fix that left a path open, and the same class of bug in sibling code the fix never touched. Use when you want to prove that prior fixes actually held rather than trusting that a shipped patch closed the hole. The target is this codebase's own first-party source, not its dependencies.
license: MIT
compatibility: Needs the cloned repo with full git history in ./src, the scrutineer API for the advisory cache, and network access to read advisory pages. Uses `git` and may use Claude subagents.
allowed-tools: Read,Write,Bash,Grep,Glob,WebFetch,Task
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.max_turns: 100
  scrutineer.model: max
  scrutineer.requires_remote: true
  scrutineer.requires:
    - advisories
---

# advisory-deep-dive

A published advisory means a vulnerability in this codebase was found and fixed once. This skill asks whether the fix held. For each advisory the repository already carries, it locates the fix in git history and re-audits three failure modes:

- **Bypass** — the fix added a check, filter, or escape, but a crafted input reaches the same sink anyway. Blocklists miss variants; a fix for one encoding rarely covers all of them.
- **Incomplete fix** — the patch closed the one call-site, parameter, or code path in the report, while a sibling path to the same sink stayed open.
- **Sibling vulnerability** — the same class of bug (same CWE) lives elsewhere in the tree, in code the fix never touched.

The target is this codebase's own first-party source. Do not re-report the original advisory as a finding, and do not report that a dependency has a CVE. A finding is valid only if a *current* weakness lives in this repository's code at HEAD.

This audit reuses the six-step discipline of the `security-deep-dive` skill — trace, boundary, validate, prior-art, reach, rate — per candidate. The difference is the starting point: not a fresh inventory of every sink, but the fix commit of a known past vulnerability.

## Workspace

- `./src` — the cloned repository, full history preserved under `./src/.git`
- `./context.json` — repo identity plus a `scrutineer` block with `api_base`, `token`, `repository_id`, and optional `scan_subpath`
- `./report.json` — write your findings report here
- `./schema.json` — the JSON schema your report must conform to

If `scrutineer.scan_subpath` is set, scope every code read, trace, and reported `location` to `./src/{scan_subpath}` and treat that sub-folder as the project root. Advisories, packages, and dependents remain repo-wide.

## Scrutineer API (call with `Authorization: Bearer {token}`)

- `GET {api_base}/repositories/{repository_id}/advisories` — the advisory worklist: `uuid`, `url`, `title`, `description`, `severity`, `cvss_score`, `classification` (the CWE), `packages`, `published_at`, `withdrawn_at`. This is your input.
- `GET {api_base}/repositories/{repository_id}` — canonical metadata
- `GET {api_base}/repositories/{repository_id}/packages` — published packages, to verify against the shipped artefact in Step 4 of the per-candidate checklist
- `GET {api_base}/repositories/{repository_id}/dependents` — top dependents for reach analysis
- `GET {api_base}/repositories/{repository_id}/scans?skill=threat-model&status=done` then `GET {api_base}/scans/{id}` — the structured threat model for trust boundaries, if one ran

If any request returns an empty list or a non-200, that upstream scan has not run or the API is unreachable; fall back to reasoning over `./src`.

## Step 1: Build the advisory worklist

Fetch the advisories. Drop any with a non-empty `withdrawn_at` — a withdrawn advisory was not a real vulnerability. Process the rest in a stable order (by `published_at`, then `uuid`) so two runs against the same commit produce the same report.

**If the list is empty, write `{"findings": []}` and exit.** A repository with no published advisories has nothing for this skill to re-audit; that is a valid clean result, not a failure.

## Step 2: Locate the fix for each advisory

The advisory record does not carry the fix commit. Find it:

1. `WebFetch` the advisory `url` (the GHSA/CVE page). Its references section usually links the fixing commit or PR. Extract the CVE and GHSA ids from the `url` and `uuid` too.
2. In `./src`, search history for that fix. `git log --all --grep=<CVE-or-GHSA-id>`, `git log --all --grep=<keyword from the title>`, and `git log -S<symbol>` for a function named in the advisory. A fix usually lands shortly before `published_at`; use the date to disambiguate candidates.
3. Read the fix diff with `git show <commit>`. This diff — what it added, and what it left alone — is the anchor for all three questions below.

If you genuinely cannot locate the fix, say so in the finding's `prior_art` and still run the sibling-vulnerability analysis over the code region the advisory describes; skip the bypass and incompleteness questions, which need the patch.

## Step 3: The three questions

Anchored on the fix diff, ask each question. Any candidate answer runs the full per-candidate checklist below before it becomes a finding.

**Bypass.** Read what the fix checks for. Is it an allowlist (safe by construction) or a blocklist (safe only against the inputs it enumerated)? For a blocklist, enumerate what it missed — alternate encodings, case folding, Unicode normalisation forms, alternate path separators, double-encoding, null bytes, an equivalent primitive the filter does not name — and any code path that reaches the same sink without passing through the new check. Construct one such input and try it against current HEAD.

**Incomplete fix.** The report named one path to the sink. Grep for the others: sibling call-sites of the same dangerous primitive, other public parameters that flow to it, other entry points. Did the patch guard all of them, or only the one in the report?

**Sibling vulnerability.** Take the advisory's CWE and root cause and grep the tree for the same shape elsewhere — the same missing containment check, the same unsafe primitive on a different input. Code the fix never touched, exhibiting the class the fix proves the project is prone to.

## Per-candidate checklist

For every candidate from Step 3, apply the `security-deep-dive` six steps in order and stop at the step that rules it out, recording which:

1. **Trace** the value from the sink back to a trust boundary.
2. **Boundary** — is the input actually attacker-controlled in this project's threat model, or a trusted developer/operator choice? Check any existing mitigation the project already has before concluding the input reaches unguarded.
3. **Validate** — write a reproduction and run it against current HEAD. Paste the script verbatim and its output into `validation`. A bypass or incomplete-fix candidate that cannot be reproduced at HEAD is not a finding: the fix held.
4. **Prior art** — cite the advisory (`uuid`, `url`) this candidate descends from. Check issues and PRs for whether a maintainer already considered and declined this variant.
5. **Reach** — is the candidate reachable from a public entry point in the shipped artefact? Record `reachable`, `harness_only`, or `unclear`.
6. **Rate** severity and confidence given everything above.

## Fan-out for many advisories

One agent can handle a handful of advisories end to end. For a repository with many, fan out with one subagent per advisory (or per small batch), each running Steps 2–3 and the checklist for its slice.

Subagents do not see this SKILL.md — only the prompt you write them and the shared working directory, where `report.json` sits in plain view. Left to infer the deliverable, each writes `./report.json` and clobbers the previous one; a clobbered report is still schema-valid, so nothing downstream flags the loss. When you delegate:

- Tell every subagent, in its prompt, not to write or touch `./report.json`. That file is yours to write once, at the end.
- Give each a distinct scratch file — `./candidates-<advisory-id>.json` — and have it return that path.
- You are the sole writer of `./report.json`. Read every scratch file back, union the candidates, and write the one report yourself.

## Output

Write `./report.json` to match `./schema.json`: a `findings` array. For each surviving finding:

- `id` is a stable `F001`, `F002`, … `title`, `severity`, `confidence`, `cwe`, `location` (`path:line`), `reachability`, `quality_tier`, and the per-step markdown `trace` / `boundary` / `validation` / `prior_art` / `reach` / `rating` as in `security-deep-dive`.
- `references` links the origin: one entry `{"url": <advisory url>, "tags": "advisory"}` (use `ghsa` or `cve` when the url is that specific), and, when you found it, one `{"url": <fix commit or PR url>, "tags": "patch"}` (or `pr`).
- Say in `title` which of the three modes it is, e.g. "Bypass of GHSA-xxxx path-traversal fix" / "GHSA-xxxx fix left <sibling path> open" / "Same OS-command-injection class as GHSA-xxxx in <other file>".

Write `{"findings": []}` if every past fix held and no sibling turned up — a clean re-audit is the expected common result.
