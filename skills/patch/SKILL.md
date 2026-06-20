---
name: patch
description: Propose a code patch for a finding. Produces a unified diff against the scanned ref plus a short rationale; a diff that passes the worker's applicability gate is stored on the finding as its suggested fix, and a summary note is posted for analyst review. The skill never pushes to the remote.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Finding-scoped; runs against ./src at the scanned ref's HEAD.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: patch
  scrutineer.max_turns: 50
---

# patch

Propose a minimal code patch that fixes a confirmed finding. You are not shipping the fix; you are handing the analyst a starting diff and explaining what it does. The analyst reviews, edits if needed, and opens a PR by hand.

## Workspace

- `./src` — the repository at the scanned ref (the default branch unless the scan was started on a branch), writable
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, `scrutineer.scan_id`, `scrutineer.finding_id` (required; this skill only makes sense finding-scoped)
- `./report.json` — write the patch + rationale here
- `./schema.json` — shape of `report.json`

## What to do

1. Read `./context.json`. If `scrutineer.finding_id` is missing, write `{"error": "no finding_id in context.json; patch is finding-scoped"}` to `report.json` and exit 0.

2. Fetch the finding: `GET {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}`. Read `location`, `cwe`, `trace`, `boundary`, `validation`, `rating`. These five together tell you where the sink is, what the vulnerable input flow looks like, and what dangerous behaviour you need to stop.

3. Inside `./src`, edit files to fix the finding. Constraints:

   - **Minimal.** Change only what the fix requires. Do not refactor surrounding code, rename variables, reformat unrelated lines, or upgrade dependencies unless the fix inherently requires it.
   - **In place.** Fix the sink where it lives. If the finding's `location` is `pkg/foo/bar.go:42`, that is where the patch should land (or at the nearest layer where a guard is sensible — e.g. the input validator that feeds the sink).
   - **Consistent.** Match the existing code style and idioms. If the codebase uses a specific sanitiser, validator, or helper for similar cases, reuse it. Do not introduce a new helper module for a one-off fix.
   - **Safe.** The patch must not break the reproduction's documented legitimate behaviour — only block the dangerous path. If you cannot tell where the dangerous path diverges from legitimate use, stop and refuse to patch (see "Refusing to patch" below for the `{"error": ...}` shape).
   - **Include a test when practical.** If the repo has a test suite that covers the vulnerable code path, add a regression test that would fail without your patch. If the repo has no tests, or the sink is in a place that is hard to cover, skip this and say why in `rationale`.

4. Once you have a working tree edit, generate a unified diff against HEAD:

   ```sh
   cd src
   git add -N .
   git diff HEAD -- . > ../patch.diff
   ```

   Read `../patch.diff` (the workspace root, alongside `report.json`) and put its contents into `report.json` under the `patch` field. Do not commit; the diff is the artefact. If the diff is empty, something went wrong — do not write an empty patch. Write `{"error": "patch produced no diff"}` and exit 0.

5. POST a finding note summarising the patch: `POST {api_base}/findings/{finding_id}/notes` with:

   ```json
   {
     "body": "Proposed patch in scan #{scan_id}.\n\nFiles changed: ...\n\n{short rationale}\n\nApply with: `git apply` the diff from the scan report.",
     "by": "patch"
   }
   ```

   The note lives on the finding page; the full diff lives in `report.json` and is viewable on the scan page. A diff that passes the worker's applicability gate is also stored on the finding as `suggested_fix` and served from the finding page as a `.patch` download.

6. Do not PATCH any editable fields on the finding. Specifically:
   - Do not set `fix_commit` — that field means a shipped upstream fix, not a proposal. The analyst sets it after their PR merges.
   - Do not set `fix_version` — same reason.
   - Do not touch `status`. Lifecycle transitions belong to the analyst.

7. Write `./report.json`:

   ```json
   {
     "patch": "diff --git a/pkg/foo/bar.go b/pkg/foo/bar.go\n...",
     "rationale": "Short prose — two or three sentences. What the guard is, why it blocks the trace, what legitimate input it still lets through.",
     "files_changed": ["pkg/foo/bar.go", "pkg/foo/bar_test.go"],
     "base_commit": "<HEAD sha from ./src>",
     "tests_added": true,
     "notes": "Optional: anything the analyst should know — a second sink you spotted but didn't patch, a style choice you weren't sure of, a test you couldn't write."
   }
   ```

   `base_commit` is the HEAD sha the diff applies to. The analyst needs this to `git am` or `git apply` cleanly — if they rebased since the scan, they know the patch may not apply and can regenerate.

## Refusing to patch

Write `{"error": "...", "rationale": "..."}` and exit 0 in any of these cases — do not ship a bad patch:

- The finding prose is too thin (empty Trace, empty Validation). You need both to know where the sink is and what behaviour to stop.
- The fix is architectural (e.g. "rewrite this whole module to not shell out") rather than localisable. A patch skill proposes a surgical fix; larger changes are an issue comment for the maintainer, not a diff.
- The codebase is in a language or framework you cannot confidently edit without risking regressions. It is better to say so than to produce a plausible-looking but wrong patch.
- The finding has already been fixed upstream. Check `git log -- {location}` — if a recent commit looks like it addressed the sink, surface the SHA in `notes` and refuse to duplicate.

## Constraints

- Do not push. Do not commit. Do not open a PR. The scrutineer workspace is ephemeral and isolated; your diff is the only thing that survives the scan.
- Do not add new dependencies. If sanitisation or escaping is needed, reuse a helper the codebase already imports. A patch that needs a new top-level dep almost always means the fix is in the wrong place.
- Do not edit the lockfile, go.sum, Gemfile.lock, package-lock.json, Cargo.lock, etc. unless you also changed the manifest that owns it. Stray lockfile churn makes diffs hard to review.
- Do not touch files outside what the fix requires. CI config, docs unrelated to the fix, README — leave alone.
