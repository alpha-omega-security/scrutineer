---
name: disclose
description: Draft the disclosure content for a finding in GitHub Security Advisory shape. Produces a title, markdown description, affected package block, CVSS vector, CWE list, and references, then writes them back to the finding so the analyst can paste them into the GHSA form (or POST to GitHub's repository-advisories REST endpoint) rather than composing from scratch.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Finding-scoped; runs on one finding at a time.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# disclose

Draft disclosure content for an existing finding in a shape that maps one-to-one to GitHub's repository security advisory (GHSA) form. You are not deciding whether the bug is real — the triage and verify skills did that. Your job is to turn a confirmed finding into text a maintainer can paste into `https://github.com/{org}/{repo}/security/advisories/new`, or that a caller can POST to `POST /repos/{owner}/{repo}/security-advisories`.

## Workspace

- `./src` — the repository at its current HEAD, so you can link to file:line and read tag history
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.repository_id`, and `scrutineer.finding_id` (required; this skill only makes sense finding-scoped)
- `./report.json` — write a GHSA-shaped record of what you drafted
- `./schema.json` — shape of `report.json`

## What to do

1. Read `./context.json`. If `scrutineer.finding_id` is missing, write `{"error": "no finding_id in context.json; disclose is finding-scoped"}` to `report.json` and exit 0.

2. Fetch the finding: `GET {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}`. You get title, severity, cwe (comma-joined), location, affected, cvss_vector, cve_id, fix_version, fix_commit, and the six-step prose (trace, boundary, validation, prior_art, reach, rating). Also fetch:
   - `GET {api_base}/repositories/{repository_id}` for the upstream URL and default branch
   - `GET {api_base}/repositories/{repository_id}/packages` for the list of published packages; you need this to fill GHSA's affected-package block

3. Compose the GHSA fields below. Every field names the GHSA REST key (`summary`, `description`, `vulnerabilities`, etc.) so the mapping is explicit. Keep each one factual and derived from the finding — do not invent details the audit did not establish.

   **`summary` (title).** A single sentence, under 80 characters. Start with the impact verb ("Arbitrary file write in …", "Prototype pollution in …"), not the package name. Reuse the finding's `title` if it already fits that shape.

   **`description` (markdown body).** This is the main document a maintainer reads. Structure as below. Each section is required unless marked optional.

   ```
   ## Summary

   Two or three sentences describing the vulnerability in the maintainer's own domain terms. Repeat the one-line summary then expand.

   ## Impact

   What an attacker can do. Stay tight — reuse the Rating prose if it already covers this. Name the attacker model (unauthenticated remote, local, authenticated user) in the first sentence.

   ## Affected versions

   A line per affected range, matching the `vulnerabilities[].vulnerable_version_range` values. Example:
   - `>= 1.0, < 2.3.1` (all pre-2.3.1 releases)

   ## Patched versions

   If a fix has shipped, list the first patched version. Otherwise write "Not yet patched" and state whether the `fix_commit` on the finding is on the default branch.

   ## Proof of concept

   Reuse the Validation prose, formatted as a short runnable recipe. Include the minimum needed to trigger the bug. A fenced code block when a script exists.

   ## Fix suggestion

   One or two sentences on where the guard belongs (sanitise here, validate there, remove the sink). Do not claim a specific patch unless the Trace identifies the exact line.

   ## References

   - `{repo.html_url}/blob/{default_branch}/{location}` — the vulnerable code
   - `https://cwe.mitre.org/data/definitions/{n}.html` — one line per CWE
   - any URL that appeared verbatim in the prior_art field of the finding
   ```

   GHSA's REST endpoint has no structured references field — all URLs live inside the description markdown. You will still post them as scrutineer references (step 4) so the UI surfaces them as links, but the maintainer-facing copy is the markdown list.

   **`vulnerabilities[]` (affected products).** One entry per published package. Build from the repository's packages list. Each entry has:

   ```json
   {
     "package": { "ecosystem": "<ghsa-ecosystem>", "name": "<package-name>" },
     "vulnerable_version_range": ">= 1.0, < 2.3.1",
     "patched_versions": "2.3.1",
     "vulnerable_functions": ["pkg.Parse", "pkg.ParseFile"]
   }
   ```

   Normalise the ecosystem string to the exact GHSA enum — all lowercase, with these specific spellings: `rubygems` (not `RubyGems`), `npm`, `pip` (not `pypi` or `PyPI`), `maven`, `nuget`, `composer`, `go`, `rust`, `erlang`, `actions`, `pub`, `other`. If a scrutineer package has `ecosystem: "Packagist"`, emit `"composer"`; if `"Cargo"`, emit `"rust"`. Map anything unrecognised to `"other"`.

   If the repository has no packages, omit the `vulnerabilities` array entirely and note in the `notes` field of `report.json` that this advisory is source-only (a maintainer filing it would still need to add an affected-product block manually).

   `vulnerable_functions` is optional; fill it only when the Trace field names specific exported symbols (e.g. `pkg.Foo`, `Class#method`). Leave empty otherwise.

   **`severity` / `cvss_vector_string`.** GHSA accepts exactly one of the two; prefer the CVSS vector when you can derive one confidently, fall back to the severity label otherwise.

   Use CVSS 3.1. Derive each metric from the finding prose: `AV` from the attack surface described in Boundary, `AC` from how contrived the trigger is in Validation, `PR`/`UI` from whether the trigger needs authentication or human interaction, `S` from whether the impact crosses a trust boundary, and `C`/`I`/`A` from the dangerous behaviour in Rating. Write the full vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

   For the severity label fallback, map scrutineer's `severity` field (`Critical`/`High`/`Medium`/`Low`) to GHSA's lowercase `critical`/`high`/`medium`/`low`. If the finding has a pre-existing `cvss_vector`, leave it alone and reuse it here — do not overwrite analyst edits.

   **`cwe_ids[]`.** Split the finding's comma-joined `cwe` field into an array of `CWE-N` strings (GHSA accepts multiple). Do not invent CWEs not in the finding.

   **`cve_id`.** Pass through whatever the finding carries; leave blank (omit the key) if unset. CVE IDs are assigned by a CNA, not drafted — do not fabricate one.

   **`credits[]`.** Omit unless the finding prose explicitly attributes the discovery (e.g. a prior_art reference to a named researcher). Leave empty by default.

4. Write the composed pieces back via the scrutineer API.

   **PATCH the finding** — `PATCH {api_base}/findings/{finding_id}` with `Authorization: Bearer {token}` and JSON body:

   ```json
   {
     "fields": {
       "title": "<summary>",
       "cvss_vector": "CVSS:3.1/...",
       "affected": ">=1.0, <2.3.1",
       "fix_version": "2.3.1",
       "disclosure_draft": "<description markdown>"
     },
     "by": "disclose"
   }
   ```

   Only include fields you want to change. If the finding already had a non-empty `cvss_vector`, `affected`, `fix_version`, or `title`, leave those keys out of the body so the analyst's value is preserved. `disclosure_draft` may be overwritten — a re-run is allowed to produce a fresh draft.

   **POST each reference** — for every URL cited in the description, `POST {api_base}/findings/{finding_id}/references` with:

   ```json
   { "url": "https://...", "tags": "upstream|cwe|prior-art", "summary": "short label" }
   ```

   Before posting, `GET {api_base}/findings/{finding_id}/references` and skip URLs that already exist — re-runs should not create duplicates.

5. Write `./report.json`. The top-level `ghsa` block is the drop-in body for `POST /repos/{owner}/{repo}/security-advisories`; an operator or downstream skill can submit it as-is.

   ```json
   {
     "ghsa": {
       "summary": "...",
       "description": "...",
       "vulnerabilities": [
         {
           "package": { "ecosystem": "go", "name": "example.com/pkg" },
           "vulnerable_version_range": ">= 1.0, < 2.3.1",
           "patched_versions": "2.3.1",
           "vulnerable_functions": ["pkg.Parse"]
         }
       ],
       "cwe_ids": ["CWE-22"],
       "cvss_vector_string": "CVSS:3.1/...",
       "cve_id": null,
       "credits": []
     },
     "patched": ["cvss_vector", "affected", "fix_version", "disclosure_draft"],
     "preserved": ["title"],
     "references_added": 3,
     "references_skipped": 1,
     "notes": "short prose about anything non-obvious: no published packages (source-only advisory), an ambiguous tag range, a missing prior-art link, etc."
   }
   ```

   `ghsa` mirrors the GHSA REST body: every key is drawn from GitHub's repository-advisories schema, so downstream code can POST it without a translation step. `patched` lists fields you actually sent in the PATCH /findings body. `preserved` lists fields you chose not to touch because the analyst had already set them.

## Constraints

- Do not mark the finding as `ready` — lifecycle transitions belong to the analyst. Your output is input for their review, not a replacement for it.
- Do not post communications. `POST /findings/{id}/communications` records maintainer contact, which this skill has not made.
- Do not fabricate a CVE ID, a CWE, a credit, or a vulnerable function name. Every value in the `ghsa` block must be derivable from the finding, the repo, or the packages list.
- Do not emit `severity` and `cvss_vector_string` together — GHSA rejects the pair. Prefer the CVSS vector; use `severity` only when you cannot derive a vector.
- If the finding prose is too thin to draft from (empty Trace, empty Validation), write `{"error": "finding {id} has insufficient prose to draft disclosure"}` to `report.json` and exit 0. Do not PATCH anything.
