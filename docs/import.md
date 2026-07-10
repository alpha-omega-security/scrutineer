# Importing findings from other tools

Scrutineer can ingest vulnerability reports produced by external scanners or written by hand and turn them into the same `Repository`, `Scan`, and `Finding` rows a native scan produces. Imported findings carry through the rest of the workflow unchanged: `verify`, `reachability`, `patch`, `disclose`, and the dedup-on-rescan machinery all treat them as first-class.

The endpoint is `POST /api/v1/import` on the localhost-only `/api/v1` surface, so no bearer token is required and the host-header check applies. The body is sniffed; the format is not in the URL.

## Using it

    curl --data-binary @report.sarif http://127.0.0.1:8080/api/v1/import

The request body is the report itself, up to 16 MiB. The response is JSON:

    {
      "format": "sarif",
      "results": [
        {
          "repository_id": 42,
          "repository":    "https://github.com/example/widget",
          "scan_id":       1024,
          "tool":          "CodeQL",
          "created":       5,
          "observed":      2,
          "finding_ids":   [301, 302, 303, 304, 305]
        }
      ]
    }

`created` counts findings inserted on this call; `observed` counts findings that already existed with the same fingerprint and had their `seen_count` bumped. A SARIF file with several runs, or a CSV grouping rows under several `Repository` slugs, returns one result per repository.

When the report carries no repository (most pentest writeups, the minimal-JSON shape with `repository: ""`), pass `?repo=<https-url>`:

    curl --data-binary @pentest.md "http://127.0.0.1:8080/api/v1/import?repo=https://github.com/example/widget"

`?repo=` always wins over any provenance in the body, so it doubles as an override when a CodeQL run reports the wrong URL.

Each import becomes one `Scan` row per repository with `kind = import` and `skill_name` set to the producing tool's name, so imported findings show up in the scans list alongside native runs and link back to a parent the UI can render. The scan row's `started_at` and `finished_at` are both set to upload time; `status` is `done` immediately.

Re-importing the same report against the same repository upserts: findings with a matching fingerprint update `last_seen_scan_id`, bump `seen_count`, and clear the missed-count counter. Nothing is duplicated and nothing is deleted. Findings that were imported once and not present in a later import simply do not get observed; the existing miss-count machinery is the right tool for "the upstream scanner no longer flags this" and it is left to the operator to run `verify` if they want to confirm.

## Revalidation on import

Each *newly-created* finding is enqueued for a `revalidate` run — the cheap classifier that triages an external tool's unvalidated severity claim and, when it confirms a High/Critical true positive, chains into the heavier `verify`. This runs over every imported finding regardless of severity (a native deep-dive only revalidates its own High/Critical output, but an import's severity is an outside claim worth checking even when it reads Low). Re-observed findings — those matching an existing fingerprint — are left alone, and a revalidate already queued or running for a finding is never double-queued.

A remote repository first seen through an import also gets one repository-scoped `metadata` run. That run clones the source through the normal cache path and populates the repository row, so an imported repository is not left as a URL plus findings until somebody manually verifies one. Reimporting an existing hollow repository repairs it; a completed or in-flight metadata run is never duplicated. This onboarding is independent of `?revalidate=false`, which controls only finding-level classification.

An imported `file://` repository is usable only when that exact local directory exists on the receiving host. If it does not, the import is rejected instead of creating an unusable repository row. Supply `?repo=https://forge/owner/repo` to replace sender-local provenance with a cloneable URL. Reimporting the same old bundle without that override cannot change its embedded repository value.

To import without priming this funnel, pass `?revalidate=false`:

    curl --data-binary @bundle.json "http://127.0.0.1:8080/api/v1/import?revalidate=false"

The findings still land and no finding-level work is enqueued. A remote repository may still receive the single metadata onboarding run described above. The natural use is ingesting findings that have already been through an audit elsewhere — a trusted [sharing bundle](encrypted-sharing.md) arrives carrying the producer's full audit narrative (`boundary`, `validation`, `prior_art`, `reach`, `rating`), so re-running even the cheap classifier on it is redundant spend. The default is `revalidate=true`; a value that is neither `true`/`false` nor `1`/`0` is rejected with `400` rather than silently treated as on, so a caller that meant to disable the funnel is never billed for it by a typo. (The toggle has no effect on the unrecognised-format fallback below: those findings come from the `ingest` skill asynchronously and are not put through the import-time enqueue.)

## Unrecognised formats

A body that matches none of the formats below is not rejected outright. When `?repo=` is supplied, the payload is handed to the `ingest` skill instead: the raw bytes are staged into the skill's workspace at `import/report`, the repository is cloned alongside at `./src`, and the model normalises whatever the report is (a scanner's bespoke JSON, a pentest write-up, a pasted email) into findings, verifying each claimed location against the checkout. The response is `202 Accepted` with the queued `scan_id`:

    {
      "format":        "unrecognised",
      "repository_id": 42,
      "repository":    "https://github.com/example/widget",
      "scan_id":       1031,
      "skill":         "ingest",
      "status":        "queued"
    }

Findings land asynchronously when the scan completes, through the same fingerprint upsert as every skill run. Without `?repo=` there is nothing to clone (an unparseable body has no readable provenance), so the request still fails with `422`. The skill treats the report as untrusted input: its output is schema-validated like any skill report, and instructions embedded in the report body are ignored rather than followed.

## Supported formats

The detector reads the first few bytes of the body and dispatches:

| Format | Detection rule |
|---|---|
| SARIF 2.1.0 | Valid JSON with a top-level `runs` array. |
| Minimal JSON | Valid JSON with a top-level `findings` array. |
| Findings CSV | First row contains the columns `Severity`, `Repository`, `Name`, `Description`. |
| Findings markdown | Body starts with `# `, contains at least one `## ` section, and at least one `**Key:** value` metadata line. |

### SARIF 2.1.0

The format most scanners emit: CodeQL, Semgrep, Snyk, Checkmarx, anything that follows GitHub's code-scanning conventions. Each `runs[]` entry becomes one `Result`. The repository URL is taken from `versionControlProvenance[0].repositoryUri`; the tool name from `tool.driver.name`.

Per-result mapping:

| Scrutineer field | SARIF source |
|---|---|
| `title` | `rule.shortDescription.text`, falling back to `rule.name`, then `result.message.text`, then `ruleId`. |
| `description` | `result.message.text`, falling back to `rule.fullDescription.text`. |
| `severity` | `rule.properties.security-severity` interpreted as a CVSS v3 base score (>=9 critical, >=7 high, >=4 medium, >0 low), falling back to `result.level` (`error` -> high, `warning` -> medium, `note`/`none` -> low). |
| `confidence` | `rule.properties.precision` (`very-high`/`high` -> high, `medium` -> medium, `low` -> low). Empty when absent. |
| `cwe` | First matching `cwe` tag in `rule.properties.tags`. Matches `CWE-79`, `cwe-79`, and `external/cwe/cwe-079`. |
| `location` | `result.locations[0].physicalLocation`: `artifactLocation.uri` plus `region.startLine` (and `startColumn` when present). |
| `suggested_fix` | `result.fixes[0].description.text` when present. |

Severity defaulting in SARIF is deliberately conservative: when the producer left both fields empty, scrutineer stores an empty severity and the UI shows it as such rather than guessing.

### Minimal JSON

A small shape for hand-written pentest reports and tools with no SARIF emitter.

    {
      "repository": "https://github.com/example/widget",
      "commit": "deadbeef",
      "tool": "pentest-2026q2",
      "findings": [
        {
          "title": "Path traversal in download endpoint",
          "cwe": "CWE-22",
          "severity": "critical",
          "confidence": "high",
          "location": "src/handlers/download.js:88",
          "description": "filename parameter is joined to the static root without normalisation.",
          "patch": "--- a/src/handlers/download.js\n+++ b/src/handlers/download.js\n@@\n- const p = path.join(root, req.query.filename)\n+ const p = path.join(root, path.basename(req.query.filename))\n"
        }
      ]
    }

`tool` defaults to `manual` if absent. `title` is the only field worth always supplying; the rest are optional and left empty when missing.

`patch` is folded into the finding's description (the audit trace) rather than written to `suggested_fix`, which is reserved for diffs that have passed the patch-applicability gate — an imported diff is an unverified lead until a `patch` run promotes it. When `fix_commit` is present it is noted alongside the folded diff so a later `patch` run knows the base to rebase onto.

Scrutineer's own encrypted-sharing bundle ([encrypted-sharing.md](encrypted-sharing.md)) is this same shape, enriched with the fields it round-trips between instances. Every bundle adds a per-finding `commit` (falls back to the top-level `commit` when absent), `sub_path`, the full `locations` set, `sinks`, `vid`, `reachability`, `quality_tier`, `fix_commit`, and the audit-narrative fields `boundary`, `validation`, `prior_art`, `reach` and `rating`.

An `include=all` bundle adds the archival superset: `snippet`, `affected`, `fix_version`, `cve_id`, `ghsa_id`, `cvss_vector`/`cvss_v4_vector` (the derived scores are recomputed from the vectors on import, never read from the bundle), `mitigation`/`mitigation_semgrep`, `breaking_change`/`breaking_change_rationale`, `dup_check`, `disclosure_draft`, `exploited_in_wild`/`exploited_in_wild_evidence`, the real `upstream_fix_commit` (its own key, since `fix_commit` already carries the patch base), and the finding's `notes`, `communications`, and `references` child records. On import the child records are attached to the finding; re-importing the same bundle onto a finding that already exists content-dedupes them rather than piling up duplicates.

Hand-written reports may supply any of these, but none are required, and the top-level `generated_at` a bundle carries is ignored on import.

### Findings CSV

The export shape GitHub's code-scanning UI produces, plus close variants. The required columns are `Severity`, `Repository`, `Name`, `Description`; the parser also reads `Status`, `Category`, `File path`, `Line`, `Confidence`, `CWE`, and `Finding URL` when present, and any extra columns are ignored.

Rows whose `Status` column is anything other than `Open` (case-insensitive) are skipped: dismissed and resolved entries are not pulled in. Rows are grouped by `Repository`, so a single CSV with findings against three repos yields three results.

`Repository` is read as either a full URL or a `owner/repo` slug; bare slugs are expanded to `https://github.com/<slug>` since the producer of this export shape is GitHub-only. The tool name is the host of the `Finding URL` column; an export that omits it falls back to the literal string `csv`.

### Findings markdown

The export shape some hosted scanners produce, with one finding per H1 heading followed by an H2 section per fact:

    # Path traversal in download URL

    ## Details
    The download URL generation interpolates parsed components into URL paths...

    ## Location
    [download_url.rb:97](https://github.com/example/widget/blob/main/download_url.rb#L97)

    ## Impact
    ...

    ## Reproduction steps
    1. ...

    ## Recommended fix
    Components that were percent-decoded during parsing must be re-encoded...

    ---
    **Severity:** MEDIUM
    **Status:** Open
    **Category:** Path traversal
    **Repository:** example/widget
    **Branch:** main

`Location` is parsed twice: the link text becomes the `file:line` location, and the link target (when it is a forge blob URL like `https://github.com/owner/repo/blob/...`) yields the repository URL. The `**Repository:**` metadata line is the fallback. `Details`, `Impact`, and `Reproduction steps` are concatenated into `description`; `Recommended fix` becomes `suggested_fix`.

The tool name for markdown imports is the literal string `markdown` since the export format carries no producer field.

## What happens after the upload

The flow is the same regardless of format:

1. **Detect and parse.** `ingest.Parse` sniffs the body, picks a parser, and returns `[]Result`. Each `Result` is one batch of findings against one repository.
2. **Resolve the repository.** `?repo=` if present, otherwise `Result.RepoURL`. The URL is normalised through `ParseRepoInput` (the same path the UI uses) and a `Repository` row is created on first sight.
3. **Create the scan row.** One per `Result`, with `kind = import`, `status = done`, `skill_name = <tool>`, `findings_count = len(findings)`. The scan's `commit` is `Result.Commit` when the format carried one (SARIF `versionControlProvenance`, minimal-JSON `commit`).
4. **Upsert findings.** Each parsed finding is fingerprinted with the tool name in the skill-name slot and its sub-path (`db.FingerprintFinding(tool, sub_path, cwe, location, title)`), then matched against existing rows by `(repository_id, fingerprint)`. The sub-path is empty for every format except scrutineer's own bundle, so their fingerprints are unchanged; carrying it keeps two findings at the same location in different monorepo sub-projects from collapsing onto one fingerprint. Match found: `last_seen_scan_id`, `last_seen_commit`, `seen_count` are updated and a `FindingHistory` row is written. No match: a new `Finding` row is created with `imported_from = <tool>`. Whatever fix an ingest carries — the `suggested_fix` a parser extracted from a SARIF/markdown report, or the minimal/bundle `patch` — is folded into the finding's trace prose, not written to the `suggested_fix` column, which is reserved for diffs a `patch` run has put through the applicability gate. An `include=all` bundle also carries `notes`, `communications` and `references`; these are attached to the finding after it is created (or, on a re-import onto an existing finding, appended only where an identical record does not already exist).
5. **Prime the funnel.** Each newly-created finding is enqueued for `revalidate` (which chains into `verify` on a confirmed High/Critical), unless `?revalidate=false` was passed. See [Revalidation on import](#revalidation-on-import) above.

The full column set is in [database.md](database.md); the `Finding.ImportedFrom` field is what distinguishes imported findings from native ones. The scans index filters on `kind = import` to show only imports, and imported findings appear in the main Findings list by default, alongside audit findings — an import is curated data, not noisy auto-scanner output, so it is not hidden behind the scanners toggle.

## Adding support for a new format

The parser contract is small. Each format implements one function:

    func parseFoo(data []byte) ([]Result, error)

returning one `Result` per repository. The `Result` and `Finding` shapes are in `internal/ingest/ingest.go`; populate what the format gives you and leave the rest empty. The web layer is responsible for normalising severity defaults, choosing a repository when provenance is missing, and creating scan and finding rows; the parser only translates.

Wire the format in two places:

1. **`internal/ingest/ingest.go`**. Add a `Format` constant, a `case` in `detect`, and a `case` in `Parse`. `detect` should match on cheap cues (a top-level JSON key, a magic byte, a header row); it sees the full body but should not parse it twice. Return the new `Format` only on a positive identification, never as a fallback, because the dispatch in `Parse` treats an empty `Format` as `ErrUnrecognised` and a wrong identification produces a misleading error.
2. **`internal/ingest/foo.go`**. Implement `parseFoo`. If detection needs more than a top-level key (a CSV header check, an XML root element), put the helper alongside.

Conventions worth following:

- **Severity vocabulary.** Lowercased: `critical`, `high`, `medium`, `low`, or empty. The CSV parser shows the pattern.
- **CWE format.** `CWE-79`, not `cwe-79` or `CWE-079`. Use `normaliseCWE` in `csv.go`.
- **Location format.** `file:line` or `file:line:column`, relative to the repository root. SARIF's `URI` field is already in this shape.
- **Tool name.** Take it from the report itself wherever possible; the response payload exposes it as `tool` and it becomes `Finding.ImportedFrom`. Falling back to the format name (`csv`, `markdown`) is acceptable when the producer is anonymous.
- **Skipping.** Drop dismissed or withdrawn entries inside the parser; the upsert layer has no way to know they should not exist.
- **Provenance.** When the format carries `commit` set `Result.Commit`; it becomes the scan's commit and the suggested-fix base.

Add a fixture under `internal/ingest/testdata/` and a test in `internal/ingest/ingest_test.go` that calls `Parse` against the fixture and asserts on field-level mapping; the existing SARIF, CSV, and markdown tests are the templates.

CSAF and OSV are intentionally deferred. CSAF round-trips against scrutineer's own export but the inverse is not a straight inversion: `product_status` buckets, VEX flags, and the per-product justifications do not map cleanly onto a single `Finding` row. OSV is closer to a fit but its `affected[]` shape is package-oriented rather than code-oriented, so a sensible Finding `location` field needs a heuristic. Both are worth doing; neither is a mechanical write.
