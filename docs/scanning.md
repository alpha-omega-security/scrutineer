# Scanning repositories

Click **Add repository** in the sidebar, paste a git HTTPS URL, and scrutineer enqueues the `triage` skill. To scan a maintained branch instead of the default, fill the **Branch** field (it suggests the remote's branches as you type and also accepts a tag or commit), or append a `/tree/<branch>` suffix to the URL; the suffix also works one-per-line when bulk-importing. Triage then enqueues the rest of the pipeline: independent skills run in parallel, and the deep-dive audits start once `threat-model` completes. Open the repo page and switch to the Scans tab to watch progress, or wait for the Findings tab to fill in.

The `triage` skill selects the scan set for the repository. See [skills.md](skills.md#bundled-skills) for the bundled skills and how to change the pipeline, and [diff-based-rescans.md](diff-based-rescans.md) for scanning changes since an earlier scan.

## Monorepos

To scan one package inside a monorepo, append `#<sub/dir>` to the URL -- e.g. `https://github.com/rails/rails#activesupport` (or paste a `.../tree/<branch>/<sub/dir>` URL). Scrutineer scopes the whole pipeline to that sub-folder and gives the sub-package its own page, findings, packages, advisories, disclosure channel, and export, instead of rolling every package up under the repository. By default a sub-package scan is confined to its own sub-folder (siblings pruned, `.git` kept), widening to the whole repository automatically if the sub-package cannot resolve its dependencies in isolation; set `subproject_scope: soft` to always scan against the whole tree, or `monorepo_attribution: false` to keep registry data repo-wide (see [`scrutineer.sample.yaml`](../scrutineer.sample.yaml)). The `subprojects` skill also auto-discovers a monorepo's sub-packages, so you can scan them from the repo page without composing URLs by hand. Findings, packages, advisories, the disclosure channel, and export are attributed per sub-package; dependents, maintainers, posture, and health stay repo-wide. There is no per-sub-package schedule -- to re-scan sub-packages on a cadence, drive the local API from cron or a systemd timer (see [`scripts/rescan-subprojects.sh`](../scripts/rescan-subprojects.sh)).

## Importing an organisation

To onboard a whole GitHub org at once, open **Add multiple** → **Import a whole org** and enter the org (or user) login. Scrutineer fetches every repository and queues each one with the default scan set, skipping forks, archived repos (unless you opt in), and any URL already in the database. Set `GITHUB_TOKEN` to raise GitHub's unauthenticated rate limit when importing large orgs.

## Local directories

You can also scan a directory on disk, useful before pushing, or for code not hosted on a git forge. Paste an absolute path (`/path/to/project`) in the same **Add repository** field. Scrutineer copies the directory into a per-scan workspace and runs the default skill set; skills that need a forge URL or ecosyste.ms enrichment (`advisories`, `exposure`, `fork`, `maintainers`, `metadata`, `packages`, `public-issue`, `report-upstream`) are skipped automatically. Symlinks are recreated as-is rather than dereferenced during the copy; in container mode their targets then resolve inside the container, so host files reached only through such a link are not visible to skills. Under `--no-container`, and for the skills listed in `host_skills`, the kernel dereferences them normally, so only point scrutineer at trees you trust.

## Investigating a report

To check a research lead, choose **Investigate a report** in the sidebar, enter the repository URL and paste the report. An optional branch, tag or commit selects the revision to check. This queues one focused investigation without the default scan pipeline. The scan retains the submitted text and records an assessment of each claim, with zero or more findings. Reproduced behaviour with unestablished security impact remains inconclusive; new High/Critical findings enter the existing revalidation workflow.

## Scan results

- **Structured findings** -- vulnerability reports parsed into a database with severity, CWE, location (linked to source), affected versions, and a six-step analysis trace
- **Threat model view** -- the project's security contract (components, entry-point trust table, properties provided and disclaimed, known non-findings) rendered from the `threat-model` scan, falling back to the deep-dive's boundaries and sink inventory on older repositories
- **Dependency exploration** -- dependency and dependent tables with one-click import to scan any package's source repository
- **Package registry data** -- downloads, dependents, versions, and registry links for every published package
- **Known advisories** -- existing CVEs and security advisories pulled automatically
- **Maintainer identification** -- model-backed skill combining commit history, issue/PR activity, and registry ownership to identify who to contact for disclosure
- **CWE catalogue** -- embedded MITRE CWE data with tooltips on finding tables and full descriptions on finding pages
- **Reachability analysis** -- trace sinks found in dependencies through application code to see which are actually reachable
- **Rescan dedup** -- findings carry a content fingerprint so re-running a scan updates existing rows instead of creating duplicates; same-fingerprint hits within one scan collapse to a single finding with a `+N` expandable location list, and findings that stop appearing are marked "not seen" with a miss count

## Navigating the UI

Every index page has a search box plus filter and sort dropdowns; the specifics vary by page. The sidebar groups its pages under Work, Inventory, Insights and Configuration, in this order:

- **Findings** -- every vulnerability across all repos. A finding page shows where the finding stands on its lifecycle, its scoring fields and the next step, then groups the rest into Analysis (the six-step analysis: trace, boundary, validation, prior art, reach, rating, plus observations and verification history), Remediation, Disclosure (draft, fields, communications log, references) and Activity (notes, reviews, labels, change history, chat) tabs.
- **Scans** -- every scan that has run. Queued scans can be paused/resumed, running or queued scans can be cancelled and failed ones retried.
- **Audit** -- random sample of recent low and false-positive verdicts for spot-checking the cheap-classifier output. Each row records the analyst's agreement-or-overturn verdict, and a small dashboard shows the running overturn rate.
- **Repositories** -- your scanned repos with language, last-scan status, and finding counts. Click into one for tabs covering Summary, Findings, Threat Model, Compliance, Packages, Dependencies, Dependents, Advisories, Maintainers, Data, Scans, and Chat, plus "Export report" in the header's More menu for a markdown rollup.
- **Organizations** -- repos, findings, and maintainers grouped by owning org, with per-org markdown exports.
- **Packages** -- registry entries discovered across all repos.
- **SBOMs** -- uploaded CycloneDX/SPDX documents. Each component is resolved to a source repository and can be imported for scanning.
- **Advisories** -- known CVEs and security advisories pulled for any scanned package.
- **Maintainers** -- people identified as maintainers, with their linked repos and findings.
- **Reporting** -- corpus-wide activity over a rolling window (24 hours, 7 days, 30 days, or all time) with a minimum-severity floor on findings: repositories scanned, runs started and completed, findings, a per-day breakdown, and the per-scan cost and token averages beside their all-time figures. Downloadable as CSV or JSON; JSON exports pulled from several discrete scanner instances can be combined into one corpus-wide report with `go run ./scripts/merge-reports a/report.json b/report.json`; see [docs/reporting.md](reporting.md).
- **Usage** -- token and cost totals across all scans, broken down by skill.
- **Skills** -- installed skills from disk and from the UI; view, edit, or run any of them.
- **Settings** -- theme, colour scheme, model tiers, runner concurrency (restarts the runner to apply, cancelling in-flight scans) and default turn cap (applied to the next scan), plus system stats (record counts, DB size, paths). The chat pool is sized at half the concurrency the server started with and is not resized here, so a change only takes effect for chat after a restart.

Scan logs and status changes stream through SSE. The Scans page, repositories list and a repository's Scans tab refresh their tables when scans start, finish, are cancelled, paused, resumed or queued, while preserving scroll position, filters and sort order. Elapsed times update in the browser. Settings also provides six colour themes and a light/dark/system toggle.

## Finding workflow

Each finding from the `security-deep-dive` skill starts at **new** and moves through a guided workflow:

1. **new** -- just identified. High/Critical from `security-deep-dive` and every imported finding auto-enqueue a `revalidate` pass first, which records `true_positive` / `false_positive` / `already_fixed` / `uncertain` on the finding. Every true positive chains into the release-build `critic`; High/Critical true positives also chain into `verify`. Outside that path: click "Run verification" to start independent confirmation using model tokens, "Mark triaged" if you have already verified it independently, or "Reject"
2. **enriched** -- verification confirmed it, or revalidation classed it as a true positive. Review and click "Mark triaged" to save your decision
3. **triaged** -- confirmed real. Review the critic's release-build assessment, then click "Draft disclosure" (a model scan) to generate the draft. An exact `NON_VIABLE` assessment blocks private disclosure, public issues, and upstream reporting; `VIABLE`, `SAMPLE_OR_TEST`, `CONDITIONAL_VIABLE`, and unassessed findings remain analyst decisions
4. **ready** -- draft prepared. Run the `report-upstream` skill to file it via GitHub PVR (github.com only, requires `gh` auth), run `public-issue` for reviewed low-severity hardening findings that are safe to file publicly, or click "Mark as reported" after sending it yourself. When upstream has no PVR, follow the runbook in [docs/disclosure-fallback.md](disclosure-fallback.md): route to a CNA when `cna-match` names one, otherwise contact the channel `maintainers` returned. With `federation_peers` configured, every route out of this state (the button, the `report-upstream` and `public-issue` skills, and the VINCE submission) first asks each peer whether it already holds the same finding and, on a match, names their contact so you coordinate before proceeding (see [docs/interchange.md](interchange.md))
5. **reported** -- sent to maintainer. Click "Acknowledged" when they respond
6. **acknowledged** -- maintainer working on fix. Click "Mark fixed" when it ships
7. **fixed** -- patch available. Click "Mark published" to issue the advisory
8. **published** -- done

When upstream has already fixed the issue, click "Fixed upstream" from any status before **acknowledged** to jump straight to **fixed** without generating or sending a report.

- **Exploited-in-the-wild flag** -- analyst-only `yes`/`no` field on findings with free-text evidence, surfaced on the finding page, in the OSV `database_specific` block, in CSAF audit notes, and in markdown report exports
- **Breaking-change classifier** -- the `breaking-change` skill runs over a suggested-fix diff plus the top dependents, recording `breaking` / `non_breaking` / `unknown` with a rationale and the list of affected dependents
- **Mitigation guidance** -- the `mitigate` skill drafts short-term workarounds and an optional semgrep rule per finding, separate from the code fix
- **CVSS v3.1 and v4.0** -- both vectors stored side by side with derived scores; analyst form, OSV/CSAF exports, and the `disclose` skill all carry both forward, with the v4 metric set kept distinct from v3
- **Release watch** -- the `release-watch` skill closes the gap between fix-landed and fix-shipped: once a finding reaches `fixed`, the skill polls upstream releases and records the release tag, URL, and timestamp when it appears
- **CNA matching** -- identify the CVE Numbering Authority whose scope covers a repo so disclosures go to the right contact

A PVR report is hard to unsend; before pointing this at an external repository, run it once end-to-end against a repository you control with PVR enabled to confirm the body shape and patch attachment land the way you expect.

Each finding page has a notes section for recording triage reasoning and communication history.

### Federation opt-out

The repository page carries a Federation opt-out control: recording one cancels the repository's queued, running and paused scans, then refuses every new scan on it, including scheduled runs and automatic follow-ups. It also withdraws the repository from the interchange feeds, and, when the public feed is configured, publishes the request so other federated instances honour it too; an opt-out arriving on a peer feed sets it here the same way. See [docs/interchange.md](interchange.md).

### Chat

The Chat tab on a repository or a finding opens a read-only conversation with the agent about that code: it works from a copy of the clone plus a snapshot of the findings, and is restricted to reading and searching, so it can explain and cross-check but never modify anything. Each conversation keeps its own working copy on disk, so delete the ones you are done with from the conversation page to reclaim the space.

### Patches and re-attack

A `patch` run whose diff survives the applicability gate (the diff parses, targets files that exist, touches the flagged file, and passes `git apply --check`) creates an immutable numbered remediation attempt and updates the finding's `suggested_fix` projection. The current diff is downloadable from the finding page as a `.patch` file and included in markdown report exports. To iterate on your own edits, push them to a branch, scan that branch, then run `patch` against the new scan. `Re-attack patch` checks out an attempt's exact base commit, applies its exact diff, and independently exercises at least three distinct root-cause variants plus a benign control. Only a complete `failed_to_bypass` result derives `verified_secure`; a same-class, same-sink bypass is retained as evidence and staged for later patch attempts, while missing or inconsistent evidence remains `verification_incomplete`. Earlier attempts and bypass evidence remain immutable.

## Exploring dependencies

The Dependencies tab on a repo groups packages by name and shows all manifest files where each appears. It shows runtime dependencies by default, with a toggle for test/build/dev rows. The import button (arrow icon) next to a dependency resolves it to a repository URL via packages.ecosyste.ms and queues the full pipeline for it. Dependencies you've already imported show a link icon instead.

The same applies to the Dependents tab -- you can import any dependent's repository with one click.

## Imports and exports

- **SBOM import** -- upload a CycloneDX or SPDX document, resolve each component to a source repository, and queue scans automatically
- **Finding import** -- POST SARIF, CSV, markdown, or minimal-JSON findings from external scanners and pentest reports into the same workflow as native scans, with fingerprint dedup against re-imports
- **Free-form ingest** -- when the format sniffer in `/api/v1/import` cannot place a payload, the `ingest` skill normalises it against the source checkout (resolving locations) before it enters the findings table
- **CSAF export** -- download any finding as a schema-validated CSAF 2.0 advisory document
- **OSV export** -- download any finding as a schema-validated OSV record, aligned with the OSS-SIRT advisory template (credits, CWE IDs, withdrawn, SEMVER ranges, CVSS v3 + v4 severity entries)
- **JSONL export** -- stream all findings or scans as line-delimited JSON for ingestion elsewhere
- **Markdown report export** -- download a single consolidated `report.md` per repository or organisation
- **Disclosure bundle** -- download `bundle.tar.gz` per finding: OSV, CSAF, markdown report, patch.diff, a runnable `poc/` directory extracted from the finding's Validation step, and a manifest naming the contents; ready to hand to a coordinator or attach to a private email when filing outside GitHub PVR
- **CERT/CC VINCE submission** -- map a reviewed disclosure into VINCE's authenticated vulnerability-report form, review every field and attachment, then send one multipart request and record the returned VRF ID. The action requires a config-file API key; see [docs/disclosure-fallback.md](disclosure-fallback.md#submit-to-certcc-vince)
- **Encrypted sharing / archival bundle** -- export a repository's findings as a self-contained JSON bundle that round-trips through `/api/v1/import`, optionally age-encrypted to your team's keys. The default bundle is share-safe (finding substance only); `include=all` produces a lossless archival superset -- enrichment, disclosure fields, notes, communications, and references -- for backing up or moving a repo's findings between your own instances. See [docs/encrypted-sharing.md](encrypted-sharing.md)

Scrutineer can ingest findings produced elsewhere so they enter the same triage and disclosure workflow:

    curl -H "Authorization: Bearer $(cat data/operator-token)" --data-binary @report.sarif http://127.0.0.1:8080/api/v1/import

SARIF 2.1.0, CSV, markdown, and a minimal JSON shape are all accepted; the format is sniffed from the body. See [docs/import.md](import.md) for the full request and response shape, the per-format field mapping, and how to add support for a new format.
