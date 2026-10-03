# Glossary

These definitions describe terms as they appear in Scrutineer's interface and reports. The [ecosyste.ms glossary](https://docs.ecosyste.ms/docs/guides/glossary/) covers the wider package and repository terminology.

## Repositories and packages

| Term | Meaning |
| --- | --- |
| Dependency | A package the scanned project uses. A direct dependency is declared by the project; a transitive dependency is brought in through another dependency. |
| Dependent (reverse dependency) | A package or repository that uses the scanned project's packages. If application A uses library B, B is A's dependency and A is B's dependent. |
| Ecosystem | A package-management family, such as npm, RubyGems, or PyPI. |
| Forge | A service hosting Git repositories, such as GitHub or GitLab. |
| Lockfile | A file recording resolved dependency versions. Scrutineer's dependency inventory reads these alongside manifests. |
| Maintainer | A person responsible for the project or its packages. Scrutineer's `maintainers` skill combines repository activity and registry ownership to identify people to contact about findings. |
| Manifest | A file declaring package metadata or dependencies, such as `package.json` or `go.mod`. |
| Monorepo | A repository containing several packages or projects. Scrutineer can discover and scan its subprojects separately. |
| Owner | The user or organisation account under which a repository is hosted. The owner account and the people responsible for security reports may differ. |
| Package | A named unit of software distributed through a registry. One repository can produce several packages. |
| Package URL (PURL) | A structured package identifier containing an ecosystem and package name, with optional version and other qualifiers. Scrutineer uses PURLs to identify packages across imports and exports. |
| Ref / commit | A scan's ref selects a branch, tag, or commit. The recorded commit identifies the exact source snapshot scanned. |
| Registry | A service that publishes and distributes packages. |
| Repository (repo) | The source tree added to Scrutineer by Git URL or local directory path. Findings and scans belong to a repository. |
| Subproject / subpath | A package or component within a repository, and its directory relative to the repository root. A subpath such as `packages/core` limits a scan to that directory and associates its findings with that part of the repository. |
| Upstream / downstream | Upstream supplies the code or package; downstream consumes it. A finding in a library can affect several downstream applications. |

## Scanning

| Term | Meaning |
| --- | --- |
| Baseline scan | An earlier scan used for comparison. A diff rescan compares its baseline commit with the current commit; fix validation compares findings against a selected baseline. |
| Coverage / completeness | The recorded scope and evidence of what a scan reviewed. Completeness is `complete`, `partial`, or `unknown`, assessed by the worker against the scope it can check. A `done` scan can have partial or unknown coverage; complete coverage does not establish that the code has no vulnerabilities. See [diff-based rescans](diff-based-rescans.md#coverage-metadata). |
| Diff rescan | A scan focused on changes since a compatible baseline. It can fall back to a full scan when the baseline or diff is unsuitable. |
| Exploratory audit | An extra deep-dive scan used to check for gaps in the planned audits. A **random dig** reviews a selected source directory without prior scan guidance; an **adversarial sweep** challenges a threat-model exclusion. See [exploratory audits](exploratory-audits.md). |
| Focus area | A part of the project that handles outside input, such as a parser or upload handler, together with the paths to its code. Each focus area can receive its own deep-dive scan. |
| Full scan | A scan of the skill's normal repository or subproject scope, without restricting analysis to a commit diff. Path exclusions still apply. |
| Pipeline | The related skill runs started to analyse a repository. The `triage` skill starts the default pipeline; later results can queue further scans. |
| Recon | Short for reconnaissance. The `recon` skill identifies where a project handles outside input and groups that code into focus areas for later audits. |
| Report / transcript | A report is a scan's output, often structured JSON parsed into application records. A transcript records the agent's messages and tool activity during execution. |
| Scan (run, job) | One recorded execution of a skill. Scans have their own status, scope, report, and usage. Imports and skipped scheduled runs also create scan records. |
| Scan group | A shared identifier for scans launched as one batch. Related scans can use it to read each other's findings and avoid reporting the same issue twice. |
| Skill | A reusable scan recipe with instructions and settings. It can include scripts and a schema defining the expected report format. Skills can run command-line tools or use a model; see [skills](skills.md). |
| Triage | In the pipeline, `triage` selects and queues skills. In the finding workflow, triage is the analyst's review of whether a finding is valid and what to do with it. |

## Security analysis and evidence

| Term | Meaning |
| --- | --- |
| Advisory | A security notice describing a vulnerability and affected software. Scrutineer's Advisories view contains known advisories fetched for the project's packages; an individual finding can also be exported as an advisory document. |
| Attack path / attack tree | An attack path describes how an attacker can cause harm and what access or conditions they need. Verification records an attack tree with evidence for reachable, blocked, or unproven steps. |
| Attack surface / entry point | The interfaces through which input enters a project, and a particular interface such as an HTTP route, CLI argument, or public parser function. |
| Confidence | The reported certainty of a finding, recorded as high, medium, or low. A high-confidence finding can still have low severity. |
| CWE | Common Weakness Enumeration: identifiers for kinds of defect, such as injection or access-control failure. |
| Exposure / reachability | Whether a consumer's code can reach a vulnerable operation under the relevant conditions. `reachability` examines a scanned application's dependencies; `exposure` assesses one finding against one dependent. |
| Finding | A potential vulnerability recorded by a scan or import, with evidence and a review status. Findings need review before they can be treated as confirmed. |
| Fingerprint | Scrutineer's key for deduplicating repeated findings within a repository. It uses the producing skill, subpath, weakness class, and file location, with the title included when no CWE is present. Line-number changes alone do not create a new fingerprint. |
| Not seen / missed count | A finding did not reappear in a compatible full rescan. The cause could be a fix or variation in model output, so a missing finding still needs investigation. |
| Novelty | Whether the reported issue remains unfixed upstream: `unfixed`, `fixed`, `unclear`, or `not_checked`. This is separate from the finding's review lifecycle. |
| Proof of concept (PoC) / reproduction | Input, code, or commands intended to demonstrate the claimed failure. Verification checks whether the reproduction reaches the project's code and produces the claimed result. |
| Provenance | The origin of a field value or change: `tool`, `model_suggested`, `analyst`, or `system`. Finding history records changes so reviewers can distinguish model output from analyst decisions. |
| Revalidation | The `revalidate` skill's read-only classification using the finding, source, and history. Its verdict is `true_positive`, `false_positive`, `already_fixed`, or `uncertain`; it does not execute the reproduction. |
| Release viability | The `critic` skill's assessment of whether a finding can affect a real release build. Results are `VIABLE`, `NON_VIABLE`, `SAMPLE_OR_TEST`, or `CONDITIONAL_VIABLE`. An exact `NON_VIABLE` result blocks disclosure actions. |
| Severity / CVSS | Severity describes the impact and conditions of a vulnerability, using Critical, High, Medium, or Low for deep-dive findings. The Common Vulnerability Scoring System (CVSS) calculates a numerical score from metrics such as required access and impact. Its vector is the text string recording those metric values. |
| Sink | An operation where attacker-controlled input could cause harm, such as command execution, a database query, or a file write. A sink inventory is a list of audit candidates; each candidate still needs an attack path and evidence. |
| Threat model / security contract | A description of what a project protects, the attacks it is designed to resist, and the responsibilities left to its users. Scrutineer stores the supporting code and documentation evidence, along with open questions, for use in later audits. |
| Trust boundary | A point where input crosses between different permissions or levels of control, such as an unauthenticated request entering application code. |
| Verification | The `verify` skill's check of a finding against current code, including three reproduction attempts graded against fixed criteria. Results are `confirmed`, `fixed`, `inconclusive`, `deferred`, or `not_attempted`. These results are separate from lifecycle status. |
| VID | A hash identifying the function or file bytes at a finding's location. It lets different tools identify the same code and changes when those bytes change. Scrutineer uses the fingerprint to identify repeated findings. |

## Review, fixes, and disclosure

| Term | Meaning |
| --- | --- |
| Audit queue | A sample of classifier decisions for an analyst to check, including low-severity and false-positive results. Here, "audit" means reviewing those decisions. |
| CNA | CVE Numbering Authority: an organisation authorised to assign CVE identifiers within its scope. The `cna-match` skill identifies a suitable authority for a repository. |
| CVE / GHSA | Identifiers for vulnerability records: Common Vulnerabilities and Exposures and GitHub Security Advisories. These identify particular records; CWE identifies a weakness class. |
| Disclosure / disclosure channel | Reporting a vulnerability to a maintainer or coordinator, and the contact route used. The `disclose` skill prepares a draft; sending it is a separate workflow action. |
| Health | The repository's maintenance classification: `active`, `stale`, `abandoned`, or `zombie`, derived from activity and maintainer evidence. |
| Lifecycle | The finding's workflow status: `new`, `enriched`, `triaged`, `ready`, `reported`, `acknowledged`, `fixed`, `published`, `rejected`, or `duplicate`. In particular, `enriched` means verification ran, `triaged` records confirmation, and `ready` means a disclosure draft is prepared. See the [finding workflow](../README.md#finding-workflow). |
| Mitigation / workaround | A measure that reduces exposure while a code fix is unavailable, such as disabling an affected feature. The `mitigate` skill records this guidance separately from the suggested patch. |
| Posture | Readiness to receive and handle a vulnerability report, classified as `ready`, `partial`, or `unprepared`. Evidence includes a security policy and an available reporting channel. |
| Private vulnerability reporting (PVR) | GitHub's private reporting route for sending a vulnerability to repository maintainers. See [disclosure fallback](disclosure-fallback.md) for other routes. |
| Re-attack | An independent test of a saved patch using variations of the original attack and harmless input that should still work. Results are `failed_to_bypass`, `bypassed_patch`, or `inconclusive`; the result applies to the tested patch and inputs. |
| Remediation attempt | A numbered patch saved with the commit it applies to. Each attempt is kept unchanged for later testing. It must pass checks that it applies cleanly before being saved, but still needs testing to establish whether it fixes the vulnerability. |
| Resolution | How a finding was addressed: `fix`, `migrate`, `workaround`, `adopt`, or `wontfix`. This is recorded separately from lifecycle status. |
| Shipped fix | A fix included in an upstream release. `release-watch` records release evidence separately from a fix commit or the finding's `fixed` lifecycle status. |

## Execution and interchange

| Term | Meaning |
| --- | --- |
| Backend / harness | The agent command-line program used to run work with a model, such as Claude Code, Codex, OpenCode, or Copilot. |
| Container runtime / runner profile | The runtime launches scan containers. A runner profile supplies the language tools and system dependencies available inside a scan's container. |
| Egress policy | Rules controlling outbound network access from a scan, including allowed destinations. See [egress policies](egress-policies.md). |
| Federation / claim-check | Exchange between separate Scrutineer installations. Before reporting a finding, a claim-check asks the other installations whether they already have it, so reporters can coordinate without sharing the vulnerability details. See [interchange](interchange.md). |
| OSV / CSAF | Open Source Vulnerability and Common Security Advisory Framework: structured advisory formats available as finding exports. |
| SARIF | Static Analysis Results Interchange Format: a format for tool findings that Scrutineer can [import](import.md). |
| SBOM | Software Bill of Materials: an inventory of software components and dependencies. Scrutineer accepts CycloneDX and SPDX SBOMs for import and can generate a CycloneDX SBOM for a repository. |
| Worker / workspace | The worker executes queued scans. A workspace contains the source copy, skill, context, and output files staged for one execution. |
