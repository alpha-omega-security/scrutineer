# Changelog

Entries are grouped by release, newest first. Each entry is a summary written for people who fund and direct the work rather than a full commit list; see the git log for that.

## Unreleased

- Scans can be scheduled to repeat automatically and are skipped when the code has not changed since the last run. ([#633](https://github.com/alpha-omega-security/scrutineer/pull/633), [@alexandre-daubois](https://github.com/alexandre-daubois))
- Large repositories can be split into named focus areas that are audited in parallel, each with its own report and coverage record. ([#625](https://github.com/alpha-omega-security/scrutineer/pull/625) [#652](https://github.com/alpha-omega-security/scrutineer/pull/652) [#653](https://github.com/alpha-omega-security/scrutineer/pull/653) [#673](https://github.com/alpha-omega-security/scrutineer/pull/673), [@abhinavgautam01](https://github.com/abhinavgautam01))
- Added a forensics mode that investigates a suspected account or release compromise and produces a cited evidence timeline without touching the repository. ([#643](https://github.com/alpha-omega-security/scrutineer/pull/643), [@abhinavgautam01](https://github.com/abhinavgautam01))
- Added a variant search that, once a vulnerability is confirmed, checks the rest of the repository for other places the same flaw appears. ([#686](https://github.com/alpha-omega-security/scrutineer/pull/686), [@abhinavgautam01](https://github.com/abhinavgautam01))
- The security audit now checks for mass-assignment and for authentication controls that fail open when an input is left out. ([#664](https://github.com/alpha-omega-security/scrutineer/pull/664) [#672](https://github.com/alpha-omega-security/scrutineer/pull/672), [@abhinavgautam01](https://github.com/abhinavgautam01))
- The evaluation suite can now use an AI model to grade results, so scoring no longer depends on exact wording. ([#685](https://github.com/alpha-omega-security/scrutineer/pull/685), [@abhinavgautam01](https://github.com/abhinavgautam01))
- Swift projects are now supported. ([#650](https://github.com/alpha-omega-security/scrutineer/pull/650), [@andrew](https://github.com/andrew))
- Hardened the scanner against repositories crafted to influence their own results or reach into the operator's network, and added an audit log of scan actions. ([#665](https://github.com/alpha-omega-security/scrutineer/pull/665) [#667](https://github.com/alpha-omega-security/scrutineer/pull/667) [#668](https://github.com/alpha-omega-security/scrutineer/pull/668) [#670](https://github.com/alpha-omega-security/scrutineer/pull/670), [@abhinavgautam01](https://github.com/abhinavgautam01), [@p-linnane](https://github.com/p-linnane))
- Fetching a repository now retries after a brief network failure instead of abandoning the scan. ([#682](https://github.com/alpha-omega-security/scrutineer/pull/682), [@snowyukitty](https://github.com/snowyukitty))
- Releases are now cut automatically every two weeks. ([#666](https://github.com/alpha-omega-security/scrutineer/pull/666), [@p-linnane](https://github.com/p-linnane))

## 2026-07-14

- First packaged release: Scrutineer now ships as a standalone binary with everything needed to run a scan bundled in. ([#631](https://github.com/alpha-omega-security/scrutineer/pull/631), [@p-linnane](https://github.com/p-linnane))
- Scans can now be driven by OpenAI Codex or opencode as alternatives to Claude, so operators are not tied to one AI vendor. ([#535](https://github.com/alpha-omega-security/scrutineer/pull/535) [#536](https://github.com/alpha-omega-security/scrutineer/pull/536), [@andrew](https://github.com/andrew))
- Added an evaluation suite that runs the auditor against repositories with known planted vulnerabilities and scores what it catches and what it wrongly flags. ([#590](https://github.com/alpha-omega-security/scrutineer/pull/590) [#616](https://github.com/alpha-omega-security/scrutineer/pull/616), [@abhinavgautam01](https://github.com/abhinavgautam01))
- Rescanning a repository now examines only the code that changed since the last run, cutting the cost of keeping results current. ([#602](https://github.com/alpha-omega-security/scrutineer/pull/602), [@andrew](https://github.com/andrew))
- New audit that re-reads a project's past security advisories and checks whether the published fixes were complete or can be bypassed. ([#556](https://github.com/alpha-omega-security/scrutineer/pull/556), [@alexandre-daubois](https://github.com/alexandre-daubois))
- Perl projects and Ruby native extensions are now supported. ([#527](https://github.com/alpha-omega-security/scrutineer/pull/527), [@andrew](https://github.com/andrew); [#546](https://github.com/alpha-omega-security/scrutineer/pull/546) [#554](https://github.com/alpha-omega-security/scrutineer/pull/554), [@dkw-oss](https://github.com/dkw-oss))
- Disclosure packages sent to maintainers now include a runnable proof of concept and record how each finding was originally discovered. ([#610](https://github.com/alpha-omega-security/scrutineer/pull/610) [#612](https://github.com/alpha-omega-security/scrutineer/pull/612), [@andrew](https://github.com/andrew))
- Hardened against prompt injection: instruction files planted in a target repository are stripped before analysis, and audits treat all repository content as data rather than directions. ([#604](https://github.com/alpha-omega-security/scrutineer/pull/604) [#608](https://github.com/alpha-omega-security/scrutineer/pull/608), [@andrew](https://github.com/andrew))

## 2026-06-29

- Added dedicated runners for Node.js, Python, Go, Java, .NET, C/C++, and Erlang/Elixir so audits can build, test, and instrument code in each of those ecosystems. ([#430](https://github.com/alpha-omega-security/scrutineer/pull/430) [#431](https://github.com/alpha-omega-security/scrutineer/pull/431) [#433](https://github.com/alpha-omega-security/scrutineer/pull/433) [#434](https://github.com/alpha-omega-security/scrutineer/pull/434) [#435](https://github.com/alpha-omega-security/scrutineer/pull/435) [#437](https://github.com/alpha-omega-security/scrutineer/pull/437) [#438](https://github.com/alpha-omega-security/scrutineer/pull/438) [#459](https://github.com/alpha-omega-security/scrutineer/pull/459), [@andrew](https://github.com/andrew))
- Rust projects are now supported. ([#351](https://github.com/alpha-omega-security/scrutineer/pull/351), [@walterhpearce](https://github.com/walterhpearce))
- Scans can run under Podman (including rootless setups) and Apple's container runtime as well as Docker. ([#492](https://github.com/alpha-omega-security/scrutineer/pull/492), [@dkw-oss](https://github.com/dkw-oss); [#513](https://github.com/alpha-omega-security/scrutineer/pull/513), [@p-linnane](https://github.com/p-linnane))
- Findings can be exported as an encrypted bundle for secure hand-off between separate installations. ([#397](https://github.com/alpha-omega-security/scrutineer/pull/397), [@dkw-oss](https://github.com/dkw-oss))
- New validation step that re-tests a proposed patch against the original finding before it is offered to a maintainer. ([#490](https://github.com/alpha-omega-security/scrutineer/pull/490) [#493](https://github.com/alpha-omega-security/scrutineer/pull/493), [@alexandre-daubois](https://github.com/alexandre-daubois))
- Every repository in a GitHub organisation can be imported in one action. ([#394](https://github.com/alpha-omega-security/scrutineer/pull/394), [@connorshea](https://github.com/connorshea))
- Added a workbench for editing a repository's threat model between audit runs. ([#267](https://github.com/alpha-omega-security/scrutineer/pull/267), [@andrew](https://github.com/andrew))

## 2026-06-15

- Added an analyst review queue with structured accept/reject verdicts, so every AI-produced finding is checked by a person before it goes further. ([#378](https://github.com/alpha-omega-security/scrutineer/pull/378), [@andrew](https://github.com/andrew))
- Findings export in the standard OSV and CSAF advisory formats and carry CVSS v4.0 scores. ([#327](https://github.com/alpha-omega-security/scrutineer/pull/327), [@alexandre-daubois](https://github.com/alexandre-daubois); [#383](https://github.com/alpha-omega-security/scrutineer/pull/383) [#384](https://github.com/alpha-omega-security/scrutineer/pull/384), [@andrew](https://github.com/andrew))
- New quick re-check pass filters obvious false positives before an expensive full verification is queued. ([#375](https://github.com/alpha-omega-security/scrutineer/pull/375) [#376](https://github.com/alpha-omega-security/scrutineer/pull/376), [@andrew](https://github.com/andrew))
- Added checks that classify whether a proposed fix would break existing callers and whether the maintainer has shipped a fixed release. ([#379](https://github.com/alpha-omega-security/scrutineer/pull/379) [#385](https://github.com/alpha-omega-security/scrutineer/pull/385), [@andrew](https://github.com/andrew))
- Added a mitigation mode that produces operational workarounds and detection rules when a finding cannot be patched immediately. ([#381](https://github.com/alpha-omega-security/scrutineer/pull/381), [@andrew](https://github.com/andrew))
- Any branch or tag of a repository can be scanned, not only the default branch. ([#303](https://github.com/alpha-omega-security/scrutineer/pull/303), [@alexandre-daubois](https://github.com/alexandre-daubois))

## 2026-06-01

- Hardened isolation mode: scans run with outbound network access limited to an allowlist, inside single-use container networks. ([#274](https://github.com/alpha-omega-security/scrutineer/pull/274) [#277](https://github.com/alpha-omega-security/scrutineer/pull/277), [@alexandre-daubois](https://github.com/alexandre-daubois))
- First language-specific runner (Ruby) and the profile machinery to add more. ([#259](https://github.com/alpha-omega-security/scrutineer/pull/259), [@alexandre-daubois](https://github.com/alexandre-daubois); [#279](https://github.com/alpha-omega-security/scrutineer/pull/279), [@connorshea](https://github.com/connorshea))
- Local directories can be scanned without needing a hosted git repository. ([#242](https://github.com/alpha-omega-security/scrutineer/pull/242), [@alexandre-daubois](https://github.com/alexandre-daubois))
- ARM machines are supported. ([#304](https://github.com/alpha-omega-security/scrutineer/pull/304), [@alexandre-daubois](https://github.com/alexandre-daubois))
- In-browser code viewer for jumping straight from a finding to the source line it cites. ([#232](https://github.com/alpha-omega-security/scrutineer/pull/232), [@alexandre-daubois](https://github.com/alexandre-daubois))
- Failed scans resume from where they stopped instead of restarting from the beginning. ([#301](https://github.com/alpha-omega-security/scrutineer/pull/301), [@connorshea](https://github.com/connorshea))

## 2026-05-18

- Each repository now gets a written threat model describing its trust boundaries and attack surface, which later audits work from. ([#188](https://github.com/alpha-omega-security/scrutineer/pull/188), [@andrew](https://github.com/andrew))
- Exposure analysis: for a confirmed vulnerability, work out which downstream projects that depend on the affected code are actually reachable by it. ([#200](https://github.com/alpha-omega-security/scrutineer/pull/200), [@alexandre-daubois](https://github.com/alexandre-daubois))
- Findings can be filed directly with maintainers through GitHub's private vulnerability reporting. ([#184](https://github.com/alpha-omega-security/scrutineer/pull/184), [@andrew](https://github.com/andrew))
- Findings export in the CSAF/VEX format used by downstream vulnerability tooling. ([#98](https://github.com/alpha-omega-security/scrutineer/pull/98), [@alexandre-daubois](https://github.com/alexandre-daubois))
- Audits now cover authorisation flaws (accessing another user's records) and prompt-injection risks in code that calls AI models. ([#196](https://github.com/alpha-omega-security/scrutineer/pull/196), [@N0tre3l](https://github.com/N0tre3l); [#170](https://github.com/alpha-omega-security/scrutineer/pull/170), [@andrew](https://github.com/andrew))
- Findings from other scanners and spreadsheets can be imported and tracked alongside Scrutineer's own. ([#187](https://github.com/alpha-omega-security/scrutineer/pull/187), [@andrew](https://github.com/andrew))

## 2026-05-04

- Project start. A web application and job queue that clone open-source repositories, run AI-driven security audits inside an isolated container, and record what they find.
- Upload a software bill of materials and Scrutineer queues a scan of every dependency it lists. ([#86](https://github.com/alpha-omega-security/scrutineer/pull/86), [@andrew](https://github.com/andrew))
- Each confirmed finding gets a drafted security advisory and a candidate patch. ([#39](https://github.com/alpha-omega-security/scrutineer/pull/39) [#40](https://github.com/alpha-omega-security/scrutineer/pull/40), [@andrew](https://github.com/andrew))
- Individual packages inside a monorepo can be scanned on their own. ([#43](https://github.com/alpha-omega-security/scrutineer/pull/43), [@andrew](https://github.com/andrew))
- Per-scan cost and token usage is recorded and shown on a usage page. ([#79](https://github.com/alpha-omega-security/scrutineer/pull/79), [@andrew](https://github.com/andrew))
- Repositories are matched to their CVE Numbering Authority so disclosures are routed to the right contact. ([#92](https://github.com/alpha-omega-security/scrutineer/pull/92), [@andrew](https://github.com/andrew))
