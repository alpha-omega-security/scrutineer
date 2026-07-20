# Changelog

Entries are grouped by release, newest first. Each entry is a summary written for people who fund and direct the work rather than a full commit list; see the git log for that.

## Unreleased

- Scans can be scheduled to repeat automatically and are skipped when the code has not changed since the last run. (#633, @alexandre-daubois)
- Large repositories can be split into named focus areas that are audited in parallel, each with its own report and coverage record. (#625 #652 #653 #673, @abhinavgautam01)
- Added a forensics mode that investigates a suspected account or release compromise and produces a cited evidence timeline without touching the repository. (#643, @abhinavgautam01)
- The security audit now checks for mass-assignment and for authentication controls that fail open when an input is left out. (#664 #672, @abhinavgautam01)
- Swift projects are now supported. (#650, @andrew)
- Hardened the scanner against repositories crafted to influence their own results, and added an audit log of scan actions. (#665 #667 #670, @abhinavgautam01, @p-linnane)
- Releases are now cut automatically every two weeks. (#666, @p-linnane)

## 2026-07-14

- First packaged release: Scrutineer now ships as a standalone binary with everything needed to run a scan bundled in. (#631, @p-linnane)
- Scans can now be driven by OpenAI Codex or opencode as alternatives to Claude, so operators are not tied to one AI vendor. (#535 #536, @andrew)
- Added an evaluation suite that runs the auditor against repositories with known planted vulnerabilities and scores what it catches and what it wrongly flags. (#590 #616, @abhinavgautam01)
- Rescanning a repository now examines only the code that changed since the last run, cutting the cost of keeping results current. (#602, @andrew)
- New audit that re-reads a project's past security advisories and checks whether the published fixes were complete or can be bypassed. (#556, @alexandre-daubois)
- Perl projects and Ruby native extensions are now supported. (#527, @andrew; #546 #554, @dkw-oss)
- Disclosure packages sent to maintainers now include a runnable proof of concept and record how each finding was originally discovered. (#610 #612, @andrew)
- Hardened against prompt injection: instruction files planted in a target repository are stripped before analysis, and audits treat all repository content as data rather than directions. (#604 #608, @andrew)

## 2026-06-29

- Added dedicated runners for Node.js, Python, Go, Java, .NET, C/C++, and Erlang/Elixir so audits can build, test, and instrument code in each of those ecosystems. (#430 #431 #433 #434 #435 #437 #438 #459, @andrew)
- Rust projects are now supported. (#351, @walterhpearce)
- Scans can run under Podman (including rootless setups) and Apple's container runtime as well as Docker. (#492, @dkw-oss; #513, @p-linnane)
- Findings can be exported as an encrypted bundle for secure hand-off between separate installations. (#397, @dkw-oss)
- New validation step that re-tests a proposed patch against the original finding before it is offered to a maintainer. (#490 #493, @alexandre-daubois)
- Every repository in a GitHub organisation can be imported in one action. (#394, @connorshea)
- Added a workbench for editing a repository's threat model between audit runs. (#267, @andrew)

## 2026-06-15

- Added an analyst review queue with structured accept/reject verdicts, so every AI-produced finding is checked by a person before it goes further. (#378, @andrew)
- Findings export in the standard OSV and CSAF advisory formats and carry CVSS v4.0 scores. (#327, @alexandre-daubois; #383 #384, @andrew)
- New quick re-check pass filters obvious false positives before an expensive full verification is queued. (#375 #376, @andrew)
- Added checks that classify whether a proposed fix would break existing callers and whether the maintainer has shipped a fixed release. (#379 #385, @andrew)
- Added a mitigation mode that produces operational workarounds and detection rules when a finding cannot be patched immediately. (#381, @andrew)
- Any branch or tag of a repository can be scanned, not only the default branch. (#303, @alexandre-daubois)

## 2026-06-01

- Hardened isolation mode: scans run with outbound network access limited to an allowlist, inside single-use container networks. (#274 #277, @alexandre-daubois)
- First language-specific runner (Ruby) and the profile machinery to add more. (#259, @alexandre-daubois; #279, @connorshea)
- Local directories can be scanned without needing a hosted git repository. (#242, @alexandre-daubois)
- ARM machines are supported. (#304, @alexandre-daubois)
- In-browser code viewer for jumping straight from a finding to the source line it cites. (#232, @alexandre-daubois)
- Failed scans resume from where they stopped instead of restarting from the beginning. (#301, @connorshea)

## 2026-05-18

- Each repository now gets a written threat model describing its trust boundaries and attack surface, which later audits work from. (#188, @andrew)
- Exposure analysis: for a confirmed vulnerability, work out which downstream projects that depend on the affected code are actually reachable by it. (#200, @alexandre-daubois)
- Findings can be filed directly with maintainers through GitHub's private vulnerability reporting. (#184, @andrew)
- Findings export in the CSAF/VEX format used by downstream vulnerability tooling. (#98, @alexandre-daubois)
- Audits now cover authorisation flaws (accessing another user's records) and prompt-injection risks in code that calls AI models. (#196, @N0tre3l; #170, @andrew)
- Findings from other scanners and spreadsheets can be imported and tracked alongside Scrutineer's own. (#187, @andrew)

## 2026-05-04

- Project start. A web application and job queue that clone open-source repositories, run AI-driven security audits inside an isolated container, and record what they find.
- Upload a software bill of materials and Scrutineer queues a scan of every dependency it lists. (#86, @andrew)
- Each confirmed finding gets a drafted security advisory and a candidate patch. (#39 #40, @andrew)
- Individual packages inside a monorepo can be scanned on their own. (#43, @andrew)
- Per-scan cost and token usage is recorded and shown on a usage page. (#79, @andrew)
- Repositories are matched to their CVE Numbering Authority so disclosures are routed to the right contact. (#92, @andrew)
