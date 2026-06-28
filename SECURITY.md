# Security policy

## Reporting a vulnerability

Please report security issues through GitHub's private vulnerability reporting on this repository: open the Security tab and choose "Report a vulnerability". That keeps the report private between you and the maintainers until a fix is ready.

If you cannot use GitHub, email info@alpha-omega.dev with "scrutineer security" in the subject line.

We aim to acknowledge new reports within five working days and to agree a disclosure timeline with you once the issue is confirmed.

Please do not open a public issue for security problems.

## Reports written or found by AI tools

If you used an AI tool to find or write up the issue, say so in the report.

Before submitting, verify the finding yourself: confirm the affected code path exists, run the proof of concept, and check that the behaviour matches what the tool claims. AI tools regularly invent function names, file paths, tool flags, and impact claims that don't hold up. A report we can't reproduce, that cites code that isn't there, or that proposes a fix using APIs that don't exist will be closed and may get the account blocked from future reports.

Don't paste the tool's output as the report. Write what you actually verified, in your own words, and keep it short.

## Supported versions

Scrutineer is not yet versioned; only the current `main` branch is supported. If you find a problem in an older commit, check whether it still reproduces on `main` before reporting.

## Severity

We rate confirmed issues as Low, Medium, High, or Critical and publish that rating in the advisory. We don't set CVSS vectors: scrutineer is an operator-run application with no package-manager install base, so most CVSS inputs (attack vector, scope, affected population) don't map cleanly, and a numerical score implies a precision we don't have. If a downstream database assigns a CVSS score to one of our advisories, that score is theirs, not ours.

## Scope

Scrutineer is a single-operator tool that clones third-party repositories and runs analysis over them. By default scans run inside a container; with `--no-container` they run directly on the host. The threat model assumes scanned repositories are hostile; see `threatmodel.md` for the current boundaries and known residuals. We are interested in reports where:

- a malicious repository can escape the scan workspace or container
- the web UI or HTTP API can be abused from outside `127.0.0.1`
- a skill or scan can read or write data belonging to another scan
- stored data (findings, tokens, reports) can leak to a third party

Issues that require the operator to deliberately point scrutineer at hostile input and run with `--no-container` are lower priority but still welcome.

## Out of scope

These are not treated as security issues:

- Code execution inside the scan container that stays inside the container. The agent runs with shell access by design; the container plus the egress filter is the boundary, not the agent's tool permissions.
- Gaps already listed as residuals in `threatmodel.md`. Reports that turn a documented residual into a working exploit are welcome and will be credited, but the severity reflects that the gap was already public.
- Prompt injection that only affects the content of the scan's own findings or report. The operator reviews findings before acting on them.
- Resource exhaustion from a scanned repository (large clones, slow scans, oversized reports). Scans have wall-clock and turn limits and report output is capped; a repository that hits those limits fails its own scan, which is the intended outcome.
- Anything that requires the attacker to already control the operator's host, the docker daemon, or the `scrutineer.yaml` config.
- Issues in dependencies that scrutineer doesn't reach. Run `govulncheck ./...` first; if it doesn't flag the path, neither will we.
