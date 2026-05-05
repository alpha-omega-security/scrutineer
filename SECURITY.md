# Security policy

## Reporting a vulnerability

Please report security issues through GitHub's private vulnerability reporting on this repository: open the Security tab and choose "Report a vulnerability". That keeps the report private between you and the maintainers until a fix is ready.

If you cannot use GitHub, email info@alpha-omega.dev with "scrutineer security" in the subject line.

We aim to acknowledge new reports within five working days and to agree a disclosure timeline with you once the issue is confirmed.

Please do not open a public issue for security problems.

## Supported versions

Scrutineer is not yet versioned; only the current `main` branch is supported. If you find a problem in an older commit, check whether it still reproduces on `main` before reporting.

## Scope

Scrutineer is a single-operator tool that clones third-party repositories and runs analysis over them. By default scans run inside a container; with `--no-docker` they run directly on the host. We are interested in reports where:

- a malicious repository can escape the scan workspace or container
- the web UI or HTTP API can be abused from outside `127.0.0.1`
- a skill or scan can read or write data belonging to another scan
- stored data (findings, tokens, reports) can leak to a third party

Issues that require the operator to deliberately point scrutineer at hostile input and run with `--no-docker` are lower priority but still welcome.
