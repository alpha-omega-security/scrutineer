---
name: posture
description: Assess a repository's security posture and its readiness to receive a vulnerability report. Checks for a security policy, private vulnerability reporting, security.txt, prior advisories, scanning workflows, and other hygiene signals, then rates the project ready / partial / unprepared. Use before disclosure to decide how much hand-holding the maintainer will need, or as a standalone health check.
license: MIT
compatibility: Needs network access to api.github.com and api.securityscorecards.dev. Works best on GitHub-hosted repositories; degrades to file-only checks elsewhere.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: posture
---

# posture

You are scoring how prepared a project is to receive and act on a security report. This is not a code audit. You are looking at policy files, repository settings, and process signals, then producing a checklist and a one-word tier.

## Workspace

- `./src` — the cloned repository
- `./context.json` — has `repository.url` and `repository.host` (e.g. `github.com`)
- `./report.json` — write the result here
- `./schema.json` — shape of `report.json`

## Checks

Run every check below. For each one, record `present` (true/false/unknown), a one-line `evidence` string saying what you found, and a `url` pointing at the file or API result when there is one. Do not skip checks; an explicit `false` is more useful downstream than a missing key.

### Disclosure intake

**security_policy** — Look for `SECURITY.md`, `.github/SECURITY.md`, `docs/SECURITY.md`, `SECURITY.rst`, or a `## Security` section in `README.md`. If found, read it and fill the `security_policy_detail` object: does it name a `contact` (email, form, or "use GitHub advisories"), list `supported_versions`, and give a `response_sla`? A file that just says "open an issue" counts as present but with empty detail.

**private_vulnerability_reporting** — Only when the host is `github.com`. Fetch `https://api.github.com/repos/{owner}/{repo}/private-vulnerability-reporting` (no auth needed for public repos). It returns `{"enabled": true|false}`. On 404 or a non-GitHub host, record `unknown`.

**security_txt** — Look for `.well-known/security.txt` or `security.txt` in `./src`. Some projects vendor it for the website they ship.

**manifest_security_contact** — Read the top-level package manifest if one exists (`package.json` `bugs`/`security`, `pyproject.toml` `[project.urls] Security`, `*.gemspec` `metadata["security_uri"]`, `Cargo.toml` `[package.metadata.security]`, etc). Present if any names a security URL or email.

**bounty_or_lifter** — Grep `README*` and `SECURITY*` for Tidelift, HackerOne, Bugcrowd, Open Collective security, or an explicit bounty programme. Record which one in `evidence`.

**prior_advisories** — Fetch `https://api.github.com/repos/{owner}/{repo}/security-advisories?state=published`. Present if the array is non-empty; put the count in `evidence`. A project that has published before knows the drill.

### Hygiene

**scorecard** — Fetch `https://api.securityscorecards.dev/projects/github.com/{owner}/{repo}`. If it returns a result, put the overall score in `evidence` and `present: true`. 404 means not scanned; record `unknown`.

**dependency_updates** — Look for `.github/dependabot.yml`, `.github/dependabot.yaml`, `renovate.json`, `.renovaterc*`, or `.github/renovate.json`.

**code_scanning** — Look in `.github/workflows/*.y*ml` for `github/codeql-action`, `securego/gosec`, `aquasecurity/trivy-action`, `snyk/actions`, or similar. Present if any scanning workflow exists.

**signed_releases** — Look in `.github/workflows/` for `sigstore/cosign`, `slsa-framework/slsa-github-generator`, `goreleaser` with `signs:`, or GPG signing steps. Also check `git tag -l | head` in `./src` and `git tag -v` one recent tag for a signature.

**codeowners** — Look for `CODEOWNERS`, `.github/CODEOWNERS`, or `docs/CODEOWNERS`.

**funding** — Look for `.github/FUNDING.yml`. A funded project is more likely to have time to respond.

**security_issue_template** — Look in `.github/ISSUE_TEMPLATE/` for a template that redirects security reports away from public issues (mentions `SECURITY.md`, "do not report vulnerabilities here", or similar). Also check `.github/ISSUE_TEMPLATE/config.yml` for a `contact_links` entry pointing at a security channel.

**archived** — From `context.json` `repository.archived` if set, otherwise the GitHub API repo response. An archived repo is an automatic `unprepared` regardless of other checks.

## Tier

Assign exactly one of:

- `ready` — has a security policy with a contact AND (PVR enabled OR a working security email/form), and is not archived.
- `partial` — has at least one intake signal (policy, PVR, security.txt, manifest contact) but it is incomplete or untested, and is not archived.
- `unprepared` — no intake signal at all, or the repository is archived.

Hygiene checks inform the `summary` prose but do not on their own move the tier; a project with CodeQL and Dependabot but no way to receive a report is still `unprepared`.

## Output

Write `./report.json` matching `./schema.json`:

```json
{
  "tier": "partial",
  "summary": "SECURITY.md names security@example.org but PVR is off and no advisories have been published. Dependabot and CodeQL are configured.",
  "checks": [
    { "id": "security_policy", "present": true, "evidence": "SECURITY.md at repo root, names email contact", "url": "https://github.com/o/r/blob/main/SECURITY.md" },
    { "id": "private_vulnerability_reporting", "present": false, "evidence": "API returned enabled:false" }
  ],
  "security_policy_detail": {
    "contact": "security@example.org",
    "supported_versions": ">= 2.x",
    "response_sla": "5 business days"
  },
  "notes": "anything that did not fit a check: pending maintainer handover, org-level policy inherited, etc."
}
```

Keep `summary` to one or two sentences a human can read in the repo list. Do not write to the scrutineer API; this skill is read-only and its output is the report file.
