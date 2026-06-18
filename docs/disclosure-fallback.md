# Disclosing when upstream has no private vulnerability reporting

`report-upstream` is the happy path: scrutineer files the finding as a private GitHub Security Advisory on the upstream repo, pushes the proposed patch into the temporary private fork GitHub allocates, and waits for the maintainer to acknowledge. The skill refuses to run if `gh api repos/{owner}/{repo}/private-vulnerability-reporting` does not report `{"enabled": true}`, because there is no equivalent private channel inside the GitHub UI.

This page is the runbook for the rest: how to disclose when PVR is off, when the upstream is not on github.com at all, or when the project sits inside a CNA's scope and the CNA prefers to handle intake. None of it needs new skills; the existing posture, maintainers, and cna-match runs already produce the data, and the choice tree below names which skill answers which question.

## Decide the route in this order

1. **Does a CNA cover the repo?** Run `cna-match` (or read the finding's CNA evidence if already populated). When the result names a CNA whose scope covers the package, prefer the CNA channel: they will issue the CVE, drive the embargo timeline, and coordinate with the maintainer themselves. Skip ahead to "Route to a CNA".

2. **Is the upstream on github.com with PVR enabled?** Run `posture`. If the resulting `posture.private_vulnerability_reporting` is `true`, use `report-upstream`; this runbook does not apply. If it is `false`, the project is on github.com but the maintainer has not opted in. Skip ahead to "GitHub upstream without PVR".

3. **Is the upstream somewhere else** (GitLab, sourcehut, codeberg, a vendor forge, a tarball-only project, a project that has effectively disappeared)? Skip ahead to "Non-GitHub or absent upstream".

`posture` is the cheapest of the three: it answers the PVR question and along the way records `security_policy` (`SECURITY.md`), `security_txt`, prior advisories, scanning workflows, and a one-word readiness tier. `cna-match` is finding-scoped and uses ecosyste.ms plus the SECURITY.md on disk; it returns the CNA, its scope, and the contact channel (email or URL). `maintainers` ranks the actual humans by activity and produces a `disclosure_channel` (email or URL from SECURITY.md, funding metadata, or a registry-owner page) plus the top contacts.

## Route to a CNA

When `cna-match` returns a CNA with a contact, send the disclosure there first. The contact is either a `mailto:` (almost always with a PGP key linked elsewhere in their policy) or a web form on the CNA's site. Run the existing chain:

1. Run `disclose` to produce the GHSA-shaped draft. The draft body is what you paste into the CNA's form or send as the email body.
2. If the finding has a `mitigate` run, the workarounds and detection guidance are part of the bundle the CNA expects.
3. Cc the maintainer when you have their address from `maintainers` and it is not the same as the CNA. The CNA decides whether to loop them in formally; cc-ing on the first message documents that we tried.
4. Move the finding to `reported` manually (the field accessor accepts the change with `source=analyst`) and record the CNA contact as a `FindingCommunication` with `channel=email` or `channel=direct`.

If the CNA wants the report submitted through a GitHub PVR on a different repo (some CNAs run intake repos), `report-upstream` can target that repo with `?repo=` once the analyst confirms which one.

## GitHub upstream without PVR

The upstream is reachable but the maintainer has not turned PVR on. Two paths, depending on the project's apparent readiness signals from `posture`:

**Readiness signals present (`security_policy`, `security_txt`, or a contact in `funding.yml`).** Use the channel they advertise. `maintainers` reads `SECURITY.md`, `.github/SECURITY.md`, `security.txt`, and the funding metadata, then emits the best channel in `disclosure_channel`. Send an encrypted email if a PGP key is in their policy; otherwise plain mail with the GHSA draft inline. Drop the patch as an attachment, not a public link.

The maintainer may respond by enabling PVR; once they confirm, you can rerun `report-upstream` to file the formal report through GitHub. Treat that as the moment the finding moves to `reported`; the email exchange before it is `FindingCommunication` rows with `direction=outbound`/`inbound`, `channel=email`.

**No readiness signals** (no `SECURITY.md`, no `security.txt`, no funding contact). The maintainer has not asked to be told about security issues, but the bug is still real. Two sub-cases:

- *Active project, just no policy yet.* The top-ranked lead from `maintainers` is in commits and PRs in the past 60 days. Open a stub `discussion` (or an `issue` with the embargo plus a CC of the lead's profile email) and ask the maintainer to enable PVR or designate a channel. Do not paste the finding body until they reply with a channel. Record the holding message as a `FindingCommunication`.
- *Inactive or absent.* No PRs merged in months, no responsive lead, the registry-owner contact is a dormant account. The finding is at risk of staying live without a fix. Drop to the next section.

Filing a *public* issue with the body of the bug is the act this runbook is designed to avoid. Public-issue filing is appropriate only for hardening-level findings where the bug is well-known or already in the wild and the open conversation costs nothing; high or medium findings do not belong there.

## Non-GitHub or absent upstream

The repo is on another forge, or the project is effectively abandoned. The chain still works; the channels just change.

- **GitLab.** GitLab supports private advisories through the security tab on a project; the project must have enabled the feature. When they have, paste the disclose draft into the GitLab advisory form. When they have not, use the email contact from `maintainers`.
- **sourcehut, codeberg, gitea, vendor forges.** Each has a SECURITY.md convention; `maintainers` reads it and surfaces the channel. The GHSA-shaped draft from `disclose` plus the patch from `patch` drop straight into the email body.
- **Tarball-only or absent upstream.** No live repo, but the package is on a registry. Two channels worth trying in order: the registry's security contact (npm, PyPI, RubyGems all have security@ addresses or report forms), and the package's last-known maintainer from `maintainers` via registry-owner email. The CNA route from earlier in the runbook is also worth checking, since the package's ecosystem may have a CNA that handles abandoned-project disclosures (npm via GitHub, Python via PSF, etc).
- **Absent maintainer.** When every channel fails, this is policy territory rather than a runbook step. Record what you tried as communications on the finding and escalate to the analyst lead. Possible directions from there include forking the project into a community-maintained home, transferring registry ownership where the registry allows it, or publishing an advisory under a CVE assigned by an ecosystem CNA without maintainer involvement.

## What gets recorded along the way

Whichever route you take, the finding's lifecycle moves through the same rows the PVR path uses, just driven by hand:

- A `FindingCommunication` row for every outbound message and every inbound response, with `channel`, `direction`, `actor`, and a body that quotes (or summarises, when the body is sensitive) what was sent. Use `channel=email`, `direct`, `issue`, `pr`, or `registry`.
- A `FindingReference` row for any URL the conversation produces: the CNA's tracking ID, a GitLab advisory URL, a public discussion you opened, a registry security report link. Tag them so they group sensibly on the finding page (`ghsa-upstream` is reserved for the GitHub PVR path; use `cna`, `gitlab-advisory`, `registry-report`, etc).
- A status transition (`reported`, eventually `acknowledged` / `fixed` / `published`) through `WriteFindingField` with `source=analyst`, so the timestamp is in `FindingHistory`. Don't transition automatically off an outbound message; only flip once the recipient has actually received the report.

Because the rows on the finding are the same shape regardless of which channel was used, finding-level metrics (time-from-reported-to-acknowledged, response rate per channel) work uniformly across the routes.

## Related skills

- `posture` — readiness check, including the PVR flag the rest of the runbook branches on
- `maintainers` — best disclosure channel for the project: SECURITY.md, security.txt, funding metadata, registry-owner contact
- `cna-match` — whether a CNA covers the package, and that CNA's contact channel
- `disclose` — drafts the advisory body, regardless of which channel it goes down
- `report-upstream` — the PVR path, included here only to name where this runbook starts
- `public-issue` — the public GitHub issue path for reviewed low-severity findings that do not warrant private disclosure
- Issue [#117](https://github.com/alpha-omega-security/scrutineer/issues/117) — extends `maintainers` to file-level owner routing for large repos
