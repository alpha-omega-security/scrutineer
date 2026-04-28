---
name: cna-match
description: Determine which CVE Numbering Authority (if any) covers this repository, so disclosures can be routed to the CNA's security contact rather than only the maintainer. Reads scrutineer's cached CNA list and matches the repo's owner, project name, and published packages against each CNA's published scope.
license: MIT
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: maintainers
---

# cna-match

Decide whether a CVE Numbering Authority covers this repository. When one does, the disclosure should go to that CNA's security contact (and usually the maintainer in CC), because the CNA is who issues the CVE ID and coordinates the advisory.

## Workspace

- `./src` — the cloned repository. Useful mainly for `SECURITY.md`, which sometimes names the CNA directly.
- `./context.json` — read `repository.url`, `repository.full_name`, `repository.owner`, plus the `scrutineer` block with `api_base`, `token`, `repository_id`.
- `./report.json` — write your result here.
- `./schema.json` — the JSON schema your report must validate against.

## Data

Call these with `Authorization: Bearer {token}`:

- `GET {api_base}/repositories/{repository_id}` — owner, full name, html_url.
- `GET {api_base}/repositories/{repository_id}/packages` — published package names and ecosystems. A CNA scope often names the package, not the repo.
- `GET {api_base}/cnas` — the full CNA list (short_name, organization, scope, email, contact_url, policy_url, root, types). Pass `?q={term}` to narrow by substring across short_name/organization/scope; useful for checking the obvious candidate first (e.g. `?q=apache` when the owner is `apache`).

Also read `./src/SECURITY.md` and `./src/.github/SECURITY.md` if present. Projects under a CNA usually say so there ("Report to security@apache.org", "We are our own CNA", "Report via GitHub Security Advisories").

## Matching

CNA scopes are free-text prose, not patterns. Match in this order and stop at the first hit:

1. **SECURITY.md names a CNA or its contact directly.** If the file says report to a specific security@ address or names a CNA programme, find that entry in `/cnas` and use it.
2. **Owner matches a CNA's organization or scope.** Repo owner `apache` → CNA `apache` ("All Apache Software Foundation projects"). Owner `kubernetes` or `kubernetes-sigs` → CNA `kubernetes`. Owner `nodejs` → CNA `nodejs`. Check `?q={owner}` first.
3. **Package or project name matches a single-project CNA scope.** Package `curl` or `libcurl` → CNA `curl`. Package `openssl` → CNA `openssl`. These CNAs have narrow scopes naming the project explicitly.
4. **Hosted on github.com with no other match.** GitHub (`GitHub_M`) is the CNA of last resort for public repos on github.com that have no other CNA. Only use this if steps 1-3 found nothing.

A scope like "Vendor X products only" or "issues discovered by our researchers" does not cover an unrelated open-source repo even if a keyword overlaps. Read the scope sentence, not just the keyword.

If nothing matches, that is a valid result: most projects have no CNA and disclosure goes to the maintainer.

## Output

Write `./report.json` matching `./schema.json`. The `output_kind` is `maintainers` so scrutineer's existing parser updates `Repository.DisclosureChannel` from the `disclosure_channel` field; `maintainers` stays an empty array. The `cna` block records which CNA matched and why so an analyst can review the reasoning in the scan report.

When a CNA matched, set `disclosure_channel` to its email if it has one, otherwise its `contact_url`. Append the organization name in parentheses so the repo page shows where the address came from, e.g. `security@apache.org (Apache Software Foundation CNA)`.

When nothing matched, leave `disclosure_channel` empty so any value the `maintainers` skill set earlier is left alone, and set `cna` to `null`.
