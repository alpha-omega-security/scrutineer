---
name: cna-match
description: Match the repository to a CVE Numbering Authority so disclosures route to the CNA's security contact when one covers the repo.
license: MIT
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: maintainers
---

# cna-match

Decide whether a CVE Numbering Authority covers this repository. When one does, the disclosure should go to that CNA's security contact (and usually the maintainer in CC), because the CNA is who issues the CVE ID and coordinates the advisory.

## Workspace

- `./src` — the cloned repository. Useful mainly for `SECURITY.md`, which sometimes names the CNA directly.
- `./context.json` — read `repository.url` and `repository.full_name`, plus the `scrutineer` block with `api_base`, `token`, `repository_id`. The owner is the part of `full_name` before the `/`.
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

A scope like "Vendor X products only" or "issues discovered by our researchers" does not cover an unrelated open-source repo even if a keyword overlaps. Read the scope sentence, not just the keyword.

If steps 1-3 find nothing, that is a valid result: most projects have no dedicated CNA and disclosure goes to the maintainer. For a repo hosted on github.com you may still record GitHub (`GitHub_M`) as the fallback CNA in the `cna` block with `match_rule: "github_fallback"`, since GitHub can issue a CVE via the advisory form, but do not set `disclosure_channel` from it. The maintainer contact (set by the `maintainers` skill) is the right first stop; the analyst can escalate to GitHub for a CVE ID later.

## Output

Write `./report.json` matching `./schema.json`. The `output_kind` is `maintainers` so scrutineer's existing parser updates `Repository.DisclosureChannel` from the `disclosure_channel` field; `maintainers` stays an empty array. The `cna` block records which CNA matched and why so an analyst can review the reasoning in the scan report.

When a CNA matched via steps 1-3, set `disclosure_channel` to its email if it has one, otherwise its `contact_url`. Append the organization name in parentheses so the repo page shows where the address came from, e.g. `security@apache.org (Apache Software Foundation CNA)`.

When nothing matched, or only the github.com fallback applied, leave `disclosure_channel` as `""`. The parser ignores empty values so any contact the `maintainers` skill set is left alone regardless of which skill ran first.

```json
{
  "maintainers": [],
  "disclosure_channel": "security@apache.org (Apache Software Foundation CNA)",
  "cna": {
    "short_name": "apache",
    "organization": "Apache Software Foundation",
    "email": "security@apache.org",
    "contact_url": "https://www.apache.org/security/",
    "policy_url": "https://www.apache.org/security/",
    "scope": "All Apache Software Foundation projects",
    "match_rule": "owner",
    "match_reason": "repo owner 'apache' matches ASF CNA scope"
  }
}
```
