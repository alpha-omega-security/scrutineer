---
name: advisories
description: Fetch the published security advisories that affect any package produced by this repository. Use to populate the Advisories tab with existing GHSA and CVE records so analysts can see what is already public before triaging new findings.
license: MIT
compatibility: Needs network access to advisories.ecosyste.ms.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: advisories
---

# advisories

## Workspace

- `./context.json` — has `repository.url`
- `./report.json` — write the advisories array here
- `./schema.json` — output shape

## What to do

1. Read `./context.json` and extract `repository.url`.
2. Fetch `https://advisories.ecosyste.ms/api/v1/advisories?repository_url={URL-ENCODED_URL}`. Follow pagination (`Link: <...>; rel="next"`) if present.
3. For each advisory returned, emit one entry in `report.json` under `advisories`:
   - `uuid` from upstream `uuid`
   - `url` from upstream `url` (or the first reference if `url` is empty)
   - `title` from upstream `title`
   - `description` from upstream `description`
   - `severity` from upstream `severity` (upper-case, e.g. `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
   - `cvss_score` from upstream `cvss_score` (number; omit if absent)
   - `classification` from upstream `classification` (e.g. CWE id)
   - `packages` — comma-joined list of affected package names upstream lists under `packages` or `package_names`
   - `published_at` and `withdrawn_at` as RFC3339 strings if upstream has them

Return `{"advisories": []}` if upstream has nothing — valid result.
