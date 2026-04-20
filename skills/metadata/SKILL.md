---
name: metadata
description: Fetch high-level repository metadata (description, default branch, languages, license, stars, forks, archived status, icon) and save it against the scan's repository row. Use as the first scan on a new repository or to refresh after upstream changes.
license: MIT
compatibility: Needs network access to repos.ecosyste.ms.
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: repo_metadata
---

# metadata

Populate repository metadata from repos.ecosyste.ms. One API call, one flat JSON document.

## Workspace

- `./context.json` — has `repository.url` (the git URL of the target repo)
- `./report.json` — write the flat metadata here
- `./schema.json` — output shape

## What to do

1. Read `./context.json` and extract `repository.url`.
2. Fetch `https://repos.ecosyste.ms/api/v1/repositories/lookup?url={URL-ENCODED_URL}`. Follow redirects.
3. Keep the raw upstream response available for the `metadata` blob (the parser stores it as `Repository.Metadata`).
4. Map the fields below into `./report.json` exactly as `./schema.json` describes:
   - `full_name` from upstream `full_name`
   - `owner` from upstream `owner`
   - `description` from upstream `description`
   - `default_branch` from upstream `default_branch`
   - `languages` as a plain array of names (upstream returns an object like `{"Go": 90, "JavaScript": 10}`; take the keys)
   - `license` from upstream `license` (string, not object)
   - `stars` from upstream `stargazers_count`
   - `forks` from upstream `forks_count`
   - `archived` from upstream `archived`
   - `pushed_at` from upstream `pushed_at` (RFC3339 string)
   - `html_url` from upstream `html_url`
   - `icon_url` from upstream `icon_url` if present

Omit any field upstream did not provide rather than making one up. If the lookup returns nothing, write `{}` and exit 0 — the parser handles an empty map cleanly.
