# Vendored JSON Schemas

These schemas are embedded into the binary (`//go:embed csaf_schemas/*.json`) and
used to validate generated CSAF 2.0 VEX documents at runtime.

| File                     | Source                                                                 | Snapshot date |
|--------------------------|------------------------------------------------------------------------|---------------|
| `csaf_json_schema.json`  | https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json       | 2026-04-29    |
| `cvss-v2.0.json`         | https://www.first.org/cvss/cvss-v2.0.json                              | 2026-04-29    |
| `cvss-v3.0.json`         | https://www.first.org/cvss/cvss-v3.0.json                              | 2026-04-29    |
| `cvss-v3.1.json`         | https://www.first.org/cvss/cvss-v3.1.json                              | 2026-04-29    |

Refresh by re-fetching from the source URLs above. The CSAF schema's `$ref`
entries point to the no-query CVSS URLs; if a CVSS schema is updated upstream
with a new `$id` query suffix, strip it locally so resolution still works.
