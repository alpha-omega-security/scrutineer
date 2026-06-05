# Vendored OSV schema

This schema is embedded into the binary (`//go:embed osv_schemas/*.json`) and
used to validate generated OSV records at runtime, the same way the CSAF
exporter validates its output.

| File              | Source                                                                               | Schema version | Snapshot date |
|-------------------|--------------------------------------------------------------------------------------|----------------|---------------|
| `osv_schema.json` | https://raw.githubusercontent.com/ossf/osv-schema/main/validation/schema.json        | 1.7.5          | 2026-06-05    |

Refresh by re-fetching from the source URL above. The schema is self-contained
(its only `$ref`s are internal `#/$defs/...` and its own `$id`), so no
companion files are needed; the compiler registers it under its `$id` and
compiles that URL.

Two constraints the exporter must respect, both enforced by this schema:

- `id` matches `#/$defs/prefix`: a registered home-database prefix or the `x_`
  escape. Scrutineer is not a registered database, so records use
  `x_scrutineer-finding-<id>`.
- `affected[].package.ecosystem` matches `#/$defs/ecosystemWithSuffix`: a fixed
  controlled list (`Go`, `PyPI`, `npm`, `RubyGems`, `crates.io`, ...). A
  package whose ecosystem is not on that list is anchored via a `GIT` range
  instead of a `package`, so export never emits a value the schema rejects.
