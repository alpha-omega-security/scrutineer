# Path traversal in download URL

## Details
Download URL generation interpolates parsed components into URL paths without re-encoding, while the parser decodes percent-encoded delimiters into those same components.

## Location
[download_url.rb:97](https://github.com/example/widget/blob/main/download_url.rb#L97)

## Impact
Allowlist check on parsed namespace passes while URL fetches attacker repo

## Reproduction steps
1. Submit a PURL with a percent-encoded version segment containing dot-segments.

## Recommended fix
Components that were percent-decoded during parsing must be re-encoded when interpolated into URL paths.

---
**Severity:** MEDIUM
**Status:** Open
**Category:** Path traversal
**Repository:** example/widget
**Branch:** main
**Date created:** 2026-04-09

---

# Second-order SSRF via hypermedia link

## Details
The fetch_version_info method constructs a URI from a JSON body field with no host validation.

## Location
[lookup.rb:179](https://github.com/example/widget/blob/main/lookup.rb#L179)

## Recommended fix
URLs received in API response bodies must be validated against an allowlist of expected hosts and schemes.

---
**Severity:** LOW
**Status:** Open
**Category:** Ssrf
**Repository:** example/widget
**Branch:** main
**Date created:** 2026-04-09
