# Node Exfiltration Review Notes

## SSRF

Search for fetch, axios, got, request, undici, node:http, proxy agents, webhook
callbacks, URL previewers, importers, and integrations that accept
caller-provided endpoints. Safe code should use a fixed service map or strict
host allowlist and re-check redirects. Inspect URL parsing differences, encoded
hosts, username/password fields, IPv6, localhost aliases, cloud metadata
addresses, and DNS rebinding windows.

Concrete defaults:

- Node's low-level `http.request()` and `https.request()` do not implement a
  redirect loop. Global `fetch()` is browser-compatible and follows redirects
  unless the call sets `redirect: "manual"` or `"error"`.
- Axios, got, and request-style clients have changed redirect and proxy
  behavior across releases. Read `package-lock.json`, `yarn.lock`, or
  `pnpm-lock.yaml` and inspect client options. A hostname check on only the
  initial URL is not enough when redirects are enabled.
- Node's built-in HTTP(S) clients do not fetch `file:` or `gopher:` URLs.
  Do not claim alternate-scheme SSRF unless the selected client or wrapper
  actually supports the scheme.
- Next.js Server Actions SSRF CVE-2024-34351 affects versions `>=13.4.0,
  <14.1.1`. Apply this advisory only when Next.js is self-hosted, an attacker
  can modify the `Host` header reaching the application, Server Actions are in
  use, and a Server Action redirects to a relative path beginning with `/`.
  Managed routing that fixes the host or an arbitrary `fetch()` elsewhere is
  outside this advisory and needs a separate trace.

## File Reads

Search for fs.readFile, createReadStream, sendFile, res.download, serve-static
wrappers, path.join/resolve, multer uploads, archive extraction, and template or
asset lookup helpers. Report traversal only when an untrusted path can escape
the intended root or select a sensitive object. Require evidence about
normalization, absolute paths, symlinks, percent decoding, and platform path
separators.

Framework behavior and false positives:

- Express `res.sendFile(relativeName, {root: fixedRoot})` validates that the
  resolved relative path stays under `root`. That is a mitigation, including
  for relative names containing `..`; inspect `dotfiles` and authorization
  separately. `res.sendFile(absolutePath)` trusts application path
  construction.
- `express.static(fixedRoot)` and equivalent fixed-root Fastify/Hono helpers
  normalize request paths. A root of `"."`, an attacker-controlled root, or a
  custom `fs` handler still needs review.
- `path.normalize()`, `path.join()`, and `path.resolve()` are transformations,
  not containment checks. Require equality with the base or a
  `base + path.sep` boundary check after resolution; plain
  `target.startsWith(base)` also accepts sibling prefixes such as
  `/srv/export-backup`.
- Do not report an archive library solely by package name. Check the pinned
  version and whether the application writes library-sanitized entry names or
  raw archive names.

## XML And Document Parsing

Search for libxmljs, xml2js, fast-xml-parser, sax, xmldom, SVG processors, and
office document parsers. Confirm whether DTDs, external entities, XInclude,
schema fetching, or network/file loaders are enabled for untrusted input before
reporting.

Pure-JavaScript SAX/tree parsers commonly parse declarations without providing
an external resource loader. A `DOCTYPE` token alone is not proof of file or
network access. For libxml-backed wrappers, entity substitution options such as
`noent: true`, DTD loading, XInclude, or a custom loader are the important
signals. Verify the installed package and option names from the lockfile and
local source.

## Response Leaks

Search for Express/Fastify/Next error handlers, development mode, stack traces,
JSON.stringify of internal errors, logging endpoints, and response bodies that
include secrets, headers, tokens, environment variables, or upstream internal
responses.

Express's default error handler suppresses stack traces when
`NODE_ENV=production`; custom error middleware can override that. Next.js
Server Components and `getServerSideProps` serialize values across the server
boundary, but a hand-shaped DTO or explicit ORM `select` is a defense. Report
only fields that are actually serialized to a less-privileged client.
