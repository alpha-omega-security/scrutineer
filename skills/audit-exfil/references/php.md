# PHP Exfiltration Review Notes

## SSRF

Search for curl_exec, file_get_contents on URLs, fopen wrappers, Guzzle,
Symfony HttpClient, webhook callbacks, importers, and previewers. Check
allow_url_fopen, redirect handling, proxy settings, scheme allowlists,
localhost aliases, IPv6/numeric IP forms, DNS rebinding, and cloud metadata
addresses.

Concrete defaults:

- PHP's `allow_url_fopen` default is enabled, so filename-taking functions such
  as `fopen()` and `file_get_contents()` can use HTTP/FTP wrappers unless the
  deployment disables it. Confirm the effective configuration as well as code.
- `allow_url_include` defaults off and is deprecated since PHP 7.4. Do not
  claim remote include solely from `include($value)` without evidence that the
  setting and wrapper make it reachable; local-file traversal remains separate.
- Guzzle follows redirects by default, with a default maximum of five.
  `allow_redirects=false` prevents redirect pivots but not an unsafe initial
  URL. Symfony HttpClient and cURL options must be inspected independently.
- cURL protocol and redirect restrictions vary by PHP/libcurl version and
  `CURLOPT_PROTOCOLS(_STR)`/`CURLOPT_REDIR_PROTOCOLS(_STR)`. Use
  `composer.lock` and deployment metadata instead of assuming HTTP-only.

## File Reads

Search for file_get_contents, readfile, fopen, include/require, SplFileObject,
Laravel/Symfony download helpers, storage path builders, zip/phar/tar handling,
and template or asset selection. Safe code should resolve under a trusted root
and enforce containment after normalization; basename or simple string replace
is usually not enough.

Framework and API behavior:

- `basename()` drops directory components but does not prove that a separately
  constructed or decoded path remains under a root. `realpath()` returns false
  for nonexistent paths, so upload/write flows need a safe-parent strategy.
- Symfony `BinaryFileResponse` and Laravel/Symfony download helpers trust the
  server path passed by application code. A constant path is safe; a
  request-derived path needs canonical containment and authorization.
- Laravel Storage keys are logical paths inside the configured disk for the
  standard adapters. Do not equate a user-controlled key with host filesystem
  traversal unless a custom/local adapter or path construction escapes that
  namespace.
- ZipArchive extraction and custom Phar/Tar loops need version-aware,
  per-entry destination checks. Merely opening or listing an archive is not
  extraction.

## XML And Document Parsing

Search for DOMDocument::loadXML, SimpleXML, XMLReader, libxml flags, SOAP, SVG,
and office document parsers. Report XXE only when untrusted XML can load
external entities, DTDs, XInclude, schemas, or file/network resources.

libxml defaults and version gates:

- With libxml 2.9.0 and later, entity substitution is disabled by default.
  A plain `DOMDocument::loadXML()`/`simplexml_load_string()` on PHP 8 is not
  enough to prove XXE.
- `LIBXML_NOENT`, `LIBXML_DTDLOAD`, `LIBXML_DTDVALID`, `LIBXML_XINCLUDE`, a
  custom external entity loader, or explicit XInclude processing changes the
  analysis. `LIBXML_NONET` blocks network access but does not make local-file
  entities safe.
- `LIBXML_NO_XXE` is available only with libxml 2.13.0/PHP 8.4 or later.
  On that combination it can preserve required entity processing while
  blocking external entities. Check both PHP and loaded libxml versions.
- `libxml_disable_entity_loader()` is deprecated in PHP 8 because secure
  defaults changed. Its absence is not a vulnerability by itself.

## Response Leaks

Search for display_errors, debug mode, Whoops, Laravel/Symfony exception pages,
var_dump/print_r in responses, exposed logs, and diagnostics that reveal
secrets, environment variables, headers, cookies, tokens, or internal service
responses.

Production templates commonly disable `display_errors`, but repository config,
container environment, and framework debug settings can override it. Laravel
and Symfony production handlers are normally generic; report only a reachable
debug configuration or custom response that includes exception details.
`var_dump`/`print_r` written only to CLI or protected operator logs is not a
response leak.
