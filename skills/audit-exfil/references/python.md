# Python Exfiltration Review Notes

## SSRF

Search for requests, httpx, aiohttp, urllib, boto client endpoints, webhook
callbacks, importers, previewers, and URL validators. Treat a path as safe only
when the code maps user input to an allowlisted host or service before the
request and enforces the same decision after redirects. Check scheme allowlists,
credentials in URLs, proxy settings, redirects, IPv6 literals, decimal or octal
IPv4 forms, DNS rebinding, and access to cloud metadata addresses.

Concrete defaults:

- `requests` follows redirects by default for every verb except `HEAD`.
  `allow_redirects=False` avoids a redirect hop, but the original destination
  still needs scheme, host, resolved-IP, and port validation.
- `urllib.request` installs HTTP redirect, proxy, FTP, and `file:` handlers in
  its default opener. Do not treat a scheme check performed after
  `urlopen()` as a guard.
- `httpx` and `aiohttp` behavior is call-site/configuration dependent. Read the
  pinned version and client construction; do not infer redirect safety from
  the library name alone.

## File Reads

Search for open, pathlib.Path.open/read_text/read_bytes, os.path joins,
send_file, FileResponse, static file helpers, zipfile, tarfile, shutil
extraction, and object-storage key construction. A lexical clean is not enough:
the code must join against a trusted root and enforce containment after
normalization and symlink resolution. Watch for double decoding and mixed path
separators.

Framework and runtime checks:

- Flask `send_from_directory(directory, path)` delegates to Werkzeug
  `safe_join` and is normally the safe choice for an untrusted relative name.
  Flask `send_file(path)` trusts the path supplied by the application.
- FastAPI/Starlette `FileResponse(path)` trusts its path. A fixed
  `StaticFiles(directory=...)` root is not itself traversal; inspect custom
  lookup logic and any attacker-controlled directory.
- `tarfile.extractall()` accepted `filter="data"` starting in Python 3.12.
  Python 3.14 changed the default from effectively `fully_trusted` to `data`.
  For 3.13 and older, require an explicit `filter="data"` or equivalent
  per-member containment checks. Even the data filter does not address archive
  bombs or every pre-existing filesystem race.
- Do not report `zipfile.extractall()` solely from the call name. Inspect the
  pinned runtime, archive-member handling, symlinks, overwrite behavior, and
  destination isolation before deciding that escape is possible.

## XML And Document Parsing

Search for lxml, ElementTree, minidom, SAX, defusedxml bypasses, YAML/XML
document imports, SVG parsing, DOCX/XLSX metadata reads, and schema validation.
Report XXE only when untrusted XML reaches a parser with DTD, entity, XInclude,
or external resource loading enabled.

Parser defaults and false positives:

- CPython's `xml.etree.ElementTree` rejects undefined external entities, and
  `xml.dom.minidom` leaves them unexpanded. A bare
  `ElementTree.fromstring()` is not evidence of XXE file read or SSRF.
- Starting with Python 3.7.1, `xml.sax` no longer processes general external
  entities by default. Earlier runtimes could load local files or make
  network requests for DTDs and entities. Check the pinned runtime version and
  any `setFeature(feature_external_ges, true)` call or custom entity resolver;
  enabling that feature on a newer runtime restores the unsafe behavior.
- `lxml.etree.XMLParser` historically defaults `no_network=True` while entity
  substitution has been enabled in older releases. `no_network` does not prove
  local `file:` entities are blocked. For untrusted XML, look for
  `resolve_entities=False`, `load_dtd=False`, `no_network=True`, and no custom
  resolver; verify their actual defaults against the pinned lxml version.
- `defusedxml` entry points are a strong mitigation for the parser operations
  they wrap. Do not flag them unless code bypasses the wrapper or installs an
  unsafe resolver afterward.

## Response Leaks

Search for DEBUG=True, traceback responses, exception formatters, repr(object)
in HTTP responses, headers/cookies reflected into errors, and logs returned
through user-accessible APIs. Operator-only logs are not a finding unless a
less-privileged caller can retrieve them.

Specific framework behavior:

- FastAPI filters output to a declared `response_model` or supported return
  type. Missing `response_model` is only a finding when the returned object
  demonstrably includes sensitive fields.
- Django and Flask production error handlers are generic by default. Report
  stack/config disclosure only when project settings enable debug/local error
  pages in a production-reachable deployment or a custom handler serializes
  exception details.
