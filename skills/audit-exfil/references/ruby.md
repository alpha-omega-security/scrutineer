# Ruby Exfiltration Review Notes

## SSRF

Search for Net::HTTP, OpenURI.open_uri, Faraday, HTTParty, RestClient, webhook
callbacks, importers, previewers, and integrations that accept URLs. Check
allowlists, scheme checks, redirect handling, proxy use, DNS rebinding,
IPv6/localhost aliases, and cloud metadata addresses. URI.parse alone is not a
security boundary.

Concrete defaults:

- `Net::HTTP` does not automatically follow redirects. A manual redirect loop
  must revalidate each `Location`; absence of such a loop is a false positive
  for redirect-based bypass, not for the initial request.
- `URI.open`/OpenURI accepts URI schemes handled by its openers and follows
  HTTP redirects under its own policy. Inspect scheme restrictions and the
  pinned Ruby behavior before treating it like `Net::HTTP`.
- Faraday and HTTParty redirect behavior depends on middleware/options.
  Determine the adapter and redirect middleware from `Gemfile.lock` and client
  construction rather than assuming a default.

## File Reads

Search for File.open/read/binread, IO.read, send_file, send_data, ActiveStorage
key selection, Pathname joins, archive extraction, and template/file lookup
helpers. Safe code should expand paths under a trusted root and enforce
containment after symlink resolution when user-controlled names are involved.

Rails behavior:

- `ActionController::DataStreaming#send_file` trusts the server path. Rails
  explicitly warns that `send_file(params[:path])` can expose arbitrary files.
- `send_data` sends bytes already held by the application and does not perform
  a filesystem lookup; it is not traversal by itself.
- Active Storage blob lookup by a signed ID is not arbitrary path access.
  Review authorization and key construction separately, especially custom
  disk-service wrappers.
- `File.expand_path`/`Pathname#cleanpath` alone does not enforce containment.
  Compare the expanded target to the expanded base with a path-separator
  boundary and account for symlinks where the target may already exist.

## XML And Document Parsing

Search for Nokogiri, REXML, Ox, XML schema validation, SVG processing, and
office document parsing. Report XXE only when untrusted XML can enable external
entities, DTD loading, XInclude, or external schema/resource fetching.

Parser defaults and false positives:

- Nokogiri's ordinary XML document parser treats input as untrusted by default:
  `NONET` is on and `NOENT` is off. A plain `Nokogiri::XML(xml)` call is not an
  XXE finding.
- Nokogiri `config.noent`, `DTDLOAD`, `DTDVALID`, XInclude processing, or
  `config.nonet`/`nononet` changes require review. `NONET` blocks network
  access but does not by itself prove local-file entities are impossible once
  entity substitution or DTD loading is enabled.
- Nokogiri's XSLT parse defaults include `NOENT` and `DTDLOAD`; do not parse
  attacker-controlled stylesheets. Distinguish this from ordinary XML
  document parsing.
- Do not transfer Nokogiri defaults to REXML or Ox. Confirm their installed
  versions and actual parser options from `Gemfile.lock` and local code.

## Response Leaks

Search for Rails consider_all_requests_local, show_exceptions, exception
renderers, object inspection in JSON responses, debug endpoints, and logs or
diagnostics exposed to lower-privileged users.

Rails production exception rendering is normally generic when
`consider_all_requests_local` is false. A custom `rescue_from` that returns
`exception.message`, `backtrace`, model `attributes`, or request parameters can
reintroduce disclosure. `as_json`/`to_json` on an Active Record model exposes
the selected model attributes unless an explicit serializer or `only`/`except`
filter narrows them.
