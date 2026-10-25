# protocol-parser mode

This entry merges into `skills/triage/references/modes.md` once PR #1077
(package-manager audit mode, which introduces `modes.md`) lands.

---

## protocol-parser

Enqueue `spec-fuzz` when first-party code implements a parser for a
wire protocol or serialization format defined by a public specification
(RFC, W3C, IETF draft). Trace an exposed function that reads bytes and
produces a structured message, and cite at least one of:

- an RFC number, ABNF fragment, or section reference in comments,
  docstrings, or test names
- a test fixture whose bytes match a known protocol frame (e.g. an
  HTTP request line, a chunked body, an SMTP DATA sequence)
- a public API named for the protocol (`parse_request`, `read_chunk`,
  `HTTPParser`)

A repository that only consumes a parser library (imports h11, llhttp,
net/http) does not qualify on that evidence alone; look for a
first-party implementation. Serialization-only code (a writer with no
reader) does not qualify. Configuration-file parsers (YAML, TOML) do
not qualify unless the repository is the parser library itself.

`spec-fuzz` selects the applicable RFC clause from scrutineer's
vendored set at run time; triage records only that the mode matched
and the file evidence.
