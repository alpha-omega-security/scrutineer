---
name: spec-fuzz
description: Test the repository's protocol parser against a formal RFC-clause oracle. Writes an adapter that drives the parser over a fixed corpus and reports what it accepts; scrutineer classifies each result against the vendored Lean model and reference-implementation matrix.
license: MIT
compatibility: Needs network access to the scrutineer API (http://host:port/api). Runs the target's parser as a subprocess in the workspace.
allowed-tools: Read,Write,Bash,Grep,Glob
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: spec_fuzz
  scrutineer.max_turns: 40
  scrutineer.model: high
  scrutineer.paths:
    - "**"
  scrutineer.ignore_paths:
    - "**/node_modules/**"
    - "**/dist/**"
    - "**/vendor/**"
---

# spec-fuzz

Read `./context.json` for `{scrutineer: {api_base, token, repository_id}}` and the scan scope. Read `./schema.json` for the output contract. Work in `./src` (or the sub-path when set).

## 1. Choose a clause

Fetch `GET {api_base}/specfuzz/clauses` (Bearer `{token}`). Each entry is `{id, citation, protocol}`. Match the repository against the listed protocols by looking for direct evidence in `./src`:

- an HTTP/1.1 parser (`protocol: http1`): code that reads a request line, header fields, and a body from bytes; RFC 7230/9110/9112 references; test fixtures containing `Transfer-Encoding: chunked` or literal chunk framing (`\r\n0\r\n\r\n`)
- a dependency on a known parser library is not enough on its own: this skill tests the repository's own parser, not one it consumes

If no listed protocol matches, write `{"error": "no matching clause; protocols=[...]"}` to `./report.json` and stop.

If more than one clause matches, pick the one whose `must_accept` control inputs the parser most obviously handles. Record the others in `notes`.

## 2. Fetch the corpus

`GET {api_base}/specfuzz/clauses/{id}` returns `{meta, controls: {must_accept, must_reject}, corpus}`. Each input has `{id, hex}`. Save the response to `./clause.json`.

## 3. Write the adapter

Write `./adapter` (any executable form: a shell script that invokes the target's Python/Ruby/Node entrypoint, or a compiled Go binary) that:

- reads newline-delimited hex-encoded byte strings on stdin
- for each line: decodes hex, feeds the bytes to the target's parser at the highest-level public entrypoint that exercises the clause (a request-parsing function for `http1`, not a lower-level tokenizer), and writes one JSON line to stdout: `{"accept": true, "body_hex": "...", "consumed": N}` on success (consumed is optional), `{"accept": false, "error": "..."}` on failure
- exits 0 after stdin closes

Prefer the server-facing entrypoint over a bare parser primitive when both exist: a library's low-level tokenizer may accept inputs the server built on it rejects.

Test the adapter against `controls.must_accept` first: every one must produce `{"accept": true}`. If any fails, the adapter is wired wrong (wrong entrypoint, missing dependency, build failed): fix it before continuing. `must_reject` failures at this stage are expected for a parser with the leniences this skill exists to find; do not treat them as adapter errors.

Record the entrypoint you drove as `file:line` relative to `./src`.

## 4. Run the corpus

Feed every `controls.must_accept[].hex`, `controls.must_reject[].hex`, and `corpus[].hex` through `./adapter` and collect one verdict per input, keyed by the input's `id`.

## 5. Report

Write `./report.json`:

```json
{
  "clause_id": "rfc9112-7.1",
  "entrypoint": "src/h11/_readers.py:148",
  "verdicts": {
    "ctrl/accept/single-chunk": {"accept": true, "body_hex": "68656c6c6f", "consumed": 15},
    "seed0/data_crlf:v4/17":    {"accept": true, "body_hex": "68656c6c6f"},
    "seed0/valid/0":            {"accept": true, "body_hex": "..."}
  },
  "notes": "adapter drives h11.Connection(SERVER); ..."
}
```

Do not classify or interpret verdicts yourself. scrutineer runs the oracle server-side, joins your verdicts against the reference matrix, and files findings for inputs the target accepts that the RFC model rejects. Your job is a correct adapter and complete verdicts.

If the adapter cannot be built (target has no invocable parser, build fails, language runtime missing), write `{"error": "..."}` with a one-sentence reason and stop.
