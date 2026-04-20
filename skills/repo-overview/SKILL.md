---
name: repo-overview
description: Produce a short plain-language overview of what a repository does, who it is for, and how security-relevant it looks on first inspection. Use when you want a quick orientation before deeper analysis.
license: MIT
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: freeform
---

# repo-overview

The repository is cloned at `./src`. Your job is to read enough of it to answer three questions in a compact JSON document, then write that document to `./report.json`.

## Output contract

Write `./report.json` with exactly this shape:

```json
{
  "purpose": "one sentence saying what the project does",
  "audience": "who uses this (end users, library consumers, operators, etc.)",
  "security_surface": "a short paragraph naming the main components that handle untrusted input or hold sensitive state",
  "notes": "anything else a security reviewer should know before going deeper"
}
```

Keep each field to two sentences at most. Do not write any other files.

## How to read the repo

1. Read `README.md` if present. Quote from it if it is clear about purpose and audience.
2. Skim the top-level directory layout. Identify the language and the main entrypoint (e.g. `cmd/`, `bin/`, `app/`, `src/`).
3. Look for files that obviously handle external input: HTTP handlers, queue consumers, deserialisers, template renderers, auth middleware.
4. Look for files that obviously hold sensitive state: database setup, credential loading, session storage, key material.
5. If there is no README, infer purpose from package manifests (`package.json`, `go.mod`, `Cargo.toml`, `Gemfile`) and file layout.

Do not attempt to audit for specific vulnerabilities in this pass. That is a separate skill.
