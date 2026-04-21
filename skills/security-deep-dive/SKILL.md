---
name: security-deep-dive
description: Audit first-party source for security vulnerabilities using an inventory-first, six-step per-sink methodology. Use when you want a thorough scan that distinguishes real findings from pattern matches and records both in a machine-readable report. The target is this codebase's own code, not its dependencies.
license: MIT
metadata:
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
---

# security-deep-dive

Audit the first-party source for security vulnerabilities. The target is this codebase's own code; do not report that a dependency has a CVE. A finding is valid only if the vulnerable logic lives here. If the same vulnerable code exists in a fork, a sibling project, or a vendored copy, note it; the finding follows the code.

The audit has two phases. Phase 1 produces an inventory of every sink in the codebase. Phase 2 works through the inventory and decides on each entry. The inventory is part of the report, not scratch work — two runs against the same commit should produce the same inventory regardless of which sinks catch attention first.

Workspace layout:
- `./src` — the cloned repository
- `./context.json` — repo identity plus a `scrutineer` block with `api_base`, `token`, `repository_id`. If `scrutineer.scan_subpath` is set, scope every inventory, trace, and validation step to `./src/{scan_subpath}` only — do not reach outside that sub-folder for code analysis, and treat the sub-folder as the project root for all relative locations in the report. Other repositories' concerns (packages, advisories, maintainers) remain repo-wide. If prior scans of this repo have run (metadata, packages, advisories, dependents, maintainers), their results are available at the API documented below; use them instead of re-fetching from upstream.
- `./report.json` — write your final report here
- `./schema.json` — the JSON schema your report must conform to

Scrutineer API (call with `Authorization: Bearer {token}`):
- `GET {api_base}/repositories/{repository_id}` — canonical metadata
- `GET {api_base}/repositories/{repository_id}/packages` — published packages with dependent counts
- `GET {api_base}/repositories/{repository_id}/advisories` — existing CVE/GHSA records (prior art)
- `GET {api_base}/repositories/{repository_id}/dependents` — top dependents with download counts (reach)
- `GET {api_base}/repositories/{repository_id}/scans?skill=repo-overview&status=done` — then `GET /scans/{id}` for the brief summary

If any of those return an empty list, the upstream scans were not run yet; fall back to your own reasoning over `./src`.

## Phase 1: Inventory

Before listing sinks, name the trust boundaries this codebase has. For a small library this is one or two lines: who calls it, what they pass, where external data enters. For something larger — a package manager, a server, a build tool — it is a table: each actor, what they control, whether they are trusted, and where you found that documented. Write it down once. The per-sink boundary checks in Phase 2 reference what you wrote here; they do not re-derive it per sink.

The boundaries you name should account for every public entry point. A library mostly called one way but with a documented secondary API has two boundaries, not one. A file the library writes and reads back is one boundary; the same file accepted as an argument from a public API is a second. List both. Step 2 checks each sink against this list; a missing boundary means a misjudged sink.

Then list every sink. Do not judge any of them yet. A sink is any place where the code does something that would be dangerous if the input were hostile, regardless of whether you currently think the input is hostile.

For each sink, record: file, line, sink class, what it consumes. Nothing else yet.

Sink classes to enumerate. The classes are conceptual; the language you are auditing has its own primitives for each. Before grepping, write down what this language calls each thing — what its eval is, what its shell-out is, what its unsafe-deserialise is. That list is your grep targets.

- Code execution: anything that treats data as code. String eval, dynamic method dispatch on a computed name, reflection that resolves a name to a callable, code loaded from a computed path, regex engines with embedded-code constructs.
- Command execution: anything that hands a string to a shell or spawns a process where arguments are built by concatenation rather than passed as an array.
- File operations: open, read, write, delete, chmod, link, where the path is computed. Includes the language's module/import mechanism if it accepts dynamic paths.
- Path handling: join, normalise, canonicalise, where the result is used for access decisions. Traversal, symlink following, case-fold confusion on case-insensitive filesystems.
- Archive extraction: any unpack of tar, zip, or similar where entry names become filesystem paths.
- Deserialisation: any format that can instantiate types or call constructors during parse. The safe-parse vs unsafe-load distinction exists in most languages; find which is which here.
- Template or interpolation: any place a value reaches another interpreted context — HTML, SQL, shell, regex, format strings, log lines — without escaping for that context.
- Network: clients that follow redirects, accept URLs from input, resolve hostnames from data, or make requests to computed targets. DNS resolution, TLS verification settings, proxy handling.
- Validation: for libraries whose contract is "I tell you whether this input is safe" — every public predicate or validator method. The sink is the return value; the danger is returning the wrong answer.
- Cryptography: key derivation, IV handling, mode and padding selection, MAC verification, any comparison of secret values.
- Memory safety: where the language has an unsafe escape hatch — raw pointers, unchecked indexing, manual allocation, foreign function interfaces, type-punning casts. Where the language's safety guarantees are explicitly suspended. For C and C++, this is the whole codebase; the inventory is bounds, lifetimes, and integer arithmetic that feeds them.
- Shared mutable state: anything that writes to a location other code reads without coordination. Globals, prototype chains, module-level caches, environment variables, signal handlers. The danger is one input poisoning what another sees.
- Concurrency: check-then-act sequences where the world can change between the check and the act. File existence before open, permission before access, anything that races a filesystem or another thread.
- Resource consumption: allocation, recursion, iteration where the bound comes from input. Unbounded caches, regex patterns prone to catastrophic backtracking, decompression where the ratio is attacker-controlled.
- Reflection or metaprogramming primitives the library installs into the caller's environment: monkeypatches, prototype extensions, import hooks, global registrations, anything that changes behaviour outside the library's own namespace.
- Round-trip integrity: any pair of operations where one is meant to be the inverse of the other. parse and serialize, encode and decode, marshal and unmarshal, escape and unescape. The sink is the pair, not either operation alone. The danger is asymmetry: if `decode(encode(x))` does not equal `x`, or `encode(decode(s))` does not produce the same `s` on re-decode, then a value can change meaning across a store-and-reload cycle. A validation that runs at parse time can be bypassed by what serialize emits. List every such pair the library exposes; the inventory entry is the pair.

Read the entire source tree. Grep exhaustively — every code-exec primitive this language has, every shell-out, every file-open, every unsafe block. The grep finds them; you confirm each is a real sink and not a comment, test fixture, or vendored dependency.

## Phase 2: Per-sink checklist

Work through the inventory in order. For each sink, do these steps in this order. Write down the result of each step. Stop when a step rules the sink out, and record which step did.

### Step 1: Trace the input

What value reaches the sink. Trace backwards through the code from the sink to where the value originates. Name each hop: this variable, assigned from this method's return, which reads this argument, which the caller sets from this. Stop when you reach the boundary of the library — a public method's parameter, a config value, an environment read, a file the library opens.

If the trace dead-ends inside the library — the value is a constant, a hardcoded path, the library's own internal data — write "internal, no external input reaches this" and move to the next sink.

### Step 2: Trust boundary

Where the input enters the library, who controls it. Check it against the boundaries you named at the start of Phase 1. The sink's input crosses one of them; name which one.

The attacker is not the developer calling the library. If the value at the boundary is a parameter the developer chose, a config the operator wrote, a path the user set in their own environment — that is not attacker-controlled in this library's threat model. The library is doing what it was told.

If the value at the boundary is network input, file contents from outside the trust domain, an environment variable that crosses a privilege boundary, deserialised data, or anything else the application receives from outside — it is attacker-controlled.

The test is documentation, not plausibility. A docstring describing a multi-process workflow puts that workflow in scope; cite it. A README showing the operator setting a value means the operator is trusted; cite it. A scenario you constructed because the finding needs a boundary that standard use does not have — that is the report telling you the finding is not real.

Before concluding trusted, check this is the only path. The trace backwards finds writers; it does not find providers — public APIs that take the sink's input as an argument. Grep public signatures and docstrings for the sink's input (the filename, the path pattern, the key). If a public method takes it, that is a second boundary with its own judgment.

For sinks the library installs into the caller's environment — monkeypatches, global hooks, methods added to core classes — the boundary question is different. The library chose to install the gadget; that choice is in scope. Whether any consumer has wired hostile input to it is a reach question for Step 5, not a reason to stop here. Record: "library installs this, input depends on consumer wiring" and continue.

If the boundary check rules the sink out — input is internal, or comes from a trusted documented source — write the reason and move to the next sink.

Even where the input is attacker-controlled, check the precondition does not subsume the conclusion. If reaching the sink requires the attacker to already hold a capability equal to or stronger than what the sink grants — write access to a directory documented as holding executable hooks, MITM position on a connection the finding claims to let them influence — the finding is circular. The attack path's first step already arrives at its last. Write "precondition subsumes conclusion" and move to the next sink.

### Step 3: Validate

Write a reproduction script and run it. The script demonstrates that the sink does what you traced — hostile input in, dangerous behaviour out. Paste the script and its output.

Before concluding you cannot reproduce, enumerate the mechanisms that produce the kind of value the sink consumes. If the sink takes a path: argv, environment, glob expansion, archive extraction. If the sink takes an identifier: dynamic-definition primitives, struct-from-hash, deserialisation that turns keys into accessors, ORM attribute generation. If the sink takes a host: user input, redirect targets, DNS, service discovery. Write the list. Try each.

Verify against the published artefact, not just git. Fetch the latest release from the registry, unpack it, confirm the sink is in the lines you said. HEAD diverges from releases.

For round-trip pairs, the reproduction is the round-trip. Construct values containing characters that are structural in the serialized form — delimiters, separators, escape sequences, percent-encoded equivalents of any of those — and run them through `decode(encode(x))` and `encode(decode(s))`. If the output differs from the input, trace what changed. A character the decoder interprets but the encoder emits raw is the asymmetry. Then check what consumes the serialized form: if anything stores it and re-parses later, the validation that ran on the first parse does not cover the second.

If the reproduction fails — the sink is gated by a check you missed, the input is sanitised on the way in, the type system prevents it — write what stopped it and move to the next sink.

### Step 4: Prior art

Check scrutineer's advisory cache first: `GET {api_base}/repositories/{repository_id}/advisories`. Every advisory already published against this repository's packages shows up here, with CVSS, classification, packages affected, and the original URL. Anything that overlaps with your finding is prior art — cite the advisory uuid and url.

Then search the repo's issues and PRs, open and closed. `git log --all --grep` and `git log -S` for the function name and key strings. Read maintainer comments. A maintainer who has already considered this and declined is a different conversation than one who has never seen it; quote the comment.

Check this package's history, not the weakness class's. A CVE in another project for the same pattern is context. A related fix in this project that left a sibling unfixed, an issue closed as wontfix, a comment thread where the design was debated — that is what you want.

Check whether the behaviour is required by a standard the library implements. An RFC, a wire format, a protocol spec. A standard that allows a dangerous choice and a library that took it stays in scope. A standard that requires the behaviour moves the finding to the standard; cite the section, write "required by [standard, section]" in the ruled-out list, and move to the next sink.

Note what you searched and what you found, even if nothing.

### Step 5: Reach

For libraries published to a registry: start with scrutineer's dependents cache: `GET {api_base}/repositories/{repository_id}/dependents`. It returns the top dependents already ranked by `dependent_repos` and `downloads`, with registry and repository URLs. Use this list; do not re-hit packages.ecosyste.ms.

Unpack the published version of each — not git HEAD; the released artefact. Read how it calls this sink. Some will not be exposed (safe variant, mitigating flag, migrated off); note these as counterexamples with line numbers. The first significant exposed dependent is the headline; if it is itself widely depended on, follow it one level.

If the dependents list is empty the dependents skill has not run yet — fall back to packages.ecosyste.ms directly.

For targets that are not library-shaped — package managers, servers, build tools — trace the input paths through the trust tiers from Phase 1 instead. Who can supply this input under each documented deployment.

Reach is data, not a verdict. "No exposed dependent in the top N I checked" is a fact for the report. It does not make the sink safe — the search was bounded, private code exists, future code will be written.

### Step 6: Rate

Severity, given everything above.

Critical: works on a fresh install with no preconditions. Any precondition disqualifies it.

High: realistic preconditions a normal deployment satisfies. Reach data that shows an exposed dependent strengthens this; absence does not by itself weaken below what the sink supports.

Medium: significant attacker positioning, unusual configuration, or a chain of conditions. Or: a library-installed gadget where the wiring is plausible but you found no consumer that does it.

Low: unrealistic preconditions, narrow impact, or the deployment environment most users run mitigates it.

Confidence, separately: what you are certain of (the sink does X, per reproduction) versus what depends on context (an attacker reaches it if Y). Name the conditions.

## Output

Write your report to `./report.json`. It must validate against `./schema.json`. Every inventory sink must appear either in `findings[].sinks` or in `ruled_out[].sinks`. Use `findings: []` for a clean report. Read `./context.json` for the repository url, default branch, and other host-provided facts if you need them for the `repository`, `commit`, and `artefact` fields. Set `spec_version` to `10`. Use today's date for the `date` field.
