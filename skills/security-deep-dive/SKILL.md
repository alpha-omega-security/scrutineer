---
name: security-deep-dive
description: Audit first-party source for security vulnerabilities using an inventory-first, six-step per-sink methodology. Use when you want a thorough scan that distinguishes real findings from pattern matches and records both in a machine-readable report. The target is this codebase's own code, not its dependencies.
license: MIT
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: findings
  scrutineer.max_turns: 120
  scrutineer.model: max
  scrutineer.requires:
    - threat-model
    - semgrep
    - repo-overview
    - advisories
    - packages
    - dependents
    - maintainers
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
- `GET {api_base}/repositories/{repository_id}/scans?skill=threat-model&status=done` — then `GET /scans/{id}` and read `report` for the structured threat model, if one ran (Phase 1 boundaries)
- `GET {api_base}/repositories/{repository_id}/findings?skill=semgrep` — static-analysis hits from a prior semgrep scan, if one ran (Phase 1 seeds)
- `GET {api_base}/repositories/{repository_id}/scans?skill=repo-overview&status=done` — then `GET /scans/{id}` for the brief summary

If any of those return an empty list or a non-200 status, the upstream scans were not run yet or the API is unreachable; fall back to your own reasoning over `./src`.

## Phase 1: Inventory

Fetch the threat-model scan first: `GET {api_base}/repositories/{repository_id}/scans?skill=threat-model&status=done`, take the most recent id, then `GET {api_base}/scans/{id}` and parse the `report` field as JSON. If you get one, it already holds the trust map: `components` and `out_of_scope` say which code is in the model, `adversaries` names the actors, `trust_boundaries` describes the line per component, and `entry_points` is the per-parameter table Step 2 looks up. Fill this report's `boundaries[]` from those fields instead of deriving from scratch — one row per actor (callers and adversaries), with `trusted` set from whether the actor appears in `adversaries.in_scope` and `source` set from the threat model's `provenance`/`source` — then skip to listing sinks. Treat threat-model entries with `provenance: "inferred"` as working hypotheses you may overturn during Phase 2; `"documented"` entries cite a file:line you can re-read. An empty list or a non-200 means the threat-model skill has not run on this repository yet, in which case derive the boundaries yourself as below.

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
- Authorization and access control: applies ONLY if the boundaries named in Phase 1 include authenticated users with distinct data. Enumerate handlers loading a record by a request-supplied ID without comparing the loaded record's owner to the session principal. The danger is Broken Object Level Authorization (IDOR).
- Agentic: anything that hands data to a language model or runs a tool on a model's behalf. Untrusted input concatenated into a prompt, system message, or tool argument; tool or function definitions exposed to a model whose scope is broader than the caller's; agent loops with no iteration or cost cap; system-prompt text reachable through error paths or echoed back in responses; calls to a paid model API where the trigger is reachable from unauthenticated input. Grep for the provider SDKs (anthropic, openai, langchain, llama-index, vertexai, bedrock) and for `messages=`, `tools=`, `system=`, `.invoke(`, `.run(` on agent objects.

Before grepping, fetch `GET {api_base}/repositories/{repository_id}/findings?skill=semgrep`. If a semgrep scan has already run on this repository each entry has `location` (file:line), `cwe`, and `title` (the semgrep rule id). Use these as anchors: open each location, confirm the line is a sink and not a comment or test fixture, and add it to the inventory under the matching sink class. They are starting points, not the inventory; semgrep's rule packs miss whole classes (round-trip integrity, agentic, validation, shared mutable state) and produce false positives, so your own grep sweep below still runs in full. An empty list means semgrep has not run yet or found nothing; carry on without it.

Read the entire source tree. Grep exhaustively — every code-exec primitive this language has, every shell-out, every file-open, every unsafe block. The grep finds them; you confirm each is a real sink and not a comment, test fixture, or third-party code vendored into this repo unmodified from upstream. Modified vendored code is first-party. (The note in the introduction about findings following vendored copies is the other direction: this repo's own code copied outward into forks or downstream vendors.)

## Phase 2: Per-sink checklist

Work through the inventory in order. For each sink, do these steps in this order. Write down the result of each step. Stop when a step rules the sink out, and record which step did.

### Step 1: Trace the input

What value reaches the sink. Trace backwards through the code from the sink to where the value originates. Name each hop: this variable, assigned from this method's return, which reads this argument, which the caller sets from this. Stop when you reach the boundary of the library — a public method's parameter, a config value, an environment read, a file the library opens.

If the trace dead-ends inside the library — the value is a constant, a hardcoded path, the library's own internal data — write "internal, no external input reaches this" and move to the next sink.

### Step 2: Trust boundary

Where the input enters the library, who controls it. Check it against the boundaries you named at the start of Phase 1. The sink's input crosses one of them; name which one. When a threat-model report was loaded, look the sink's entry function and parameter up in its `entry_points` table and cite the row by index (`entry_points[i]`): `attacker_controllable: "no"` rules the sink out as `out_of_model_trusted_input`; `"conditional"` means the row's `condition` is the precondition you carry into Step 6.

The attacker is not the developer calling the library. If the value at the boundary is a parameter the developer chose, a config the operator wrote, a path the user set in their own environment — that is not attacker-controlled in this library's threat model. The library is doing what it was told.

If the value at the boundary is network input, file contents from outside the trust domain, an environment variable that crosses a privilege boundary, deserialised data, or anything else the application receives from outside — it is attacker-controlled.

The test is documentation, not plausibility. A docstring describing a multi-process workflow puts that workflow in scope; cite it. A README showing the operator setting a value means the operator is trusted; cite it. A scenario you constructed because the finding needs a boundary that standard use does not have — that is the report telling you the finding is not real.

Before concluding trusted, check this is the only path. The trace backwards finds writers; it does not find providers — public APIs that take the sink's input as an argument. Grep public signatures and docstrings for the sink's input (the filename, the path pattern, the key). If a public method takes it, that is a second boundary with its own judgment.

For sinks the library installs into the caller's environment — monkeypatches, global hooks, methods added to core classes — the boundary question is different. The library chose to install the gadget; that choice is in scope. Whether any consumer has wired hostile input to it is a reach question for Step 5, not a reason to stop here. Record: "library installs this, input depends on consumer wiring" and continue.

For agentic sinks, the boundary is crossed when user-controlled content reaches a system prompt, tool message, or tool argument without being delimited or stripped. A user string interpolated into the user role of a chat message is expected; the same string landing in the system role, a tool definition, or the input of a tool the model then executes is the model acting on attacker instructions. Treat tool output the model reads back (web fetches, file reads, search results) as untrusted input too: a fetched page that says "ignore previous instructions" is the same shape as a user saying it.

If the boundary check rules the sink out — input is internal, or comes from a trusted documented source — write the reason and move to the next sink.

Even where the input is attacker-controlled, check whether the project has already mitigated the danger. The mitigation may live in a centralised handler, a framework default that escapes or binds, a build flag, a sanitiser library, a type-system rule, or a project-wide lint. Grep for it — the directive, the helper, the import, the config line. If the control is in place, rule the sink out at this step and cite the file and line of the existing control in the reason. Do not recommend adding a control the project already has; if the existing one is stricter than what you would have suggested, an analyst applying the advice literally weakens the project. As an example: a template `var-in-href` warning resolves here in a project whose request lifecycle sets `Content-Security-Policy: script-src 'self'`, with the rule-out reason citing that handler.

Even where the input is attacker-controlled, check the precondition does not subsume the conclusion. If reaching the sink requires the attacker to already hold a capability equal to or stronger than what the sink grants — write access to a directory documented as holding executable hooks, MITM position on a connection the finding claims to let them influence — the finding is circular. The attack path's first step already arrives at its last. Write "precondition subsumes conclusion" and move to the next sink.

### Step 3: Validate

Write a reproduction script and run it. The script demonstrates that the sink does what you traced — hostile input in, dangerous behaviour out. Paste the script and its output.

Before concluding you cannot reproduce, enumerate the mechanisms that produce the kind of value the sink consumes. If the sink takes a path: argv, environment, glob expansion, archive extraction. If the sink takes an identifier: dynamic-definition primitives, struct-from-hash, deserialisation that turns keys into accessors, ORM attribute generation. If the sink takes a host: user input, redirect targets, DNS, service discovery. Write the list. Try each.

Verify against the published artefact, not just git. If `GET {api_base}/repositories/{repository_id}/packages` returns at least one package, fetch its latest release from the registry, unpack it, and confirm the sink is in the lines you said; HEAD diverges from releases. If it returns an empty list (CLI, service, monorepo, unpublished) the git checkout is the artefact and this check is a no-op.

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

Record the verdict as `reachability`: `reachable` if a public entry point in the shipped artefact reaches the sink with attacker-controlled input; `harness_only` if the only path you can demonstrate is a test driver, fuzz target, or example program calling an internal function directly; `unclear` if you could not establish either. A `harness_only` finding is a real bug worth reporting upstream but is not disclosable as a vulnerability on its own.

### Step 6: Rate

Severity, given everything above.

Critical: works on a fresh install with no preconditions. Any precondition disqualifies it.

High: realistic preconditions a normal deployment satisfies. Reach data that shows an exposed dependent strengthens this; absence does not by itself weaken below what the sink supports.

Medium: significant attacker positioning, unusual configuration, or a chain of conditions. Or: a library-installed gadget where the wiring is plausible but you found no consumer that does it.

Low: unrealistic preconditions, narrow impact, or the deployment environment most users run mitigates it.

Confidence, separately: what you are certain of (the sink does X, per reproduction) versus what depends on context (an attacker reaches it if Y). Name the conditions.

Record `quality_tier` per sink class. For memory safety: heap overflow, use-after-free, type confusion, and controllable write are `high`; stack exhaustion, assertion failure, and null-deref at a fixed offset are `low`. For injection: shell or eval with an attacker string is `high`; log injection is `low`. A `low` tier hit is a signpost, not a stopping point — when you land on one, keep tracing the same data path for a higher-tier sink nearby before writing it up.

## Fan-out for large repositories

One agent can audit a small repository end to end. For a large one — many packages, tens of thousands of lines, dozens of sinks — fan the work out across subagents. Both phases parallelise: split Phase 1's grep-and-confirm sweep by directory or package so each subagent inventories one slice, and split Phase 2 by sink so each subagent runs the six-step checklist over a batch.

The subagents you spawn do not see this SKILL.md. They get only the prompt you write for them and the shared working directory, where `report.json` and `schema.json` sit in plain view. Left to infer the deliverable, each subagent writes `./report.json` and overwrites the previous one, silently discarding every other subagent's work — and a clobbered report is still schema-valid, so nothing downstream flags the loss. That is the failure this section exists to prevent. When you delegate:

- Tell every subagent, in its prompt, not to write or touch `./report.json`. That file is yours to write, once, at the end.
- Give each subagent a distinct scratch file for its slice — `./inventory-<area>.json` for a Phase 1 slice, `./dispositions-<area>.json` for a Phase 2 batch — and have it return that path. Distinct names mean two subagents never write the same file, so single-writer is mechanical rather than a thing you have to trust the agents to honour. (Returning the slice as message text works for small slices but truncates and re-transcribes lossily on large ones; on a repository big enough to need fan-out, prefer the scratch file.)
- You are the sole writer of `./report.json`. Read back every scratch file, union the slices, and write the one report yourself, per Output below.

## Output

Write your report to `./report.json` to match `./schema.json`. You are the only agent that writes this file; if you fanned out, consolidate every subagent's scratch file into it first (see Fan-out above). The consolidation is a union, not a copy of the last slice: every sink any subagent found must survive into the merged report. Union the inventories, dedupe by file, line, and sink class — a sink two subagents each reported once is one entry — and then place each entry by its disposition. A sink no subagent decided is a gap to resolve before you write, not an entry to drop. Every inventory sink must appear either in `findings[].sinks` or in `ruled_out[].sinks`. When a threat-model report was loaded, each `ruled_out[].reason` opens with one of its disposition labels (`out_of_model_trusted_input`, `out_of_model_adversary`, `out_of_model_unsupported_component`, `out_of_model_non_default_build`, `by_design_disclaimed`, `known_non_finding`, `model_gap`) followed by the citation into the model that backs it; without a loaded model, free-text reasons are fine. Use `findings: []` for a clean report. Set `repository` to the URL string from `context.json`'s `repository.url` (a string, not the object), `commit` to the HEAD sha of `./src`, and `artefact` to the package coordinate string (purl or `name@version`) you verified against in step 4. Set `spec_version` to `12`. Use today's date for the `date` field.
