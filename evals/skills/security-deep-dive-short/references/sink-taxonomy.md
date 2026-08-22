# Sink taxonomy

Use this reference to plan language-specific searches and classify ambiguous candidates. Start from the repository's language and framework primitives; the classes below are coverage prompts, not evidence that a matching call is vulnerable.

## Execution and interpretation

- Code execution: eval, dynamic dispatch, reflection to callables, computed module loading, executable regex features.
- Command execution: shell invocation and process arguments assembled by concatenation.
- Template and interpolation: unescaped data crossing into HTML, SQL, shell, regex, format strings, or log records.
- Deserialization: parsers that instantiate types, invoke constructors, or restore executable state.
- Agentic execution: untrusted content entering privileged model roles, tool definitions, tool arguments, or outputs consumed by an agent with broader capabilities.

## Files, formats, and networks

- Computed file reads, writes, deletes, links, permissions, imports, and module paths.
- Temporary files with predictable names, unsafe permissions, symlink following, or check/use gaps.
- Path normalization and containment decisions, including traversal, symlinks, and case folding.
- Archive extraction where entry names become filesystem paths.
- Hand-written and specialized parsers, decoders, configuration readers, protocol readers, and regex extractors. Check ambiguity, partial interpretation, and input-controlled work or allocation.
- Round trips such as parse/serialize, encode/decode, escape/unescape, and marshal/unmarshal. Check whether stored and reparsed values change meaning.
- Computed network targets, redirects, DNS resolution, proxy handling, and disabled TLS verification.

## Security decisions and state

- Authentication, authorization, session, CSRF, credential, rate-limit, and lockout decisions. Inspect absent, null, and empty security inputs and verify the protected operation fails closed.
- Object-level authorization when authenticated actors can select records by external identifiers.
- Bulk-bound request bodies that can copy server-owned fields such as tenant, owner, role, permission, workflow state, security flags, price, or balance. Shape validation is not field authorization.
- Public validation predicates whose dangerous outcome is returning the wrong answer.
- Cryptographic key derivation, nonce/IV handling, modes, padding, MAC verification, and secret comparison.
- Secret handling and logging where sensitive values cross storage, telemetry, model, or response boundaries.
- Shared mutable state, global hooks, registries, caches, environment mutation, and caller-visible metaprogramming.
- Check-then-act races across threads, processes, filesystems, or external state.

## API misuse

The library's own API surface, where the danger is that safe use is not the default use. Classify these entries `API misuse`. The sink is the API definition rather than a call site, so record the location of the default, the swallow or the field declaration.

- Dangerous defaults: a parameter, config key or constructor whose default is the unsafe choice, so a caller who passes nothing gets the weak behaviour. Verification off, a permissive mode, an algorithm or format chosen by the input, a limit that is absent rather than large. Grep the public signatures for security-shaped parameter names (`verify`, `check`, `validate`, `strict`, `insecure`, `allow`, `skip`, `max`, `timeout`) then read what each one defaults to.
- Silent failure: a security-relevant operation that reports nothing when it does not happen, so a caller cannot tell a passed check from a skipped one. A swallowed exception around a signature check, an ignored return code, a verifier whose "invalid" and "could not check" answers are the same value, a fallback that quietly downgrades. Grep for this language's swallow idioms.
- Primitive-typed secrets: keys, tokens, passwords and session identifiers held in the language's ordinary string or byte types, where the danger is what those types do for free: printing themselves in a debug or repr implementation, landing in a log line or an error message, serialising into a struct dump, comparing with the language's ordinary equality rather than a constant-time one. Grep for secret-shaped field names (`key`, `token`, `secret`, `password`, `credential`) then read their declared type.

## Native and resource safety

- Unsafe memory operations, bounds and lifetime errors, integer arithmetic feeding allocation or copy sizes, FFI, and type punning.
- Input-bounded allocation, recursion, iteration, decompression, regex work, and unbounded caches.
- Update, install, build, package, CI, workflow, plugin, and extension loading paths where untrusted artifacts gain execution or persistence.

For each candidate, record a repository-relative location, boundary, and consumed value before tracing it. The same primitive reached through different trust boundaries is more than one inventory entry. Comments, tests, fixtures, and unmodified third-party code are not first-party sinks.
