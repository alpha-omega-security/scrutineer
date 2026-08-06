# Parsers and trust boundaries

Parser audits must separate the component that consumes untrusted bytes from
the tools and adapters around it. Do not merge library and CLI assumptions.

## Boundary partition

- Library API: caller-provided buffers, lengths, encodings, callbacks,
  allocators, and incremental-feed behavior.
- CLI: argv, environment, stdin, local paths, temporary files, and output
  destinations. Decide whether a realistic attacker can influence each.
- Service or plugin: network framing, IPC, host callbacks, shared process
  privileges, and concurrency.
- FFI binding: runtime-owned strings/slices, pinning, encoding conversion,
  exceptions or panics, and ownership transfer.

Record the affected build product for each candidate. Code shared by a parser
library and a CLI can have different source controls and impacts.

## Parser state and sizing

- Trace incremental chunks across carry buffers, token boundaries, and final
  flush. Per-chunk checks may not bound accumulated state.
- Distinguish bytes, code units, Unicode scalar values, elements, and output
  expansion. Verify conversions before allocation and access.
- Check length-prefixed fields before arithmetic, allocation, and pointer
  advance. Confirm nested lengths remain inside the containing extent.
- Review sentinel and terminator writes after exact-capacity inputs.
- Check recursion, nesting, entity expansion, decompression, and repeated
  growth only when they produce a security-relevant availability failure under
  a realistic boundary.
- Callbacks may re-enter, suspend, replace buffers, or destroy parser state.
  Follow the documented and implemented callback contract.

## Temporary files

Review CLI and parser helpers that materialize untrusted content:

- creation race and symlink behavior;
- permissions and inherited umask;
- predictable names and shared directories;
- cleanup on error, cancellation, and signal paths;
- whether a path is reopened after validation;
- whether content or metadata crosses users or privilege boundaries.

Do not call every temporary-file weakness memory corruption. Route path,
permission, or disclosure findings to the appropriate audit unless it also
causes a proven memory-safety violation.
