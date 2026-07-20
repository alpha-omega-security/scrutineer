# Swift scanning container

The repository under `./src` is a Swift package (SwiftPM). The job is to find **security vulnerabilities** in it.

## Runtime

- **Swift 6.3** — `swift`, `swiftc`, `swift-package` on PATH from `/opt/swift`. This is the pinned toolchain; use it for
  building, testing, and reproducing.
- **swiftly 1.1** — the Swift toolchain manager, initialised at `SWIFTLY_HOME_DIR=/opt/swiftly`. The pinned toolchain
  above is *not* managed by swiftly; swiftly is here so you can fetch a different one when `Package.swift` declares a
  `// swift-tools-version:` newer than 6.3, or when a bug only reproduces on a specific release. Install with
  `swiftly install <version>` and invoke with `swiftly run +<version> swift build` — plain `swift` stays the pinned
  toolchain regardless of `swiftly use`.
- **C toolchain** — `gcc`, `binutils`, `pkg-config`, `libc6-dev`, `libstdc++-14-dev`, plus the `curl`, `edit`, `icu`,
  `ncurses`, `sqlite3`, `xml2`, `uuid`, and `zlib` development headers. This is what lets C-interop targets and system
  module maps compile and link.
- **lldb is unavailable** — the swift.org tarball's `lldb` links `libpython3.11`, which trixie does not carry. Debug via
  print statements, sanitizer reports, or `swift-backtrace` output rather than an interactive debugger.

SwiftPM's `.build/` directory sits under the package root inside `/work/src`, which is exec-capable, so tests and
executables run in place. `TMPDIR=/work` keeps SwiftPM's compiled package manifests off the noexec `/tmp` mount, and
`SWIFTLY_HOME_DIR` is under `/opt` so swiftly-managed toolchains are executable too.

## Operating procedure

### Background

- SwiftPM packages are declared in `Package.swift`. `.library` products are libraries, `.executable` products are
  binaries, and `.testTarget` targets carry the test suite. A `Package@swift-*.swift` alongside means version-specific
  manifests.
- Swift is memory-safe by default. The high-value targets are the escape hatches: `Unsafe*Pointer`,
  `Unsafe*BufferPointer`, `withUnsafe*` closures, `unsafeBitCast`, `assumingMemoryBound`, and any `@_cdecl` /
  `@_silgen_name` boundary. Also inspect C-interop targets — a `.target` whose `path` contains `.c`/`.cpp`, or a
  `module.modulemap` under `Sources/*/include` — the C side gets none of Swift's guarantees.
- In safe Swift, focus on logic and design flaws: `try!`/force-unwrap on attacker input (crash-DoS), path traversal in
  `FileManager`/`URL(fileURLWithPath:)`, command injection through `Process`, missing actor isolation on shared mutable
  state, and incorrect crypto/auth.

### Code scanning preparations

Resolve dependencies and warm the build so C-interop targets compile:

```bash
cd src
swift package describe --type json   # products, targets, whether it's a multi-target package
swift package resolve
swift build --build-tests
```

If `Package.swift`'s `// swift-tools-version:` outstrips 6.3 and the build refuses, pull the matching toolchain and
prefix every `swift` invocation with `swiftly run +<version>`:

```bash
swiftly install <version>
swiftly run +<version> swift build
```

If dependency resolution fails with a network error the scan is offline — SwiftPM clones dependencies directly from
their git URLs, so a resolved `Package.resolved` and a populated `.build/checkouts/` may already be enough. Work from
what is present and note which checks you had to skip.

### Sanitizers

SwiftPM builds with sanitizers on the stable toolchain — no nightly required:

```bash
swift test --sanitize=address    # heap/stack overrun, use-after-free in Unsafe* / C interop
swift test --sanitize=thread     # data races, including across actor boundaries
```

`--sanitize=undefined` is Darwin-only and rejected on this Linux target; do not use it. Quote the sanitizer's
`SUMMARY:` line and the top of its stack as evidence.

### Creating reproducers

Every finding ships with a reproducer — code that, run in this container, actually triggers the issue. Paste the exact
command you ran and the verbatim output (fatal error, sanitizer report, observable side effect) into the finding.
Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so explicitly instead of
inventing one.

- **Test target (preferred):** add a file under `Tests/<ExistingTestTarget>/PocTests.swift` (Swift Testing's `@Test`
  or XCTest's `XCTestCase`) and run `swift test --filter Poc`. If the package has no test target, add a `.testTarget`
  to `Package.swift`. The test output is the evidence.
- **Standalone package:** `swift package init --type executable --name poc` in `/work/poc`, add
  `.package(path: "/work/src")` and the product under `dependencies:` in its `Package.swift`, write the trigger in
  `Sources/poc/main.swift`, and `swift run --package-path /work/poc`.
- **Memory corruption in `Unsafe*` / C interop:** reproduce under `--sanitize=address` and quote the report.
- Drive the vulnerable function directly with the malicious input rather than booting the whole executable — it keeps
  the reproducer minimal and the evidence trivial to verify.

## Out of scope

- Resolved third-party source under `.build/checkouts/` — not the target of this scan unless a finding specifically
  pivots through one. Still report *known-vulnerable* dependencies, especially C libraries wrapped by a system-module
  target.
