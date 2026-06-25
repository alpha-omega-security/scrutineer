# Rust scanning container

The repository under `./src` is a Rust project, built with Cargo. The job is to find **security vulnerabilities** in it.

## Runtime

- **rustup 1.29** — manages toolchains and components; `RUSTUP_HOME=/usr/local/rustup`, `CARGO_HOME=/usr/local/cargo`,
  both on PATH and writable.
- **Rust 1.96 (stable)** — the default toolchain. `cargo` drives builds, tests, and runs; `rustc` is the compiler it
  invokes. Use stable for normal building, testing, and reproducing.
- **Nightly** with the `rust-src` component — required for the `-Z` flags that the rest of this profile relies on
  (sanitizers, `-Zbuild-std`, Miri). The pinned toolchain name is exported as `$RUST_NIGHTLY_VERSION`
  (e.g. `nightly-2026-06-24`); select it per-invocation with `cargo +$RUST_NIGHTLY_VERSION` /
  `rustc +$RUST_NIGHTLY_VERSION`. The bare `nightly` channel is not installed.
- **Miri** — installed on the nightly toolchain and already initialized (`cargo +$RUST_NIGHTLY_VERSION miri setup`).
  It interprets MIR to catch undefined behaviour (out-of-bounds, use-after-free, invalid aliasing, data races,
  uninitialized reads) that compiles and runs cleanly under a normal build. Miri can also interpret for a foreign
  target with `--target <triple>`, which is useful for pointer-width- or endianness-dependent bugs without
  cross-compiling.
- **C toolchain** — `build-essential` (gcc/g++), `pkg-config`, `autoconf`/`automake`, plus the `openssl`
  (`libssl-dev`) and `libssh` (`libssh-dev`) development headers. This is what lets `-sys` crates and `build.rs`
  scripts compile and link their C/FFI code in-place.

Dependencies and Cargo's caches resolve under `CARGO_HOME=/usr/local/cargo`, which is on an exec-capable path, so the
test and example binaries Cargo builds can run. There is no bundled `clang`; sanitizer builds use the LLVM runtime that
ships with the nightly `rust-src` (see below). If you need to instrument linked C code with a matching clang runtime
(`-Zexternal-clangrt`), install `clang` with `apt-get` first.

## Operating procedure

### Background

- A `-sys` crate suffix or a `build.rs` build script usually means external C/FFI code is compiled and linked in. Treat
  that boundary as a prime target: scrutinize both the upstream C dependency and how the Rust side calls into it
  (pointer/length handling, ownership of returned buffers, error-code checks).
- In `unsafe` blocks, look for the classic memory-safety failures — out-of-bounds, use-after-free, double-free, invalid
  `transmute`, aliasing violations, integer overflow feeding an allocation or index, and broken invariants that safe
  callers can violate. In safe Rust, focus on logic and design flaws: panics on attacker input (DoS), path traversal,
  deserialization, command/SQL injection, `unwrap`/`expect` on untrusted data, and incorrect auth/crypto.

### Code scanning preparations

Inspect the manifest to learn the shape of the project, then warm the build so dependencies resolve and any `-sys`
crates compile:

```bash
cd src
cargo metadata --no-deps --format-version 1   # crate names, targets, whether it's a workspace
cargo build --all-targets                     # compile lib, bins, examples, and tests
```

`Cargo.toml` tells you what you're scanning: a `[lib]` table (or a top-level `src/lib.rs`) is a library, `[[bin]]`
entries (or `src/main.rs`) are binaries, and `[workspace]` means multiple member crates — build and reason about each.
Note any `[features]`, since vulnerable code may sit behind a non-default feature that must be enabled with
`--features <name>` (or `--all-features`) to compile and reach it.

- **Libraries:** add an integration test under `tests/` that calls the public API, or scaffold a consumer crate with
  `cargo new /tmp/consumer` and add the target as a path dependency (`mylib = { path = "../src" }`).
- **Binaries:** prefer an integration test that drives the vulnerable code path, or run the built binary from
  `target/debug/` against crafted input.

Dependencies resolve from `Cargo.toml`/`Cargo.lock`; there is no separate install step — Cargo fetches crates on first
build. A downloaded `.crate` file (e.g. under `$CARGO_HOME/registry/cache` or fetched from crates.io) is a gzipped
tarball: `tar -xzf foo-1.2.3.crate` unpacks it. If a fetch fails with a network error the scan is offline: work from
the source and vendored crates already present and note which checks you had to skip.

### Sanitizers

Rust's sanitizers are nightly-only and need std rebuilt with instrumentation, so they require an explicit `--target` and
`-Zbuild-std` (the `rust-src` component is already installed):

```bash
cd src
RUSTFLAGS="-Zsanitizer=address" \
  cargo +$RUST_NIGHTLY_VERSION test -Zbuild-std --target x86_64-unknown-linux-gnu
```

Supported `-Zsanitizer` kinds include `address`, `leak`, `memory`, `thread`, `hwaddress`, `memtag`, `cfi`, `dataflow`,
`realtime`, and `shadow-call-stack`. AddressSanitizer (`address`) is the workhorse for `unsafe`/FFI memory bugs;
ThreadSanitizer (`thread`) for data races; MemorySanitizer (`memory`) for uninitialized reads. For builds that also
instrument linked C code, add `-Zexternal-clangrt` (requires `clang`, see Runtime). Quote the sanitizer's `SUMMARY:`
line and the top of its stack as evidence.

### Creating reproducers

Every finding ships with a reproducer — code that, run in this container, actually triggers the issue. Paste the exact
command you ran and the verbatim output (panic message, sanitizer report, Miri diagnostic, observable side effect) into
the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so explicitly
instead of inventing one.

- **Integration test (preferred):** drop `tests/poc.rs` next to the project and run
  `cargo test --test poc -- --nocapture`. The test output is the evidence. Add `--features <name>` if the sink is
  feature-gated.
- **Standalone crate:** `cargo new /tmp/poc`, add the target as a dependency (`path` or version) in its `Cargo.toml`,
  write the trigger in `src/main.rs`, and `cargo run --manifest-path /tmp/poc/Cargo.toml`.
- **Undefined behaviour / `unsafe`:** write a test that exercises the suspect code and run it under Miri —
  `cargo +$RUST_NIGHTLY_VERSION miri test --test poc`. A Miri error is strong evidence of UB; note that Miri can't
  execute most FFI, so for `-sys`/C boundaries fall back to an AddressSanitizer build instead.
- **Memory corruption in `unsafe`/FFI:** reproduce under AddressSanitizer (see Sanitizers) and quote the report.
- Drive the vulnerable function directly with the malicious input rather than booting the whole program — it keeps the
  reproducer minimal and the evidence trivial to verify.

## Out of scope

- Third-party dependencies under `CARGO_HOME` (`/usr/local/cargo/registry`) — not the target of this scan unless a
  finding specifically pivots through one. Still report *known-vulnerable* dependencies, especially C libraries pulled
  in by `-sys` crates: when a `-sys` crate or `build.rs` builds and links C code, that boundary and the linked library
  are in scope.
