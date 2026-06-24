# Rust scanning container

The repository under `./src` is a Rust project.

## Runtime

- **rustup** - Rust toolchains and  tools are installed using the `rustup` tool. Both the latest stable and nightly are installed.
- **Rust 1.96** - `cargo` / `rustc` (a pinned rust toolchain installed with `rustup`). 
- `cargo` - The rust package manager and compiling tool to use. Use this tool for building and running Rust projects.
- `rustc` - The underlying rust compiler invoked by `cargo`
- C toolchain (`build-essential`, `pkg-config`) plus the `openssl`/`libssh` dev headers
- `miri` - an Undefined Behavior detection tool for Rust. It can run binaries and test suites of cargo projects and detect unsafe code that fails to uphold its safety requirements.

## Operating procedure

### Additional Knowledge

- Some rust packages have the `-sys` name extension. This is a standard, and not a rule, but suggests the package imports external
  C dependecies. You can also identify this if a `build.rs` file exists. In these cases, it means this crate also imports this external
  C code. Make sure to give special attention to these cases, as they suggest FFI boundaries and sources of undefined behavior both in the
  third party dependecy and in the Rust usage of it. This means there is a boundary of different safety garuntees which requires 
  special attention.
- Rust code specifically has `unsafe` code which ignores Rust safety rules. Please consider both memory-safety vulnerabilities and other
- standard vulnerabilities in these cases. In pure Rust code, you are focusing more on logic and design vulnerabilities.

### Code scanning preparations

Download a given .crate file and extract it as the source code. Inspect the extracted Cargo.toml file - a project may be a 
library or a binary, so you need to determine whether you need to use integration tests or directly invoking the binary if 
performing tests. 

For libraries, you may need to create your own new project with `cargo new`, which utilizes the library. You can also create 
integration tests for the same purpose. Always prioritize an integration test over a new test project.

For binaries, leverage creating new integration tests for scanning and identification. 

Miri is installed, and should be used to scan and identify for cases of undefined behavior. 


### Address Sanitizer Support
ASAN is available for builds during inspection, and can be instantiated during a build using an environmental variable RUSTFLAGS='-Zsanitizer=<flags>'

To enable a sanitizer compile with `-Zsanitizer=address`, `-Zsanitizer=cfi`, `-Zsanitizer=dataflow`,`-Zsanitizer=hwaddress`,`-Zsanitizer=leak`,`-Zsanitizer=memory`, 
`-Zsanitizer=memtag`, `-Zsanitizer=realtime`, `-Zsanitizer=shadow-call-stack` or `-Zsanitizer=thread`. You might also need the `--target` and build-std flags. 
If you’re working with other languages that are also instrumented with sanitizers, you might need the external-clangrt flag. See the section on working with 
other languages.

You may need to use `build-std` for sanitizer support, which is invoked via `-Z build-std`

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- Use cargo script when able to create a complete reproduction. This should be a single contained .rs file which can be executed with `cargo poc.rs`
- Generate a test case which triggers the exploit. This can be done as an integration test in the project. 
- When the vulnerability is undefined behavior or an unsafe code segment, make sure a test case is generated which miri will identify.

## Scope

You should inspect this source for vulnerabilities that exist directly within its source. Third-party dependencies
vulnerabilities should be excluded from scanning. However, if you identify known vulnerabilities in dependencies, 
such as vulnerablilities in imported C libraries in sys crates, please report them as a finding. When a third party
C dependency is being imported via a `-sys` crate or you identify a `build.rs` building and linking C code, consider 
the boundary to this code and the dependency as in scope.