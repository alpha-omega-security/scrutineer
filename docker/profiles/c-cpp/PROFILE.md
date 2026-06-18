# C/C++ scanning container

The repository under `./src` is a C or C++ project. The job is to find **security vulnerabilities** in it.

## Runtime

- **gcc / g++** and **clang / clang++** (the default `cc`/`c++` is gcc). clang additionally offers `-fsanitize=fuzzer`, `=memory`, and `=thread`.
- Build systems: **cmake** (with **ninja**), **make**, and **autotools** (`autoconf`/`automake`/`libtool`/`pkg-config`).
- Analysis tools: **AddressSanitizer / UndefinedBehaviorSanitizer** (via the compiler flags below), **valgrind**, **gdb**, **clang-tidy**, and **cppcheck**.

## Why the sanitizers

ASan/UBSan turn silent memory corruption and undefined behaviour into loud, pinpointed reports, so you can find bugs in
C/C++ instead of guessing from static reading. They are detection tooling, not the deliverable. The deliverable is a
security finding: what the bug is, what an attacker controls, the impact (info disclosure, memory corruption to RCE,
DoS, type confusion), and a reproducer that shows it.

`ASAN_OPTIONS` and `UBSAN_OPTIONS` are pre-exported with sensible defaults (`detect_leaks=0`, non-fatal so exploration
continues, readable traces).

## Operating procedure

### Building

Use the project's own build system, adding the sanitizers through the standard flag variables:

```bash
cd src
# CMake
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g" && cmake --build build
# Make / autotools
./configure 2>/dev/null; make CFLAGS="-fsanitize=address,undefined -g" CXXFLAGS="-fsanitize=address,undefined -g"
```

Build with gcc or clang, but link the same compiler you compiled with so the sanitizer runtime matches. If a build
needs a dependency, install it with `apt-get` without asking. If a fetch fails with a network error the scan is offline
-- work from the source present and note what you skipped.

### Investigating and reproducing

- Run the built binary (or a focused harness) against attacker-controlled input; quote the ASan/UBSan `SUMMARY:` line
  plus the relevant top of the stack as evidence, then describe the bug in one line.
- `valgrind -q ./binary` catches leaks and uninitialised reads the sanitizers may miss; `gdb` for interactive triage.
- For a standalone case, compile a minimal harness that calls the vulnerable function directly with the malicious input
  rather than driving the whole program -- minimal is the evidence. With clang you can also build a libFuzzer target
  (`-fsanitize=fuzzer,address`).
- `cppcheck` and `clang-tidy` are useful for a quick static pass to surface candidates, but a real finding is one you
  reproduced by running it here. "Potential RCE" with no demonstrated primitive is a hypothesis -- say so honestly.

## Out of scope

- Vendored or system third-party libraries -- not the target of this scan unless a finding specifically pivots through
  one.
