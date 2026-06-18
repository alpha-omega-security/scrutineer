# Python-extension scanning container

The repository under `./src` is a Python package with a compiled C/C++ extension. The job is to find **security
vulnerabilities** in the native code.

## Why this container

CPython here is built **--with-pydebug + AddressSanitizer + UndefinedBehaviorSanitizer**. ASan/UBSan are detection
tooling: they turn silent memory corruption into loud, pinpointable hits so you can find bugs in C code instead of
guessing from static reading. They are not the deliverable.

The deliverable is a security finding: what the bug is, what an attacker controls from the Python side, what the impact
is (info disclosure, memory corruption to RCE, DoS, type confusion bypassing a check), and a reproducer that shows it.
A sanitizer hit is a starting point, not a report.

## Layout

- `./src` — package source, including the C/C++ extension (start here).
- `/usr/local/python-asan` — debug+ASan+UBSan CPython. `python`/`python3` on PATH; the build reports a debug build and
  loads `_testcapi`.
- `/opt/cpython` — CPython source tree. Cross-reference C-API internals (`Include/*.h`, `Objects/`) when triaging.
- `gdb`, `gh`, `claude` — on PATH.

## Building the extension

Extensions are compiled with **gcc** (the default `cc`, matching how CPython itself was built) and the pre-exported
sanitizer `CFLAGS`/`CXXFLAGS`/`LDFLAGS`, so anything pip builds against this interpreter is instrumented and shares the
interpreter's ASan runtime. A clang-built `.so` dlopened into this gcc-ASan CPython aborts with a runtime mismatch, so
build standalone fuzz harnesses with clang if you want libFuzzer, but build loadable extensions with gcc. Build in
place:

```bash
cd src
python -m pip install -e . -v        # or: python setup.py build_ext --inplace
```

`pip` is available here (the interpreter is one we built, not an externally-managed install). If a build needs a
dependency, install it the same way; it gets instrumented too. If the build fails with `Could not resolve host` the
scan is offline — note which steps you had to skip.

## Sanitizer config (pre-exported)

```
PYTHONMALLOC=malloc
  Routes Python allocations through libc malloc so ASan sees every allocation, not just the arenas pymalloc
  requests from libc. The interpreter is built --without-pymalloc to match.

ASAN_OPTIONS=
  symbolize=1                  readable stack traces
  detect_leaks=0               CPython has known interpreter-shutdown leaks; flip to 1 only when chasing a suspect
  allocator_may_return_null=1  a huge allocation returns NULL instead of aborting, so you reach the code under test
  halt_on_error=0              keep going after the first report while exploring
  print_summary=1              one-line summary at the end

UBSAN_OPTIONS=
  print_stacktrace=1
  print_summary=1
```

Extensions are built with `-fno-sanitize-recover=undefined`, so a UB hit in the extension aborts rather than silently
continuing — the abort is the evidence.

## Investigating a sanitizer hit

A hit means a memory-safety bug in C code. Work the bug, don't just file the trace.

1. **What is the primitive?** Read the ASan/UBSan output — heap-buffer-overflow (read or write?), use-after-free,
   double-free, integer overflow into an allocation, type confusion. Each has a different exploitability ceiling.
2. **What does an attacker control?** Walk back from the crash to the Python-level entry point — the method or function
   the extension exposes, its argument parsing (`PyArg_ParseTuple`, the buffer protocol). Which argument's length,
   contents, or type reaches the bad code, and could a caller realistically pass it?
3. **What is the impact?** OOB read to info disclosure; OOB write / UAF / double-free to memory corruption (often
   RCE-able in native code); integer overflow into an allocation to an undersized buffer then overflow; missing type
   or bounds check to a pivot. UBSan-only hits may be benign — chase the consequence, not the label.
4. **Reduce to the smallest reproducer that still triggers it.** Minimal Python, only what's needed. The minimal form
   is the evidence.
5. Cross-reference `/opt/cpython` for C-API contracts (reference counting, buffer protocol, `PyObject` layout) when the
   surrounding C relies on semantics that aren't local.

## Creating reproducers

A reproducer demonstrates the security bug, not just that something crashed. It must be something you actually ran in
this container. If you couldn't run it here, say so explicitly — never invent one.

- Small case: a script run with `python /tmp/poc.py` after building the extension in place.
- The reproducer should show the **attacker-controlled input** reaching the bug — what call, what argument, what value.
  A bug that only triggers under values nobody could supply is a weak finding; find the real attack surface or
  downgrade the report.
- Quote the sanitizer output as **evidence** (the `SUMMARY:` line plus the relevant top of the stack), then describe
  the bug in one line — e.g. "1-byte heap-buffer-overflow write in `parse_header`, byte sourced from the
  attacker-supplied `data` argument".
- "Potential RCE" with no demonstrated primitive is a hypothesis — say so honestly rather than overclaiming.

## Rules

- Back every claim with a command you ran in the container. Prefer running things over static reasoning.
- Build the extension before analyzing.
- Install missing build deps via `pip` or `apt-get` without asking.
