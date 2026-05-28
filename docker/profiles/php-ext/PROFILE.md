# PHP-extension scanning container

The repository under `./src` is a PHP-C extension. The job is to find **security vulnerabilities** in it.

## Why this container

PHP here is built **debug + AddressSanitizer + UndefinedBehaviorSanitizer**. ASan/UBSan are detection tooling: they
turn silent memory corruption into loud, pinpointable hits so you can actually find bugs in C code instead of guessing
from static reading. They are not the deliverable.

The deliverable is a security finding: what the bug is, what an attacker controls from the PHP side, what the impact
is (info disclosure, memory corruption → RCE, DoS, type confusion bypassing a security check), and a reproducer that
shows it. A sanitizer hit is a starting point, not a report.

If a specific case genuinely needs uninstrumented PHP (you suspect a sanitizer false positive — e.g., interceptor
mismatch), say so in the finding and `apt-get install -y php-cli` for one. Don't make it the default workflow.

## Layout

- `./src` — extension source (start here).
- `/usr/local/php` — debug+ASan+UBSan PHP. `php`, `phpize`, `php-config` on PATH. `php -v` reports `(DEBUG)`.
- `/opt/php-src` — PHP source tree. Cross-reference Zend internals (`Zend/zend_*.h`) when triaging.
- `composer`, `gh`, `claude`, `gdb`, `strace` — on PATH.

## gcc vs clang

PHP is gcc-built, so its ASan runtime is gcc's `libasan.so`.

- **PHP extensions** (anything you `extension=` into PHP): build with **gcc** (the default `cc`). The pre-exported
  `CFLAGS`/`LDFLAGS` work as-is. A clang-built `.so` dlopen'd into the gcc-asan PHP aborts with runtime-mismatch.
- **Standalone fuzz harnesses, libFuzzer targets, test programs**: build with **clang** (`CC=clang CXX=clang++`).
  Same sanitizer flags; clang additionally gives `-fsanitize=fuzzer`, `-fsanitize=memory`, `-fsanitize=thread`.
- **Rebuilding PHP itself with clang**: supported but invasive — re-run `/opt/php-src` configure with
  `CC=clang CXX=clang++`. Clang-built extensions will then load. Don't mix afterward.

## Sanitizer config (pre-exported)

```
USE_ZEND_ALLOC=0
  Disables Zend's arena allocator. Without this, ASan sees only the big chunks Zend asks libc for, not the
  per-emalloc sub-allocations inside them — most extension bugs would slip past. Keep on for analysis.

ASAN_OPTIONS=
  symbolize=1                       readable stack traces
  strict_string_checks=1            catch strlen/strcpy on non-NUL-terminated bufs
  detect_stack_use_after_return=1   catch returning pointer-to-stack
  detect_leaks=0                    PHP has known startup leaks; flip to 1 only when chasing a focused suspect
  print_summary=1                   one-line summary at the end

UBSAN_OPTIONS=
  print_stacktrace=1
  print_summary=1
```

Re-running a confusing hit with `USE_ZEND_ALLOC=1` sometimes produces a cleaner trace — useful while investigating;
the underlying bug exists either way.

## Building the extension

```bash
cd src
phpize
./configure --enable-<name>   # macro from PHP_ARG_ENABLE in config.m4
make -j"$(nproc)"

# Smoke load
php -d extension="$(pwd)/modules/<name>.so" --ri <name>
```

Only run the full `make test` suite when investigating something specific — it's slow and noisy.

## Investigating a sanitizer hit

A hit means there's a memory-safety bug in C code. The investigation is figuring out whether it's security-relevant
and how. Work the bug, don't just file the trace.

1. **What is the primitive?** Read the ASan/UBSan output — heap-buffer-overflow (read or write?), UAF, double-free,
   stack-buffer-overflow, integer overflow into allocation, type confusion. Each has a different ceiling for
   exploitability.
2. **What does an attacker control?** Walk back from the crashing call to the PHP-level entry point — the
   `ZEND_FUNCTION(...)`, the `zend_parse_parameters`. Which argument's length / contents / type reaches the bad code?
   Could a script (or a `.phpt`, an HTTP route, a Phar) realistically pass that?
3. **What is the impact?**
   - OOB read → potential info disclosure (heap contents readable back from PHP / leaked over the wire).
   - OOB write / UAF / double-free → memory corruption; in native code that's frequently RCE-able.
   - Integer overflow into alloc → undersized buffer + subsequent write → heap overflow.
   - Type confusion (missing `Z_TYPE_P` check, wrong `convert_to_*`) → pivots to one of the above, or bypasses a
     security check in pure PHP land.
   - UBSan-only hits (e.g., signed overflow) → may be benign, may underpin a real bug. Chase the consequence, not
     the UBSan label.
4. **Reduce to the smallest reproducer that still triggers it.** Strip dependencies, strip noise — minimal PHP, only
   what's needed. The minimal form is the evidence.
5. Cross-reference `/opt/php-src` for Zend macro semantics (`ZVAL_*`, `Z_ADDREF_P`, `OBJ_RELEASE`, arena vs emalloc)
   when the surrounding C uses contracts whose details aren't local.

## Creating reproducers

A reproducer demonstrates the security bug, not just that something crashed. It must be something you actually ran
in this container. If you couldn't run it here, say so explicitly — never invent one.

- Small case: a script run with `php -d extension="$(pwd)/modules/<name>.so" /tmp/poc.php`.
- Regression-style: a `.phpt` under the project's `tests/`, run via `make test TESTS=tests/<file>.phpt`.
- The reproducer should show the **attacker-controlled input** reaching the bug — what PHP-level call, what argument,
  what value. A bug that only triggers under values nobody could realistically supply is a weak finding; either find
  the real attack surface or downgrade the report.
- Quote the sanitizer output as **evidence** that the bug fires (the `SUMMARY:` line plus the relevant top of the
  stack), then describe what the bug is in one line — e.g., "1-byte heap-buffer-overflow write at
  `foo_parse_header+0x42`, byte sourced from attacker-supplied `$header[i]`".
- Where you can, push further: an OOB read PoC that prints leaked heap bytes back through PHP, a type-confusion PoC
  that bypasses a `Z_TYPE_P` check and reaches an unintended path. "Potential RCE" with no demonstrated primitive is
  a hypothesis — say so honestly rather than overclaiming.

## Rules

- Back every claim with a command you ran in the container. Prefer running things over static reasoning.
- Build the extension before analyzing. If `config.m4` exists but no `Makefile`, run
  `phpize && ./configure --enable-<name> && make`.
- Install missing build deps via `apt-get` without asking.
