# Ruby native-extension scanning container

The repository under `./src` is a Ruby gem that ships a **native extension** (C/C++, or
Rust via rb-sys/Cargo). The job is to find **security vulnerabilities** in it.

## Audit BOTH surfaces — this is not a C-only scan

A native gem is almost always *mostly Ruby* wrapping a small accelerated core. There are
two attack surfaces and you are responsible for **both**:

1. **The Ruby API** (`lib/**/*.rb`) — usually the larger surface. Injection, deserialization,
   path traversal, SSRF, and — the Ruby-specific bit — taint flowing through **metaprogramming /
   dynamic dispatch** (see the section below). The generic semgrep pass largely misses these.
2. **The native extension** (`ext/<name>/`) — where memory-safety bugs hide. This container
   exists to make those *loud*: the default interpreter is built with **AddressSanitizer +
   UndefinedBehaviorSanitizer**, so a reproducer that drives the extension turns silent memory
   corruption into a pinpointed crash.

Filing only C findings (or only Ruby findings) is an incomplete scan. Cover the whole gem.

### If the repo is also a Rails app

Some repos are a Rails app *and* ship a native extension (a `config/application.rb` alongside
`ext/**/`). Such a repo matches this profile first, so it also carries **Brakeman**: run
`brakeman ./src` (stock interpreter) for the Rails-shaped classes — SQLi, XSS, mass-assignment,
unsafe deserialization, command injection, SSRF, open redirect, CSRF gaps — the generic semgrep
pass misses, on top of the C/Ruby audit above.

## Layout & interpreters

- `./src` — the gem source. `lib/` is the Ruby API; `ext/<name>/` is the native extension
  (`extconf.rb` + `*.c`/`*.cpp`, or a `Cargo.toml` for Rust).
- **`ruby` (default, on PATH) → `/usr/local/ruby-asan` — the ASan+UBSan build.** `ruby -e 'p
  RbConfig::CONFIG["CFLAGS"]'` shows the sanitizer flags. Its `gem`/`bundle` compile extensions
  *instrumented* automatically (the flags flow through rbconfig). Use this to build and drive the
  extension.
- **`/usr/bin/ruby` — stock Ruby (apt).** Uninstrumented and fast; use it for reading-speed
  Ruby-level work and as the **valgrind** target. Never run valgrind against the ASan ruby.
- `/opt/ruby-src` — the Ruby source tree the ASan build came from. Cross-reference C-API
  semantics here when triaging (`include/ruby/**`, `string.c`, `gc.c`).
- `gdb`, `strace`, `valgrind`, `cargo`, `brakeman`, `gh`, `claude` — on PATH.

## Building & driving the extension (under ASan, the default ruby)

```bash
cd src
bundle install            # builds native gems instrumented (default ruby = ASan)
rake compile              # most gems; produces lib/<name>/<name>.so
# or, directly:
cd ext/<name> && ruby extconf.rb && make
```

Then drive it from Ruby and let a sanitizer abort be the signal:

```bash
bundle exec ruby /tmp/poc.rb      # or: ruby -e '...'
```

**Version skew.** The sanitized interpreter is Ruby 3.4. If the gem targets another version (`required_ruby_version`,
`.ruby-version`) and the extension won't compile or load against 3.4 — removed C-API, struct-layout changes — say so
explicitly; that is a coverage gap, not a clean result. ASan/memory-safety coverage stays on 3.4; for a Ruby-level
reproducer on the gem's own version use `ruby-build <x.y.z> /tmp/ruby-<x.y.z>` (on PATH) or the stock `/usr/bin/ruby`,
and state the version used.

### Rust extensions (rb-sys / Cargo-native)

The Rust side is mostly safe; the danger is `unsafe` blocks and the `extern "C"` /
`rb-sys` FFI boundary (pointer/length handling, ownership of returned buffers, `VALUE`
round-tripping). Instrument it to match the ASan interpreter:

```bash
cd src
RUSTFLAGS="-Zsanitizer=address" \
  cargo +$RUST_NIGHTLY_VERSION build -Zbuild-std --target x86_64-unknown-linux-gnu
```

then rebuild the gem so it loads the instrumented `.so`. Miri is **not** in this image — it
can't cross FFI, which is the whole point of an extension; for isolated unsafe-Rust logic use
the dedicated `rust` profile. `$RUST_NIGHTLY_VERSION` is exported.

### Go extensions (rare)

True CRuby Go extensions (cgo `c-shared` loaded via Fiddle/FFI) are uncommon. The Go
toolchain is **not** pre-installed. If you find one, note it in the report and, if it matters,
`apt-get install -y golang` and build with `go build -buildmode=c-shared -asan`. Treat the
cgo boundary (C strings, pointer lifetimes) as the prime target.

## Sanitizer config (pre-exported)

```
RUBY_FREE_AT_EXIT=1              free the VM at exit so shutdown UAF/leaks are attributable
ASAN_OPTIONS=
  detect_leaks=0                 Ruby has known startup allocations; flip to 1 only when
                                 chasing a focused suspect (with RUBY_FREE_AT_EXIT=1)
  detect_stack_use_after_return=0  Ruby's conservative GC scans the C stack for VALUEs;
                                 ASan's fake stack hides them and causes spurious GC frees.
                                 Keep 0 unless you understand the interaction.
  abort_on_error=1               a detected bug is a hard, pinpointed stop
  symbolize=1 / print_summary=1  readable trace + one-line SUMMARY
UBSAN_OPTIONS=
  print_stacktrace=1 / print_summary=1  readable trace + one-line SUMMARY
  halt_on_error=0                the interpreter is built WITHOUT -fno-sanitize-recover, so its
                                 own benign UB prints-and-continues and never kills the scan
  abort_on_error=1               an extension is built WITH -fno-sanitize-recover=undefined, so
                                 its UB hits the compiled-in abort — SIGABRT (same signature as
                                 an ASan finding) is the evidence
```

If a confusing crash looks like a GC/ASan artifact rather than a gem bug (a free deep inside
`gc.c` with no extension frame), say so and cross-check with valgrind on the stock ruby.

## valgrind fallback (stock ruby only)

When the ASan build won't compile the extension, or the gem ships a precompiled/fat binary,
fall back to memcheck on the **stock** interpreter:

```bash
valgrind --suppressions=/usr/local/share/ruby-ext/ruby.supp \
         --leak-check=full --error-exitcode=99 \
         /usr/bin/ruby /tmp/poc.rb
```

The suppression file silences conservative-GC false positives; extend it with
`--gen-suppressions=all` if GC noise drowns a run. valgrind is slower and noisier than ASan —
prefer ASan; reach for valgrind as the no-rebuild safety net.

## Investigating a sanitizer hit

A hit means a memory-safety bug in native code. Work the bug, don't just file the trace.

1. **What is the primitive?** heap-buffer-overflow (read or write?), use-after-free, double-free,
   stack-buffer-overflow, integer overflow into an allocation, type confusion. Each has a
   different exploitability ceiling.
2. **What does an attacker control?** Walk back from the crash to the Ruby entry point — the
   `rb_define_method(...)` → C function boundary, the `rb_scan_args` / `Check_Type` /
   `StringValue` parsing. Which argument's length, contents, or type reaches the bad code, and
   could a Ruby caller realistically pass it?
3. **What is the impact?**
   - OOB read → info disclosure (heap bytes readable back into Ruby / over the wire).
   - OOB write / UAF / double-free → memory corruption; in native code frequently RCE-able.
   - Integer overflow into `xmalloc` → undersized buffer → subsequent write overflows.
   - Missing `Check_Type` / wrong `T_*` assumption → type confusion that pivots to one of the
     above, or bypasses a check in pure Ruby.
   - UBSan-only hits (signed overflow, misaligned load) → may be benign; chase the consequence.
4. **Reduce to the smallest reproducer** that still triggers it — minimal Ruby, only what's
   needed. The minimal form is the evidence.
5. **Cross-reference `/opt/ruby-src`** for C-API contracts: `VALUE`, `RSTRING_PTR` /
   `RSTRING_LEN`, `StringValueCStr` (NUL-termination), `rb_str_modify`, `xmalloc` / `ruby_xfree`,
   `rb_gc_guard` (premature GC of a still-referenced VALUE), `Check_Type`, `rb_funcall`, the
   `T_STRING`/`T_ARRAY`/`T_DATA` tags, `TypedData_Get_Struct`.

## Ruby-specific analysis: metaprogramming & dynamic dispatch

Ruby resolves methods at runtime, so taint can reach a sink through indirection a syntactic
scanner cannot follow. The model can — reason about it explicitly. Treat these as sinks and
trace what a caller controls into them:

- **Dynamic dispatch:** `send` / `public_send` / `__send__` with an attacker-influenced method
  name or args; `method`, `respond_to?`-gated calls; `define_method` / `method_missing` that
  route untrusted names to behaviour.
- **Code/const evaluation:** `eval`, `instance_eval` / `class_eval` / `module_eval`,
  `binding.eval`, `const_get` / `qualified_const_get` / `constantize` (Rails) on tainted input
  (class/gadget instantiation).
- **Deserialization gadgets:** `Marshal.load`, `YAML.load` / `Psych.load` (non-`safe_load`),
  `Oj.load` in compat/object mode, `JSON.parse(..., create_additions: true)`. These reach
  object-graph gadget chains — combined with the dynamic dispatch above, that is the classic
  Ruby RCE path. Flag any of them on untrusted bytes.
- **Command/file sinks via interpolation:** `Kernel#system` / `exec` / `spawn`, backticks,
  `%x{}`, `IO.popen`, `Open3.*`, and the `Kernel#open("|cmd")` / `URI.open` pipe trick;
  `File`/`IO` reads on a path built from input (traversal).
- **Format/templating:** `ERB.new(src).result`, `format` / `String#%` with a user-controlled
  format string.

A native gem's Ruby wrapper often passes user data straight into the C call — follow it across
the boundary in both directions.

## Creating reproducers

Every finding ships a reproducer — code that, run **in this container**, actually triggers the
issue. Paste the exact command and the verbatim output. Reasoning-only or "this would"
reproducers do not count; if you couldn't run it here, say so explicitly — never invent one.

- Build the extension first (above). Small case: write `/tmp/poc.rb`, run `bundle exec ruby
  /tmp/poc.rb` (or `ruby /tmp/poc.rb`) under the ASan interpreter.
- Show the **attacker-controlled input** reaching the bug — what Ruby call, what argument, what
  value. A bug only triggerable by values nobody could supply is weak; find the real attack
  surface or downgrade.
- Quote the sanitizer output as **evidence** (the `SUMMARY:` line + the relevant top of stack),
  then state the bug in one line — e.g. "4-byte heap-buffer-overflow write in
  `ext_parse+0x3a`, length sourced from the attacker-supplied `data` argument".
- For an OOB read, push to a PoC that prints leaked heap bytes back through Ruby; for a type
  confusion, one that bypasses a missing `Check_Type`. "Potential RCE" with no demonstrated
  primitive is a hypothesis — say so honestly.

## Rules

- Back every claim with a command you ran here. Prefer running things over static reasoning.
- Build the extension before analyzing the native side; audit the Ruby side regardless.
- Install missing build deps via `gem`, `bundle`, or `apt-get` without asking. If a fetch fails
  with a network error the scan is offline — work from what's present and note skipped checks.

## Out of scope

- Installed third-party gems (under `/work/.gem` or `./src/vendor/bundle`) — not the target
  unless a finding specifically pivots through one. Still report a *known-vulnerable* native
  dependency a `-sys`-style gem builds and links.
