# Validating the `ruby-ext` ASan recipe

One-time check that the sanitized interpreter actually catches a memory-safety or UB bug in a native gem.
Needs Docker + network. The image build compiles Ruby (and Rust) from source — ~15–20 min.

## 1. Build the images

```bash
# from repo root
docker build -t scrutineer-runner:local -f Dockerfile.runner .
docker build -t scrutineer-profile-ruby-ext \
  -f docker/profiles/ruby-ext/Dockerfile \
  --build-arg RUNNER_IMAGE=scrutineer-runner:local \
  docker/profiles/ruby-ext
```

The image build itself is a partial gate: it fails if the configure flags are wrong (the
`ldd … | grep libasan` smoke step at the end of the Dockerfile won't pass).

## 2. Smoke test

```bash
docker run --rm scrutineer-profile-ruby-ext sh -c '
  ruby -v &&
  ldd /usr/local/ruby-asan/bin/ruby | grep libasan &&
  /usr/bin/ruby -v && valgrind --version && cargo --version && ruby-build --version'
```

## 3. Seed a buggy gem

A C extension that overflows a 16-byte heap buffer, reachable from Ruby:

```bash
mkdir -p /tmp/boom/ext/boom
cat > /tmp/boom/ext/boom/extconf.rb <<'RB'
require "mkmf"
create_makefile("boom")
RB
cat > /tmp/boom/ext/boom/boom.c <<'C'
#include <ruby.h>
#include <string.h>
/* vulnerable: copies the whole input into a fixed 16-byte heap buffer */
static VALUE boom_copy(VALUE self, VALUE str) {
  long n = RSTRING_LEN(str);
  char *buf = xmalloc(16);
  memcpy(buf, RSTRING_PTR(str), n);   /* heap-buffer-overflow when n > 16 */
  VALUE out = rb_str_new(buf, n);
  xfree(buf);
  return out;
}
void Init_boom(void) {
  VALUE m = rb_define_module("Boom");
  rb_define_module_function(m, "copy", boom_copy, 1);
}
C
cat > /tmp/boom/poc.rb <<'RB'
require_relative "ext/boom/boom"
Boom.copy("A" * 64)   # overflows the 16-byte buffer
puts "NO CRASH"
RB
```

## 4. Build under ASan + trigger

```bash
docker run --rm --user root -v /tmp/boom:/src -w /src scrutineer-profile-ruby-ext sh -c '
  cd ext/boom && ruby extconf.rb && make && cd /src && ruby poc.rb'
```

**Pass:** aborts with `ERROR: AddressSanitizer: heap-buffer-overflow` and a `SUMMARY:` line in
`boom_copy` — **not** `NO CRASH`.

Negative control (must print `NO CRASH`, no ASan output):

```bash
docker run --rm --user root -v /tmp/boom:/src -w /src scrutineer-profile-ruby-ext sh -c '
  cd /src && ruby -e "require_relative %q(ext/boom/boom); Boom.copy(%q(short)); puts %q(NO CRASH)"'
```

## 5. UBSan alignment scoping (interpreter quiet, extension checked)

The interpreter is built with `-fno-sanitize=alignment` — CRuby accesses packed
iseq structs at unaligned addresses (benign on amd64/arm64), which UBSan would
otherwise flag on every `rescue`/`ensure` path. A native extension must still get
the check, so a post-build step rewrites the recorded `cppflags` in rbconfig
(mkmf ignores env `CFLAGS`, so the env approach php-ext / python-ext use does not
reach Ruby extensions). This confirms both halves.

A C extension with a deliberately misaligned typed access:

```bash
mkdir -p /tmp/aln/ext/aln
cat > /tmp/aln/ext/aln/extconf.rb <<'RB'
require "mkmf"
create_makefile("aln")
RB
cat > /tmp/aln/ext/aln/aln.c <<'C'
#include <ruby.h>
struct a8 { long x; };
/* misaligned: p is xmalloc'd+1, so the 8-byte store is unaligned */
static VALUE aln_go(VALUE self) {
  char *b = xmalloc(32);
  struct a8 *p = (struct a8 *)(b + 1);
  p->x = 42;                            /* UBSan alignment check fires here */
  return LONG2NUM(p->x);
}
void Init_aln(void) {
  rb_define_module_function(rb_define_module("Aln"), "go", aln_go, 0);
}
C

docker run --rm --user root -v /tmp/aln:/src -w /src scrutineer-profile-ruby-ext sh -c '
  cd ext/aln && ruby extconf.rb && make V=1 && cd /src &&
  ruby -e "require_relative %q(ext/aln/aln); Aln.go"'
```

**Pass:** aborts with `runtime error: member access within misaligned address …
requires 8 byte alignment` in `aln_go`, SIGABRT (exit 134). The `make V=1` compile
line must carry `-fno-sanitize-recover=undefined` and **no** `-fno-sanitize=alignment`
— proof the rbconfig rewrite reached the extension.

> The **compile-line** half of this check (the flags on the `make V=1` line) now also runs
> automatically during the image build — see the "Build-time proof …" `RUN` in the Dockerfile,
> which compiles a throwaway extension and greps its compile command — so a broken rbconfig
> rewrite fails the build rather than reaching here. This §5 additionally confirms the *runtime*
> abort, which the build-time gate does not exercise.

Interpreter-quiet control (exception handling must run clean, no alignment reports
leaking from the interpreter itself):

```bash
docker run --rm scrutineer-profile-ruby-ext sh -c '
  ruby -e "begin; raise; rescue; end; 100.times { [].each {} }; puts %q(interpreter ok)"'
```

**Pass:** prints `interpreter ok` with no `runtime error: … alignment` lines.

## 6. (optional) valgrind fallback + suppressions

Stock interpreter, separate uninstrumented build:

```bash
docker run --rm --user root -v /tmp/boom:/src -w /src scrutineer-profile-ruby-ext sh -c '
  cd ext/boom && rm -f *.o *.so Makefile && /usr/bin/ruby extconf.rb && make && cd /src &&
  valgrind --suppressions=/usr/local/share/ruby-ext/ruby.supp --error-exitcode=99 /usr/bin/ruby poc.rb'
```

**Pass:** `Invalid write of size …` in `boom_copy`, exit 99, with no GC-noise errors leaking past
the suppressions.

## If a sanitizer doesn't fire / the interpreter crashes in the GC

Tune in `docker/profiles/ruby-ext/Dockerfile` (open question #1), rebuild, retry:
- fiber-related crash in `gc.c`/`cont.c` → add `--with-coroutine=copy` to `./configure`.
- noisy/false GC reports → confirm `ASAN_OPTIONS` has `detect_stack_use_after_return=0`.
- shutdown leaks → `RUBY_FREE_AT_EXIT=1` is set; keep `detect_leaks=0` unless chasing one.
- extension alignment check missing (§5) → confirm the rbconfig rewrite ran:
  `ruby -e 'p RbConfig::CONFIG["CPPFLAGS"]'` must show `-fno-sanitize-recover=undefined`
  and no `-fno-sanitize=alignment`. The interpreter build asserts this, so a bad
  state should fail the image build rather than reach here.
