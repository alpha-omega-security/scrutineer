#!/bin/sh
# Build one ASan+UBSan Ruby from source and make its mkmf extension builds
# instrumented. Called once per interpreter by the ruby-ext Dockerfile, so a
# sanitizer-flag change lands on BOTH interpreters and they cannot drift.
#
# Args: <git-ref> <install-prefix> <kept-src-dir>
#
# Flags (every interpreter this builds):
#  - sanitizers in cppflags reach the compile of the interpreter AND, via
#    rbconfig CPPFLAGS, every extension mkmf later builds.
#  - -fno-sanitize=alignment: the interpreter does benign unaligned packed-struct
#    access; without it UBSan floods every rescue/ensure path. The rewrite below
#    puts alignment back ON for extensions.
#  - -fno-sanitize-recover is NOT set here: the interpreter must recover from its
#    own benign UB or `make` (which runs the instrumented miniruby) aborts. The
#    rewrite below sets it for extensions so their UB aborts = the evidence.
#  - optflags=-O1 -g keeps ASan traces readable without the -O0 slowdown.
#
# Ruby's conservative GC scans the C stack for VALUEs and interacts with ASan's
# fake stack. The safe defaults (detect_stack_use_after_return=0, detect_leaks=0,
# RUBY_FREE_AT_EXIT=1) are set in the Dockerfile ENV; if fiber-heavy code crashes
# inside the GC, add the ./configure --with-coroutine=copy switch below and rebuild.
set -eux

ref="$1"
prefix="$2"
src="$3"

git clone --depth 1 --branch "$ref" "$RUBY_GIT_URL" "$src"
cd "$src"
./autogen.sh
./configure \
    --prefix="$prefix" \
    --disable-install-doc \
    cppflags="-fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fno-omit-frame-pointer -DRUBY_DEBUG=1" \
    optflags="-O1 -g" \
    debugflags="-g3" \
    LDFLAGS="-fsanitize=address -fsanitize=undefined"
make -j"$(nproc)"
make install
"$prefix/bin/ruby" -v

# Rewrite the RECORDED cppflags in this interpreter's rbconfig so extension
# compiles get the alignment check back ON and -fno-sanitize-recover=undefined
# (UB aborts = evidence). The interpreter binary is already built and stays
# quiet. Aborts loudly if the entry shape ever changes.
# shellcheck disable=SC2016  # -e body is Ruby ($LOADED_FEATURES, $1), not shell; keep it single-quoted
"$prefix/bin/ruby" -rrbconfig -e 'path=$LOADED_FEATURES.grep(/rbconfig\.rb$/).first; cfg=File.read(path); cfg.sub!(/^(\s*CONFIG\["cppflags"\] = ".*)"\s*$/){ $1.gsub(" -fno-sanitize=alignment","") + " -fno-sanitize-recover=undefined\"" } or abort("ruby-ext: cppflags entry not found in #{path}"); File.write(path, cfg)'
"$prefix/bin/ruby" -e 'f=RbConfig::CONFIG["CPPFLAGS"]; abort("ruby-ext: alignment still off for extensions: #{f}") if f.include?("-fno-sanitize=alignment"); abort("ruby-ext: -fno-sanitize-recover missing for extensions: #{f}") unless f.include?("-fno-sanitize-recover=undefined"); STDERR.puts "ruby-ext: extension CPPFLAGS =>#{f}"'

# Prove the rewrite reaches a real mkmf extension compile: build a throwaway
# extension and grep the ACTUAL compiler line. If the cppflags->CPPFLAGS chain
# ever fails to reach mkmf, the image build fails here instead of silently
# shipping uninstrumented extensions.
d="$(mktemp -d)"
mkdir -p "$d/probe"
cd "$d/probe"
printf 'require "mkmf"\ncreate_makefile("probe")\n' > extconf.rb
printf 'void Init_probe(void){}\n' > probe.c
"$prefix/bin/ruby" extconf.rb
make V=1 > compile.log 2>&1 || { cat compile.log; exit 1; }
grep -Eq -- '-fno-sanitize-recover=undefined' compile.log \
    || { echo "ruby-ext: extension compile is missing -fno-sanitize-recover=undefined"; cat compile.log; exit 1; }
if grep -Eq -- '-fno-sanitize=alignment' compile.log; then
    echo "ruby-ext: extension compile still carries -fno-sanitize=alignment (must be re-enabled for extensions)"
    cat compile.log
    exit 1
fi
cd /
rm -rf "$d"
