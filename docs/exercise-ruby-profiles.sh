#!/usr/bin/env sh
# Exercise the ruby-ext / ruby-rails profiles at RUNTIME — the part a clean
# `docker build` does NOT prove (that a sanitizer actually aborts, that the
# UBSan alignment check reaches the extension, that Brakeman actually runs).
# Runnable companion to docs/ruby-ext-validation.md (§3–§7).
#
# Prereq: images built (docs/ruby-ext-validation.md §1):
#   scrutineer-profile-ruby-ext, scrutineer-profile-ruby-rails
#   (override with EXT_IMG / RAILS_IMG)
#
#   sh docs/exercise-ruby-profiles.sh
set -eu
EXT_IMG="${EXT_IMG:-scrutineer-profile-ruby-ext}"
RAILS_IMG="${RAILS_IMG:-scrutineer-profile-ruby-rails}"

# Fail fast if the images aren't built locally — otherwise podman's short-name
# resolver errors cryptically ("cannot prompt without a TTY"). inspect never pulls.
for img in "$EXT_IMG" "$RAILS_IMG"; do
  docker image inspect "$img" >/dev/null 2>&1 || {
    echo "image '$img' not found locally — build it (docs/ruby-ext-validation.md §1) or set the name:" >&2
    echo "  EXT_IMG=rp-ruby-ext RAILS_IMG=rp-ruby-rails sh docs/exercise-ruby-profiles.sh" >&2
    exit 1
  }
done

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
# :z relabels the bind mount for SELinux hosts (mirrors DetectProfile's :ro,z);
# harmless where SELinux is off / on Docker Desktop.
run() { docker run --rm --user root -v "$W:/src:z" -w /src --entrypoint sh "$1" -c "$2" 2>&1 || true; }

# 1) ASan aborts on a heap-buffer-overflow in a native extension — the core of ruby-ext.
mkdir -p "$W/ext/boom"
printf 'require "mkmf"\ncreate_makefile("boom")\n' > "$W/ext/boom/extconf.rb"
cat > "$W/ext/boom/boom.c" <<'C'
#include <ruby.h>
#include <string.h>
/* rb_str_new + xfree USE the buffer, so -O1 can't dead-store-eliminate the memcpy. */
static VALUE go(VALUE self, VALUE x){
  long n = RSTRING_LEN(x);
  char *b = xmalloc(16);
  memcpy(b, RSTRING_PTR(x), n);   /* heap-buffer-overflow when n > 16 */
  VALUE r = rb_str_new(b, n);
  xfree(b);
  return r;
}
void Init_boom(void){ rb_define_module_function(rb_define_module("Boom"), "go", go, 1); }
C
o=$(run "$EXT_IMG" 'cd ext/boom && ruby extconf.rb >/dev/null && make >/dev/null 2>&1 && cd /src && ruby -e "require_relative %q(ext/boom/boom); Boom.go(%q(A)*64)"')
if echo "$o" | grep -q "heap-buffer-overflow"; then echo "PASS  asan-overflow"; else echo "FAIL  asan-overflow"; echo "$o"; exit 1; fi

# 2) UBSan alignment check reaches the extension at runtime — the rbconfig-rewrite half of #5.
mkdir -p "$W/ext/aln"
printf 'require "mkmf"\ncreate_makefile("aln")\n' > "$W/ext/aln/extconf.rb"
cat > "$W/ext/aln/aln.c" <<'C'
#include <ruby.h>
struct a8 { long x; };
static VALUE go(VALUE self){ char *b = xmalloc(32); struct a8 *p = (struct a8 *)(b + 1); p->x = 42; return LONG2NUM(p->x); }
void Init_aln(void){ rb_define_module_function(rb_define_module("Aln"), "go", go, 0); }
C
o=$(run "$EXT_IMG" 'cd ext/aln && ruby extconf.rb >/dev/null && make >/dev/null 2>&1 && cd /src && ruby -e "require_relative %q(ext/aln/aln); Aln.go"')
if echo "$o" | grep -q "misaligned"; then echo "PASS  ubsan-alignment"; else echo "FAIL  ubsan-alignment"; echo "$o"; exit 1; fi

# 3) Brakeman flags a Rails SQLi — the #3 add (ruby-ext ships it) and #6 (ruby-rails). Best-effort.
mkdir -p "$W/rails/app/controllers" "$W/rails/config"
printf 'source "https://rubygems.org"\ngem "rails"\n' > "$W/rails/Gemfile"
printf 'module Demo\n  class Application < Rails::Application; end\nend\n' > "$W/rails/config/application.rb"
cat > "$W/rails/app/controllers/users_controller.rb" <<'RB'
class UsersController < ApplicationController
  def show; User.where("name = '#{params[:name]}'"); end
end
RB
for img in "$EXT_IMG" "$RAILS_IMG"; do
  o=$(run "$img" 'cd /src/rails && brakeman -q --no-pager . 2>&1')
  if echo "$o" | grep -qi "SQL Injection"; then echo "PASS  brakeman-sqli [$img]"; else echo "WARN  brakeman-sqli [$img]: no SQLi warning — check: $(echo "$o" | tail -1)"; fi
done

echo "done"
