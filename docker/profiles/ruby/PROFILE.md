# Ruby scanning container

The repository under `./src` is a Ruby project.

## Runtime

- **Ruby 3.4** — `ruby`
- **`gem`** on PATH for installing individual gems.
- **`bundle`** (Bundler ships with Ruby) for installing a project's locked dependency set. Use `--no-color`.
- C toolchain (`gcc`, `make`, `autoconf`) plus the headers Ruby links against, so gems with native extensions compile when a scan reproduces a `Gemfile` in-place.

## Operating procedure

### Code scanning preparations

If `./src/Gemfile.lock` exists, install dependencies first so requires resolve and native extensions build:

```bash
cd src && bundle install --no-color
```

If only `Gemfile` exists (no lock), call out the missing lock in the report but try anyway. If Bundler fails with
`Could not resolve host` or a similar network error the scan is offline — proceed without installed gems and note
which checks you had to skip.

**Ruby version skew.** This container runs Ruby 3.4. If the project targets a different version — a `ruby "x.y.z"`
directive in the `Gemfile`, a `.ruby-version` file, or `required_ruby_version` in the gemspec — `bundle install` or a
`require` may fail (Bundler *enforces* the `Gemfile` pin; older code can use removed APIs). Do not let that silently
skip the scan: note the mismatch explicitly. To run a reproducer on the project's own version, install it with
`ruby-build <x.y.z> /tmp/ruby-<x.y.z>` (ruby-build is on PATH) and run under `/tmp/ruby-<x.y.z>/bin/ruby`, or
`apt-get install -y ruby` for any stock interpreter — and state which version you used.

### Ruby-specific analysis: metaprogramming & dynamic dispatch

Ruby resolves methods at runtime, so taint can reach a sink through indirection a syntactic scanner cannot follow.
The generic semgrep pass largely misses this; you can reason about it — do so explicitly. Treat these as sinks and
trace what an attacker controls into them:

- **Dynamic dispatch:** `send` / `public_send` / `__send__` with an attacker-influenced method name or arguments;
  `define_method` / `method_missing` routing untrusted names to behaviour.
- **Code/const evaluation:** `eval`, `instance_eval` / `class_eval` / `module_eval`, `binding.eval`; `const_get` /
  `qualified_const_get` / `constantize` on tainted input (class/gadget instantiation).
- **Deserialization gadgets:** `Marshal.load`, `YAML.load` / `Psych.load` (non-`safe_load`), `Oj.load` in
  compat/object mode, `JSON.parse(..., create_additions: true)` on untrusted bytes — combined with dynamic dispatch,
  the classic Ruby object-injection RCE path.
- **Command/file sinks via interpolation:** `Kernel#system` / `exec` / `spawn`, backticks, `%x{}`, `IO.popen`,
  `Open3.*`, and the `Kernel#open("|cmd")` / `URI.open` pipe trick; `File`/`IO` reads on a path built from input.
- **Format/templating:** `ERB.new(src).result`, `format` / `String#%` with a user-controlled format string.

### Native extensions — escalate, do not skip

This profile's interpreter is **not** instrumented for memory safety. Before finishing, check whether the gem ships a
native extension: an `ext/**/extconf.rb`, a `*.gemspec` declaring `spec.extensions`, or `*.c` / `*.cpp` / `*.rs` /
`*.go` sources under `ext/`. If any exist, the memory-safety surface of the compiled code was **not** scanned here —
record a note saying so and that it requires the **`ruby-ext`** profile. That turns a profile-detection miss into a
visible signal instead of silent under-coverage. (You may still audit the extension's C/Rust source by reading, but
say clearly that no sanitizer/instrumented run backed it.)

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- One-liner: `ruby -e '<code>'`
- Multi-line: write to `/tmp/poc.rb`, run `ruby /tmp/poc.rb`
- If the reproducer depends on the project's gems, run it through Bundler from `./src` after `bundle install`, e.g.
  `bundle exec ruby /tmp/poc.rb`, so the locked versions load rather than whatever happens to be on the system
- For framework- or HTTP-routed bugs, isolate the vulnerable method and invoke it directly with the malicious input
  rather than booting a server — keeps the reproducer minimal and the evidence trivial to verify

## Out of scope

- Installed gems — third-party code, not the target of this scan unless a finding specifically pivots through it.
  Gems install under `/work/.gem` (`GEM_HOME`, a sibling of `./src` — not inside it); a project that vendors instead
  goes to `./src/vendor/bundle`. Treat neither as project code.
