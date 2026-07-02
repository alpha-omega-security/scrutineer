# Ruby on Rails scanning container

The repository under `./src` is a Ruby on Rails application. The job is to find **security
vulnerabilities** in it. You have the full Ruby runtime **and Brakeman**, the Rails-specific
SAST — use both: Brakeman to enumerate candidate sinks fast, then your own analysis to confirm,
reproduce, and find what Brakeman misses.

## Runtime

- **Ruby 3.4** — `ruby`; `gem` and `bundle` (use `--no-color`) on PATH. C toolchain present so
  native gem dependencies build when you reproduce a `Gemfile` in-place.
- **Brakeman** — `brakeman` on PATH; Rails-aware taint analysis.
- `gh`, `claude` — on PATH.

## Operating procedure

### Preparations

```bash
cd src && bundle install --no-color    # so requires resolve and the app boots for analysis
```

If Bundler fails with `Could not resolve host` or similar the scan is offline — proceed without
installed gems and note which checks you had to skip.

**Ruby version skew.** This container runs Ruby 3.4, but Rails apps commonly pin `ruby "x.y.z"` in the `Gemfile`, and
Bundler *enforces* it — `bundle install` fails if the running Ruby isn't that version. Don't skip silently: note it,
then install the pinned version with `ruby-build <x.y.z> /tmp/ruby-<x.y.z>` (ruby-build is on PATH) and re-run Bundler
under `/tmp/ruby-<x.y.z>/bin/`, or as a last resort comment out the `ruby` directive to proceed (and say you did).
Brakeman is version-independent and runs regardless.

### Run Brakeman

```bash
cd src && brakeman -f json -q -o /tmp/brakeman.json
```

Brakeman runs without booting the app or a database. It reports warnings with a **confidence**
(High/Medium/Weak), a check name (e.g. `SQL`, `CrossSiteScripting`, `MassAssignment`,
`UnsafeReflection`, `Deserialize`, `CommandInjection`, `Redirect`), a file:line, and the tainted
expression.

- **Triage High-confidence warnings first**, then Medium. Each warning is a *lead*, not a
  finding: confirm the taint actually reaches the sink from attacker-controlled input (params,
  headers, cookies, request body), then write a reproducer.
- **Don't blindly forward** Brakeman output. Drop warnings that are guarded, unreachable, or
  framework false positives, and say why. Conversely, Brakeman is pattern-bounded — logic flaws,
  auth/authorization gaps, IDOR, and bugs in non-Rails Ruby it will not see. Cover those yourself.
- De-duplicate against anything the generic semgrep pass already reported for the same sink.

### Rails-specific analysis: metaprogramming & dynamic dispatch

Rails leans heavily on runtime dispatch, so taint reaches sinks through indirection a syntactic
scanner cannot follow — reason about it explicitly:

- **Dynamic dispatch:** `send` / `public_send` / `__send__`, `constantize` / `const_get` /
  `qualified_const_get`, `classify`, and `params`-driven method or class names (unsafe
  reflection → arbitrary method call / class instantiation).
- **Mass assignment:** attributes set straight from `params` without strong-parameters
  (`permit`); `update`/`new`/`assign_attributes` on a permissive hash.
- **Deserialization gadgets:** `Marshal.load`, `YAML.load` / `Psych.load` (non-`safe_load`),
  `JSON.parse(..., create_additions: true)`, and `cookies`/session payloads — the classic Rails
  object-injection RCE path when combined with dynamic dispatch.
- **Command/file sinks via interpolation:** `system` / `exec` / `spawn`, backticks, `%x{}`,
  `IO.popen`, `Open3.*`, `Kernel#open("|cmd")`; `send_file` / `File.read` on a path built from
  params (traversal).
- **Templating/SQL:** raw SQL via string interpolation into `where`/`find_by_sql`/`execute`;
  `html_safe` / `raw` / `<%== %>` on tainted strings (XSS); `render inline:`/`render text:` with
  user input.

### Creating reproducers

Every finding ships a reproducer — code that, run **in this container**, actually triggers the
issue. Paste the exact command and verbatim output. Reasoning-only reproducers do not count; if
you couldn't run it here, say so — never invent one.

- Prefer isolating the vulnerable method/controller action and invoking it directly with the
  malicious input over booting the whole server — minimal reproducer, trivially verifiable
  evidence. One-liner: `ruby -e '<code>'`; multi-line: `/tmp/poc.rb` run with `bundle exec ruby
  /tmp/poc.rb` so the locked gem versions load.
- For a Brakeman-sourced finding, the evidence is the confirmed taint path **plus** a run that
  shows the sink firing on attacker input — not the Brakeman warning alone.

## Native extensions

This profile's interpreter is **not** instrumented for memory safety. If the app vendors or
depends on a gem with a native extension (`ext/**/extconf.rb`, a gemspec with `spec.extensions`)
and you suspect a memory-safety bug in it, note that native scanning requires the **`ruby-ext`**
profile and was not performed here.

## Out of scope

- Installed gems (under `/work/.gem`, or `./src/vendor/bundle` if vendored) — third-party code,
  not the target unless a finding specifically pivots through one.
