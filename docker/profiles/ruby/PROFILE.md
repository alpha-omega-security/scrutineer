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

- Installed gems (Bundler's gem path, or `./src/vendor/bundle` if the project vendors there) — third-party code, not
  the target of this scan unless a finding specifically pivots through it.
