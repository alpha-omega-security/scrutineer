# BEAM scanning container

The repository under `./src` is an Erlang or Elixir project, built with rebar3 or Mix.

## Runtime

- **Erlang/OTP 27** — `erl`, `erlc`, `escript`.
- **Elixir 1.20** — `elixir`, `iex`, `mix` (for `mix.exs` projects).
- **`rebar3`** on PATH for Erlang (`rebar.config`) projects.
- **Hex** is installed; the package cache (`/opt/hex`) and Mix archives (`/opt/mix`) live on an exec-capable path rather than under `HOME`, which is a small noexec mount.

## Operating procedure

### Code scanning preparations

Fetch dependencies and compile with the tool that matches the project.

```bash
cd src
mix deps.get && mix compile        # mix.exs (Elixir)
rebar3 compile                     # rebar.config (Erlang)
```

If a fetch fails with a network error the scan is offline — work from the source already present and note which checks
you had to skip. Mix may prompt to install Hex/rebar on first use; they are already installed here, so it should not.

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- Elixir, a focused test: add an ExUnit test under `test/` and run `mix test test/the_test.exs:LINE`. The test output
  is the evidence.
- Elixir, a one-off: `elixir -e 'IO.inspect(Mod.fun(input))'` from `./src` after `mix compile` so the project's
  modules load, or a script run with `mix run /tmp/poc.exs`.
- Erlang: an EUnit test run via `rebar3 eunit --module=mod`, or `erl -pa _build/default/lib/*/ebin -noshell -eval
  'R = mod:fun(Input), io:format("~p~n",[R]), halt().'` after `rebar3 compile`.
- Drive the vulnerable function directly with the malicious input (a crafted binary, an untrusted term passed to
  `:erlang.binary_to_term`, an external command built by string interpolation) rather than booting the whole
  application — keeps the reproducer minimal and the evidence trivial to verify.

## Out of scope

- Fetched dependencies (under `deps/` or the Hex cache) — third-party code, not the target of this scan unless a
  finding specifically pivots through one.
