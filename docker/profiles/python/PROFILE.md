# Python scanning container

The repository under `./src` is a Python project.

## Runtime

- **CPython 3.13** — `python` / `python3` (a pinned uv-managed interpreter).
- **`uv`** on PATH for environment and dependency management. Use it for installs (`uv venv`, `uv pip`, `uv sync`, `uv run`).
- C toolchain (`build-essential`, `pkg-config`) plus the `ffi`/`openssl`/`zlib` dev headers, so C-extension wheels compile when a scan reproduces a project that ships them.

There is no global `pip`; the interpreter is externally managed. Install into a venv with `uv pip`, or use `uv run`.

## Operating procedure

### Code scanning preparations

Create an environment and install the dependency set with the manager that matches the project, so imports resolve and
any C extensions build:

```bash
cd src
uv venv && . .venv/bin/activate

uv pip install -r requirements.txt   # requirements*.txt
uv sync                              # uv.lock, or a PEP 621 pyproject.toml
```

For Poetry, Pipenv, or PDM projects, `uv pip install -r <exported-requirements>` works once you have a requirements
file, or install the lock's pinned set directly if the tool is available. If only `pyproject.toml` exists with no lock,
call out the missing lock in the report and install the declared dependencies anyway. If install fails with `Could not
resolve host` or a similar network error the scan is offline — proceed without installed packages and note which checks
you had to skip.

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- One-liner: `python -c '<code>'`
- Multi-line: write to `/tmp/poc.py`, run `python /tmp/poc.py`
- If the reproducer imports the project's own modules, run it from `./src` inside the activated venv so the package and
  its dependencies resolve. `uv run python /tmp/poc.py` also works and provisions the environment on demand
- For framework- or HTTP-routed bugs, isolate the vulnerable function and call it directly with the malicious input
  rather than booting a server — keeps the reproducer minimal and the evidence trivial to verify

## Out of scope

- Installed third-party packages (under the venv's `site-packages`) — not the target of this scan unless a finding
  specifically pivots through one.
