# Node.js scanning container

The repository under `./src` is a JavaScript or TypeScript project.

## Runtime

- **Node.js 22** — `node`
- **`npm`** on PATH (bundled with Node).
- **`pnpm`** and **`yarn`** (classic 1.x) on PATH, for projects whose lockfile is `pnpm-lock.yaml` or `yarn.lock`.
- C toolchain (`build-essential`) plus `python3`, so packages with native addons build via `node-gyp` when a scan reproduces them in-place.

## Operating procedure

### Code scanning preparations

Install dependencies with the manager that matches the lockfile present, so imports resolve and any native addons build:

```bash
cd src
npm ci                          # package-lock.json
pnpm install --frozen-lockfile  # pnpm-lock.yaml
yarn install --frozen-lockfile  # yarn.lock
```

Pick one based on which lockfile exists; do not run more than one. If only `package.json` exists (no lock), call out the
missing lock in the report and fall back to `npm install`. If install fails with `Could not resolve host` or a similar
network error the scan is offline — proceed without installed packages and note which checks you had to skip.

`corepack` is disabled, so the `pnpm`/`yarn` above are the image's pinned globals. If a project pins a different exact
manager version via the `packageManager` field, just use the global one and note the version difference rather than
trying to fetch the pinned version.

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- One-liner: `node -e '<code>'`
- Multi-line: write to `/tmp/poc.js`, run `node /tmp/poc.js`
- If the reproducer imports the project's own modules, run it from `./src` after installing dependencies so
  `node_modules` and the package's entry points resolve. Use `node --input-type=module` or a `.mjs` file for ESM
  packages
- For TypeScript sources, prefer requiring the published/compiled entry point; if you must run a `.ts` file directly,
  compile the minimal slice rather than pulling in a full build
- For framework- or HTTP-routed bugs, isolate the vulnerable function and call it directly with the malicious input
  rather than booting a server — keeps the reproducer minimal and the evidence trivial to verify

## Out of scope

- `./src/node_modules/` after install — third-party code, not the target of this scan unless a finding specifically
  pivots through it.
