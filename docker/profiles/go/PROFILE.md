# Go scanning container

The repository under `./src` is a Go module.

## Runtime

- **Go 1.26** — `go`. `GOTOOLCHAIN=local`, so the installed toolchain is used as-is rather than downloading another one mid-scan.
- **`govulncheck`** on PATH — reports known vulnerabilities in the module graph and, with source, which are actually reachable.
- C toolchain (`build-essential`) for cgo, so a project that imports `"C"` builds, tests, and reproduces.

The Go module cache, build cache, and tmp dir live under `/opt/go` (an exec-capable path), because `HOME` is a noexec
mount and `go run`/`go test` execute the binaries they build.

## Operating procedure

### Code scanning preparations

Modules resolve from `go.mod`/`go.sum`; there is no separate install step. Warm the build and verify it compiles:

```bash
cd src
go build ./...
```

If a build needs modules not yet cached, `go` fetches them on first use. If that fails with a network error the scan
is offline — work from the source already present and note which checks (including `govulncheck`, which needs its
vulnerability database) you had to skip.

### Reachability

`govulncheck ./...` from the module root reports known-vulnerable symbols the code actually calls, which is stronger
evidence than a version-only advisory match. Quote its output when a finding rests on it.

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- A focused test: write `xxx_test.go` next to the code and run `go test -run TestXxx ./path/...`. The test output is
  the evidence.
- A standalone program: write to `/tmp/poc/` with its own `go.mod`, or add a `main` package under the module, and
  `go run` it.
- Drive the vulnerable function directly with the malicious input rather than booting the whole service — keeps the
  reproducer minimal and the evidence trivial to verify.
- For a panic or data race, `go test -race` turns a latent race into a loud, pinpointed report; quote it.

## Out of scope

- Dependencies under the module cache (`$GOMODCACHE`) — third-party code, not the target of this scan unless a finding
  specifically pivots through one.
