# Perl scanning container

The repository under `./src` is a Perl distribution.

## Runtime

- **Perl 5** — `perl` (full Debian `perl`, not the stripped `perl-base`).
- **`cpanm`** on PATH for installing dependencies. `Module::Build` is preinstalled for `Build.PL` dists.
- **`prove`** for running the test suite.
- C toolchain (`gcc`, `make`) plus `libperl-dev` and the common `openssl`/`zlib`/`expat` headers, so XS modules
  compile when cpanm builds a dependency from source.

Modules install under `/work/perl5` via local::lib (`PERL5LIB`, `PERL_MM_OPT`, `PERL_MB_OPT` are already set), a
sibling of `./src`, so installed code stays out of the scanned tree.

## Operating procedure

### Code scanning preparations

Install the distribution's dependencies first so `use` lines resolve and any XS prerequisites build:

```bash
cd src && cpanm --notest --installdeps .
```

`--installdeps .` reads whichever of `cpanfile`, `META.json`/`META.yml`, `Makefile.PL`, or `Build.PL` the dist
provides. `--notest` skips the dependencies' own test suites; the goal is a working `@INC`, not validating CPAN.
If only `Makefile.PL` exists with no META file, run `perl Makefile.PL` first so the dependency list is generated.
If cpanm fails with `Could not resolve host` or a similar network error the scan is offline — proceed without
installed modules and note which checks you had to skip.

The project's own test suite, where present, is `prove -lr t/` (or `perl Build.PL && ./Build test` for
Module::Build dists).

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- One-liner: `perl -Ilib -E '<code>'`
- Multi-line: write to `/tmp/poc.pl`, run `perl -Ilib /tmp/poc.pl` from `./src`
- `-Ilib` puts the project's own modules on `@INC` without installing them; installed dependencies are already on
  `PERL5LIB` via local::lib
- For framework- or HTTP-routed bugs (Mojolicious, Dancer, Catalyst, Plack), isolate the vulnerable sub and call it
  directly with the malicious input rather than booting a server — keeps the reproducer minimal and the evidence
  trivial to verify

## Out of scope

- Installed dependencies under `/work/perl5` — third-party code, not the target of this scan unless a finding
  specifically pivots through it. Treat nothing under that path as project code.
