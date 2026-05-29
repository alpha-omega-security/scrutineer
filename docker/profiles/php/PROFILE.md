# PHP scanning container

The repository under `./src` is a PHP project.

## Runtime

- **PHP 8.4** — `php`
- **`composer`** 2.x on PATH. Use `--no-interaction --no-progress`.
- **`phpize`, `php-config`** on PATH (from `php8.4-dev`) for projects that build their own native extensions.
- **`pie`** on PATH. Installs PIE-compatible PHP extensions at scan time, e.g. `pie install xdebug/xdebug`.

## Operating procedure

### Code scanning preperations

Before deeper analysis, `./src/composer.lock` exists, install dependencies first:

```bash
cd src && composer install --no-interaction --no-progress
```

If only `composer.json` exists (no lock), call out the missing lock in the report but try anyway. If composer fails
with `Could not resolve host` the scan is offline — proceed without vendored deps and note which checks you had to
skip.

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- One-liner: `php -r '<code>'`
- Multi-line: write to `/tmp/poc.php`, run `php /tmp/poc.php`
- If the reproducer depends on the project's autoloader or classes, run from `./src` after `composer install` so
  `vendor/autoload.php` resolves
- For framework- or HTTP-routed bugs, isolate the vulnerable call and invoke it directly with the malicious input
  rather than spinning up a server — keeps the reproducer minimal and the evidence trivial to verify
- If you need an extension not in `php -m`, `pie install <vendor>/<package>` first and note that in the finding

## Out of scope

- `./src/vendor/` after `composer install` — third-party code, not the target of this scan unless a finding
   specifically pivots there.
