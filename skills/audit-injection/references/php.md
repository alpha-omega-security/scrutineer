# PHP injection reference

Load for PHP, Symfony, Laravel, Twig, Blade, PHAR metadata, dynamic includes,
process helpers, `eval`/`assert`, and `unserialize`.

## Version facts to check

- `assert($string)` evaluated strings as PHP code before PHP 7.2. On PHP 7.2+
  string assertions no longer evaluate code in the same way; still check
  explicit `eval`.
- `unserialize($user)` remains unsafe on untrusted input in all PHP versions
  when gadget classes with `__wakeup`, `__destruct`, `__toString`, or similar
  magic methods are available. `allowed_classes=false` materially changes risk.
- PHAR metadata deserialization bugs were reduced in PHP 8.0 by stopping
  automatic metadata unserialization in many file operations, but explicit
  PHAR metadata reads and older PHP versions remain risky.
- Twig autoescaping protects output data, not attacker-controlled template
  source. `createTemplate(userText)` or `template_from_string` are SSTI sinks.
- Laravel Blade compiles trusted server templates to PHP. A user-controlled
  Blade template source or include path is code execution.

## Dangerous APIs

- Command execution: `system`, `exec`, `shell_exec`, `passthru`, `popen`,
  backticks, Symfony Process built from one shell string, and shell wrappers
  containing request data.
- Dynamic code and includes: `eval`, `assert` string evaluation on old PHP,
  `preg_replace` with `/e` on PHP before 7, `include`/`require` on
  attacker-controlled paths, `call_user_func` over an untrusted callable, and
  dynamic class names reaching privileged constructors.
- Deserialization: `unserialize`, `Phar` metadata reads on attacker-controlled
  archives, Symfony/Laravel serializer modes that instantiate classes from
  input, and custom object hydrators using user-supplied class names.
- Templates: Twig `createTemplate`, `template_from_string`, Smarty string
  resources, Blade compilation of tenant-supplied text, and request-controlled
  view names outside a closed allowlist.

## Safe or non-reportable forms

- `escapeshellarg` plus a fixed command can mitigate shell metacharacters, but
  still check option injection and missing `--` for sensitive binaries.
- Twig/Blade rendering user variables through fixed server-owned templates is
  not SSTI.
- `json_decode` and Symfony Serializer into a concrete DTO are not object
  construction RCE by themselves.
- `unserialize($data, ["allowed_classes" => false])` blocks object gadgets.

## Commands

```bash
rg -n 'system\(|shell_exec|passthru|popen|proc_open|`[^`]*\$|Symfony\\\\Component\\\\Process' ./src
rg -n '\beval\(|assert\(|preg_replace\(.*\/e|include\s*\(|require\s*\(|call_user_func' ./src
rg -n 'unserialize\(|Phar|allowed_classes|__wakeup|__destruct|__toString' ./src
rg -n 'createTemplate|template_from_string|Smarty|Blade|view\(.*request|render\(.*request' ./src
```
