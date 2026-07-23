# Node and JavaScript injection reference

Load for Node, Express, Fastify, Koa, Hono, Elysia, Next.js, template engines,
child process use, VM sandboxes, prototype pollution to execution, and unsafe
serialization packages.

## Version facts to check

- Node's Windows BatBadBut fix for CVE-2024-27980 landed in 18.20.2,
  20.12.2, and 21.7.3; before those versions, spawning `.bat` or `.cmd`
  files with attacker-controlled arguments can invoke `cmd.exe` parsing even
  without an explicit shell. That fix was bypassed as CVE-2024-36138 until
  18.20.4, 20.15.1, and 22.4.1, so clear Windows `.bat`/`.cmd` spawn findings
  only at or above the July 2024 fixed lines. Sources:
  https://nodejs.org/en/blog/vulnerability/april-2024-security-releases-2 and
  https://nodejs.org/en/blog/vulnerability/july-2024-security-releases
- `vm2` is abandoned and should be treated as unsafe in every version; the
  maintainer stopped maintaining it in 2023 after repeated sandbox escape CVEs.
  Source: https://github.com/patriksimek/vm2/issues/533
- `node-serialize` `unserialize` is unsafe in every version on untrusted input
  because function markers can execute code; the known package advisory affects
  all published versions through 0.0.4 and has no patched version. Source:
  https://github.com/advisories/GHSA-q4v7-4rhw-9hqm
- Handlebars before 4.7.7 had prototype-pollution and helper/lookup RCE chains
  including CVE-2021-23383 and CVE-2021-23369; later advisories also affect
  versions before 4.7.9 in specific runtime/option combinations. Treat template
  compilation after user-controlled deep merge as suspicious unless the
  installed version, options, and merge guard rule it out. Sources:
  https://advisories.gitlab.com/pkg/npm/handlebars/CVE-2021-23383/ and
  https://advisories.gitlab.com/pkg/npm/handlebars/
- `lodash` prototype pollution fixes relevant to execution chains include
  4.17.5 for CVE-2018-3721, 4.17.12 for CVE-2019-10744 `defaultsDeep`
  pollution, and at least 4.17.20 for CVE-2020-8203 `zipObjectDeep` /
  path-setting pollution per NVD/advisory records. Older versions still need a
  downstream execution sink before reporting here. Sources:
  https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=890575,
  https://www.cve.org/CVERecord?id=CVE-2019-10744, and
  https://nvd.nist.gov/vuln/detail/CVE-2020-8203

## Dangerous APIs

- Command execution: `child_process.exec`, `execSync`, `spawn` or `spawnSync`
  with `{shell: true}`, `sh -c`, `cmd.exe /c`, and wrappers that accept one
  interpolated command string.
- Dynamic execution: `eval`, `new Function`, `AsyncFunction`, string-form
  `setTimeout`/`setInterval`, `vm.runInThisContext`, `vm.runInNewContext`,
  `vm2`, and framework expression engines evaluating request data.
- Templates: `Handlebars.compile(user_source)`, `pug.compile(user_source)`,
  `ejs.render(user_template)`, `nunjucks.renderString`, `liquidjs.parseAndRender`
  on tenant-supplied source, and request-controlled `res.render(viewName)`.
- Deserialization and module loading: `node-serialize.unserialize`, dynamic
  `require(user_value)`, dynamic `import(user_value)`, plugin names without a
  closed allowlist, and JSON revivers that instantiate classes or functions.
- Prototype pollution to execution: unguarded `lodash.merge`, `defaultsDeep`,
  `set`, `setWith`, `deepmerge`, or recursive merge of `req.body` followed by
  template compilation, `Function`, `vm`, child_process options, or privileged
  config reads.

## Safe or non-reportable forms

- `execFile("bin", [userArg])` and `spawn("bin", [userArg], {shell:false})`
  with a literal binary are normally safe on POSIX.
- `res.render("literal-view", data)` with a fixed view name is not SSTI.
- `JSON.parse` without a dangerous reviver is not unsafe deserialization.
- Prototype pollution without a traced execution sink belongs outside this
  skill.

## Commands

```bash
rg -n 'child_process|execSync?\(|spawnSync?\(|shell:\s*true' ./src
rg -n '\beval\(|new Function|AsyncFunction|setTimeout\([^,]*string|vm2|vm\.runIn' ./src
rg -n 'Handlebars\.compile|pug\.compile|ejs\.render|renderString|parseAndRender|res\.render\(' ./src
rg -n 'node-serialize|unserialize\(|require\(.*req\.|import\(.*req\.' ./src
rg -n 'lodash|merge\(|defaultsDeep|setWith|__proto__|constructor|prototype' ./src
```
