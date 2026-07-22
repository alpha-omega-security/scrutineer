# Node and JavaScript injection reference

Load for Node, Express, Fastify, Koa, Hono, Elysia, Next.js, template engines,
child process use, VM sandboxes, prototype pollution to execution, and unsafe
serialization packages.

## Version facts to check

- Node's Windows BatBadBut fix landed in 18.20.0, 20.12.0, and 21.7.0. Before
  those versions, spawning `.bat` or `.cmd` files with attacker-controlled
  arguments can invoke `cmd.exe` parsing even without an explicit shell.
- `vm2` is abandoned and should be treated as unsafe in every version; the
  project was archived in 2023 after repeated sandbox escape CVEs.
- `node-serialize` `unserialize` is unsafe in every version on untrusted input
  because function markers are evaluated.
- Handlebars before the 4.7.x hardening line had multiple prototype-pollution
  and helper lookup RCE chains. Treat template compilation after user-controlled
  deep merge as suspicious unless the installed version and merge guard rule it
  out.
- `lodash` prototype pollution fixes relevant to execution chains include
  4.17.11 for CVE-2018-3721/CVE-2019-10744 style merge pollution and 4.17.19
  for CVE-2020-8203 in path-setting helpers. Older versions need a downstream
  execution sink before reporting here.

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
