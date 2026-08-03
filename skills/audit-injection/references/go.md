# Go injection reference

Load for Go process execution wrappers, templates, plugins, reflection dispatch,
gob/YAML parsing, CEL/Expr evaluators, and interpreter-like packages.

## Version facts to check

- `os/exec.Command` does not invoke a shell. A command becomes shell injection
  when code explicitly runs `sh`, `bash`, `cmd`, `powershell`, or another
  interpreter with attacker-controlled text.
- `text/template` does not escape output; `html/template` escapes for HTML
  contexts. Neither is SSTI unless attacker input controls template source,
  parse text, template names, or function maps.
- `encoding/gob` can instantiate registered concrete types and call decoding
  methods, but ordinary gob decode is not arbitrary code execution without an
  attacker-controlled type/hook path. Verify registered types and decode target.
- `gopkg.in/yaml.v2`/`v3` decode into data/structs by default. Custom
  `UnmarshalYAML`, mapstructure hooks, or later dispatch from decoded fields
  are the risky cases.
- HashiCorp `go-plugin`, Go `plugin.Open`, Yaegi, Starlark, CEL, Expr, and Lua
  embedders are version- and policy-sensitive; report only when attacker input
  selects executable code or a privileged host function.

## Dangerous APIs

- Command execution: `exec.Command("sh", "-c", userText)`,
  `exec.CommandContext(..., "bash", "-c", userText)`, Windows shell wrappers,
  and helper functions that build one shell command string.
- Dynamic execution/loading: `plugin.Open(userPath)`, Yaegi `Eval`,
  Starlark/Lua interpreters with host functions, CEL/Expr evaluation over
  user-authored expressions, reflection method calls selected by request data,
  and `go generate`/tool runner endpoints exposed to users.
- Templates: `template.New(...).Parse(userText)`, `ParseFiles` over a
  user-controlled path, dynamic template lookup outside an allowlist,
  user-controlled `FuncMap`, or `template.HTML`/`JS` escape hatches fed by
  request data.
- Deserialization: gob/yaml/json decoders that trigger application-defined
  hooks or later use decoded fields as command names, template source, plugin
  paths, or expression text.

## Safe or non-reportable forms

- `exec.Command("git", "clone", "--", userURL)` is fixed argv, not shell
  injection.
- `html/template` rendering user data through a trusted parsed template is not
  SSTI.
- `encoding/json` into structs is not unsafe deserialization by itself.
- Dynamic dispatch from a closed literal map is acceptable.

## Commands

```bash
rg -n 'exec\.Command|CommandContext|/bin/sh|bash|cmd\.exe|powershell' ./src --type go
rg -n 'plugin\.Open|Eval\(|starlark|yaegi|cel-go|expr\.|lua' ./src --type go
rg -n 'template\.New|ParseFiles|ParseGlob|FuncMap|template\.(HTML|JS|URL)' ./src --type go
rg -n 'gob\.NewDecoder|yaml\.Unmarshal|UnmarshalYAML|mapstructure|reflect\.Value\.Method' ./src --type go
```
