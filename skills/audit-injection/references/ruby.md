# Ruby injection reference

Load for Ruby, Rails, ERB, Liquid, Tilt, YAML/Psych, Marshal, Kernel process
helpers, metaprogramming dispatch, and dynamic constant loading.

## Version facts to check

- Ruby Psych 4.0 changed `YAML.load` defaults toward safe loading. Ruby 3.1
  ships Psych 4. For older Psych/Ruby stacks, `YAML.load` can instantiate Ruby
  objects; `YAML.safe_load` is the untrusted-input-safe choice. Sources:
  https://bugs.ruby-lang.org/issues/17866 and
  https://ruby-doc.org/stdlib-3.1.0/libdoc/psych/rdoc/Psych.html
- `Marshal.load` is unsafe for untrusted bytes in every Ruby version because
  object hooks and gadget classes can execute behavior during load.
- Rails signed/encrypted cookies are not attacker-writable without the secret
  key. Do not report cookie deserialization unless the attacker can forge or
  write the serialized bytes.
- ERB compiles Ruby code. Liquid is designed for safer user-authored templates,
  but custom filters/tags can reintroduce dangerous method calls.

## Dangerous APIs

- Command execution: `system("...#{user}...")`, backticks, `%x(...)`,
  `IO.popen`, `Open3.capture*` with one command string, `Kernel.exec`, and
  shell wrappers using `sh -c`.
- Dynamic code and dispatch: `eval`, `instance_eval`, `class_eval`,
  `module_eval`, `send(user_method)` or `public_send(user_method)` when the
  method set is not allowlisted, and `constantize`/`const_get` on attacker
  values that reach privileged classes.
- Deserialization: `Marshal.load`, `YAML.load`, `Psych.load`, `Oj.load` with
  object mode or class creation, and custom coders that call constructors from
  user-controlled class names.
- Templates: `ERB.new(user_source).result`, Tilt rendering attacker-supplied
  source, tenant-selected partials outside an allowlist, and helper/filter
  registration driven by request data.

## Safe or non-reportable forms

- `system("git", "clone", "--", user_url)` passes argv separately and is not
  shell interpolation.
- Rails `render "literal"` or rendering data into trusted templates is not
  SSTI.
- `YAML.safe_load` and `Psych.safe_load` are safe for primitive data when class
  allowlists do not include dangerous application classes.
- `public_send` over a closed literal allowlist is acceptable.

## Commands

```bash
rg -n 'system\(|IO\.popen|Open3\.|`[^`]*#\{|%x\(|Kernel\.exec' ./src
rg -n '\beval\(|instance_eval|class_eval|module_eval|public_send|send\(|constantize|const_get' ./src
rg -n 'Marshal\.load|YAML\.load|Psych\.load|Oj\.load|safe_load' ./src
rg -n 'ERB\.new|Tilt\.new|Liquid::Template|render\s+params|render\(.*params' ./src
```
