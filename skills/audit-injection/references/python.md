# Python injection reference

Load for Python, Django, Flask, FastAPI, Jinja2, PyYAML, pickle-like formats,
subprocess wrappers, dynamic imports, and eval-like APIs. Report only when the
source is attacker-controlled and current production code reaches the sink.

## Version facts to check

- PyYAML `yaml.load(x)` without an explicit `Loader` is unsafe before 5.1.
  PyYAML 5.1 through 5.4 defaulted toward `FullLoader`; `FullLoader` before
  5.3.1 still allowed Python object construction gadgets. Treat
  `yaml.safe_load` and `yaml.load(..., Loader=yaml.SafeLoader)` as safe for
  untrusted YAML.
- `pickle`, `cloudpickle`, `dill`, `joblib`, `pandas.read_pickle`, and
  `torch.load` remain unsafe for untrusted bytes in all versions because load
  can invoke importable callables.
- Django defaults to JSON session serialization since 1.6. A project setting
  `SESSION_SERIALIZER = "django.contrib.sessions.serializers.PickleSerializer"`
  reintroduces pickle risk.
- Jinja2 sandbox escapes have had bypasses, but `render_template("file.html",
  data)` with a literal trusted file is not SSTI. `Template(user_text)` and
  Flask `render_template_string(user_text)` are the relevant template-source
  sinks.

## Dangerous APIs

- Command execution: `os.system`, `os.popen`, `subprocess.*(..., shell=True)`,
  `asyncio.create_subprocess_shell`, shell wrapper helpers, and `sh -c` or
  `bash -c` launched through an argv vector.
- Code evaluation: `eval`, `exec`, `compile`, `ast.parse` followed by compile,
  string-form `getattr`/dispatch when it reaches privileged methods, dynamic
  `importlib.import_module(user_value)`, and `__import__(user_value)`.
- Deserialization: `pickle.load(s)`, `cloudpickle.load(s)`, `dill.load(s)`,
  `joblib.load`, `marshal.load(s)`, `yaml.load` with unsafe loader, and ML
  model loaders that accept attacker-provided paths or uploads.
- Templates: `jinja2.Template(user_source)`, `Environment.from_string`, Flask
  `render_template_string`, user-selected template files outside an allowlist,
  and filters/functions registered from attacker-controlled names.

## Safe or non-reportable forms

- `subprocess.run(["cmd", user_arg], shell=False)` with a literal binary is not
  shell injection on POSIX. Check for argument injection separately only when a
  sensitive binary needs `--` or an allowlist.
- `yaml.safe_load`, `json.loads`, Pydantic model parsing, and typed DTO parsing
  are not object-construction RCE by themselves.
- Pickle used for same-process caches, trusted internal queues, or state written
  and read only by the application is not attacker-controlled unless another
  boundary lets an attacker write the bytes.
- Literal Django/Flask/Jinja template names with user data passed as variables
  are not SSTI.

## Commands

```bash
rg -n 'subprocess|os\.system|os\.popen|create_subprocess_shell|shlex|shell=True' ./src
rg -n '\beval\(|\bexec\(|compile\(|importlib\.import_module|__import__' ./src
rg -n 'pickle\.loads?|cloudpickle\.loads?|dill\.loads?|joblib\.load|marshal\.loads?|torch\.load|yaml\.load' ./src
rg -n 'render_template_string|Environment\.from_string|jinja2\.Template|Template\(' ./src
rg -n 'PyYAML|pyyaml|Django|Flask|FastAPI|Jinja2' ./src
```
