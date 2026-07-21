# Command and code execution review

## What is dangerous

Treat a sink as execution-capable when it interprets data as shell syntax,
source code, an expression, a module name, a program path, or process
arguments with shell-like expansion. Common examples include shell adapters,
string-based process APIs, eval or Function-like APIs, expression-language
engines, and dynamic module or plugin loaders.

The relevant distinction is semantic, not the API name. A wrapper around a
process launcher can be as dangerous as a direct shell invocation.

## What to prove

For a report, show all of the following:

1. An untrusted value crosses a real boundary.
2. It reaches an interpreter or process-launching semantic.
3. The path is not converted to a fixed command plus separately passed,
   validated arguments before that semantic.
4. Any allowlist, parser, escaping, or privilege boundary is insufficient for
   the actual shell, runtime, or platform in use.

Prefer a trace from a request, message, uploaded artifact, or tenant record to
the execution sink. A command assembled only from constants, a fixed argv
vector passed to a non-shell process API, or a developer-only maintenance tool
is normally not a finding.

## Checks that often change the result

- Process APIs differ: inspect whether a wrapper invokes a shell, accepts one
  string, parses a command line, inherits an unsafe environment, or uses an
  argv vector.
- Escaping is context-specific. Quoting for one shell does not establish
  safety for another shell or for a later interpreter.
- Dynamic import or plugin names are not automatically code execution. Prove
  an attacker can select an executable module outside the intended allowlist.
- Template expressions, query builders, and configuration interpolation may
  have their own evaluators; identify the evaluator rather than assuming
  ordinary string concatenation is execution.

Record the local package or framework version whenever its behavior matters.

## Framework and runtime notes

- Python: distinguish subprocess calls with a fixed argument list from
  shell=True or a string passed through a shell. Inspect application wrappers
  around subprocess, os.system, asyncio subprocess helpers, and dynamic import
  utilities.
- Node.js: child_process.exec and shell-enabled spawn behavior differ from
  execFile or spawn with a fixed argument array. Check template or expression
  packages rather than treating ordinary require calls as execution.
- Go: os/exec.Command does not invoke a shell by itself; a shell becomes
  relevant only when code explicitly launches sh, bash, cmd, powershell, or a
  comparable interpreter. Inspect command-wrapper helpers and plugin loaders.
- Java, Ruby, and JVM languages: inspect ProcessBuilder or runtime wrappers,
  string command parsing, script engines, reflection, and application-defined
  dispatch. Fixed command arrays and constrained enums are materially
  different from one interpolated command string.
