# Server-side template injection review

## Template source is different from template data

Most template engines safely render untrusted values as data when a trusted,
fixed template is used with the engine's ordinary escaped-value syntax.
Server-side template injection requires evidence that an attacker can affect
template source, an expression position, a helper or filter selection, a
template path that resolves outside a trusted set, or an unsafe output context.

Do not confuse server-side templates with client-side XSS. This audit reports
the server-side evaluator only when attacker input can change what it
interprets.

## What to inspect

- Whether template text is loaded from a fixed repository asset, a trusted
  deployment artifact, or an attacker-controlled database, upload, request,
  or tenant setting.
- Whether the engine compiles strings, evaluates expressions, permits dynamic
  includes, or exposes powerful helpers.
- Whether template names and paths are constrained to a trusted allowlist.
- Whether autoescaping applies to the rendered output context and whether a
  raw or safe-string escape hatch is used.

## Reporting standard

Show a concrete source-to-template or source-to-expression trace and the
interpreter behavior that turns it into server-side impact. A user-controlled
display value rendered through a fixed, escaped template is not SSTI.

## Framework and runtime notes

- Jinja, Django, and similar engines: a fixed template rendered with data is
  distinct from Template or from_string compilation of attacker-controlled
  text. Verify sandbox and autoescape settings from local configuration.
- Go html/template and text/template: data interpolation is not template
  source control. Examine Parse, ParseFiles, FuncMap, template-name selection,
  and use of trusted.HTML-style escape hatches in their actual context.
- Node and JVM engines: inspect dynamic template compilation, expression
  language support, include resolution, helper registration, and whether a
  tenant-controlled value can select source or an executable expression.
