---
name: mitigate
description: Draft operational mitigations for a finding consumers can apply before a fix ships. Workarounds (config flags, input restrictions, safe defaults), detection guidance (what to log and what pattern to alert on), and optionally a semgrep rule that flags the same pattern in other code bases. Distinct from disclose, which drafts the public advisory, and from patch, which proposes the code fix.
license: MIT
compatibility: Read-only against `./src`; needs network access to the scrutineer skill API to read the finding.
metadata:
  scrutineer.version: 1
  scrutineer.output_file: report.json
  scrutineer.output_kind: mitigation
  scrutineer.requires_remote: true
---

# mitigate

A finding has been confirmed and disclosure is in flight, but a fix is not out yet. Consumers running the affected code right now need guidance: how to harden the deployment, what to log so they can detect exploitation, and (where it fits) a semgrep rule that flags the same shape in their own code so they can audit beyond this one library.

This skill drafts that guidance. It is distinct from the disclose skill (which drafts the GHSA advisory) and from the patch skill (which proposes the upstream fix). Mitigations live alongside the advisory; they are what consumers do while waiting for the fix to ship, and what defenders watch for while the issue is live.

## Workspace

- `./src` — the repository at the scanned commit; read-only
- `./context.json` — has `scrutineer.api_base`, `scrutineer.token`, `scrutineer.finding_id`, `scrutineer.repository_id`
- `./report.json` — write the mitigation guidance here
- `./schema.json` — output shape

## Inputs

Fetch the finding so you know what you are mitigating:

```
GET {api_base}/findings/{finding_id}
Authorization: Bearer {token}
```

Read `title`, `severity`, `location`, `cwe`, and the six-step prose (especially `boundary` for the trigger and `validation` for the reproduction). Those describe what an attacker must do and what they get; mitigation is the inverse — what a defender does to make the attack expensive or visible.

## Procedure

1. **Identify the entry point.** From the boundary and validation steps, find the smallest deployment-level surface attackers reach the sink through: an HTTP route, a config flag that opens a feature, a CLI subcommand, a public method on a library export. Mitigations attach there.

2. **Draft workarounds.** Each workaround is a concrete change a consumer can apply now without an upstream fix. Examples by class:
   - Config flag: "set `debug.eval = false` in production; disabling this loses the eval REPL but blocks the injection."
   - Input restriction: a reverse proxy rule that caps body size below the overflow threshold, a WAF rule that drops requests with the trigger pattern.
   - Safe default: a wrapper module that calls the vulnerable function with the dangerous parameter forced to a safe value.
   - Process restriction: drop a Linux capability, run the worker as a non-root user, jail the binary in a seccomp profile.

   Each workaround names the cost ("blocks the eval REPL") so the consumer can decide. Do not draft a workaround when the trade is not worth making.

3. **Draft detection guidance.** What does an exploitation attempt look like in logs, telemetry, or runtime traces? Be concrete: a stack frame name, a request shape, an error class. If the application emits no useful signal today, say what it should log to make this detectable (and where in the code to add it).

4. **Generate a semgrep rule, optionally.** When the vulnerable pattern is structural — a particular sink called with unchecked input, a deprecated API still in use, a specific config combination — write a semgrep rule that flags it. Use the `p/r2c-internal-cmd-injection` style: one rule per id, with a `pattern` or `patterns` block, `message`, `severity`, `languages`, and `metadata.references` pointing at the finding's commit and advisory if available. Validate the rule against `./src` to confirm it matches the finding's location and does not over-match obvious safe call sites. If you cannot write a rule that distinguishes the bug from safe usages, do not write one — a noisy rule is worse than no rule.

5. **Keep it specific.** "Apply input validation" is not mitigation guidance, it is a tautology. Name the function, the field, the threshold, the config key, the commit, the file.

## Output

Write `./report.json` matching `./schema.json`:

```json
{
  "guidance": "markdown body covering workarounds and detection",
  "semgrep_rule": "optional YAML for a single semgrep rule"
}
```

`guidance` is markdown; use sub-headings for the sections (`## Workarounds`, `## Detection`). `semgrep_rule` is a complete YAML document including `rules:`; omit the field rather than emit a stub.

Scrutineer writes both to the finding (`mitigation` and `mitigation_semgrep` columns) with the changes recorded in finding history. The mitigation panel on the finding page renders the markdown and the rule together; the disclosure draft includes the mitigation section so the advisory and the workarounds travel as one piece.
