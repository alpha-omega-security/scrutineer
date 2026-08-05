# Encrypted findings sharing

Export findings from one scrutineer instance, hand the file to a teammate over any channel, and have them import it. The artifact is age-encrypted at rest the whole way; unencrypted sharing works too.

## Quick start

Use your existing SSH key — no extra key generation needed:

    cat ~/.ssh/id_ed25519.pub
    # ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... you@host

Create a recipients file with everyone's SSH public key, one per line:

    # alice (lead)
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... alice@work
    # bob
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... bob@work

Start scrutineer with both files:

    go run ./cmd/scrutineer -skills ./skills \
      -recipients-file ./recipients.txt \
      -identity-file ~/.ssh/id_ed25519

Or in `scrutineer.yaml`:

    recipients_file: ./recipients.txt
    identity_file: ~/.ssh/id_ed25519

An age identity plugin can replace or accompany the identity file. For
example, to let `age-plugin-1p` locate the matching SSH key in 1Password:

    recipients_file: /path/to/recipients.txt
    identity_plugins:
      - 1p

The equivalent CLI option is repeatable:

    go run ./cmd/scrutineer -skills ./skills \
      -recipients-file /path/to/recipients.txt \
      -identity-plugin 1p

Export a repo's findings as an encrypted bundle:

    curl -o findings.bundle.age \
      'http://127.0.0.1:8080/api/v1/repositories/1/findings?format=bundle&encrypt=1'

Send `findings.bundle.age` over Slack, email, shared drive — it's encrypted to every key in `recipients.txt`.

Import on the receiving end (decryption is automatic):

    curl --data-binary @findings.bundle.age http://127.0.0.1:8080/api/v1/import

Plaintext bundles work too — drop `&encrypt=1` on export and import accepts them as-is regardless of whether an identity is configured.

## The bundle format

`format=bundle` produces a JSON document that matches the minimal ingest shape, so no parser changes were needed:

    {
      "repository": "https://github.com/owner/repo",
      "commit": "abc123",
      "tool": "scrutineer",
      "generated_at": "2026-06-25T12:00:00Z",
      "findings": [
        {
          "title": "...", "description": "...", "severity": "High",
          "confidence": "high", "cwe": "CWE-89", "location": "...",
          "patch": "...", "fix_commit": "...",
          "commit": "...", "sub_path": "...", "locations": "...",
          "vid": "...", "reachability": "reachable", "quality_tier": "high",
          "boundary": "...", "validation": "...", "prior_art": "...",
          "reach": "...", "rating": "..."
        }
      ]
    }

`generated_at` (RFC3339 UTC) records when the bundle was produced. It lives inside the encrypted JSON — not in cleartext around the armor, which would leak the production time to anyone who intercepts the file — and the importer ignores it; it is provenance for the human recipient. The shareable unit is one repository. Severity and status filters apply: `?format=bundle&severity=High` exports only High findings. By default the bundle carries every finding for the repository, including tool-scanner output; add `&scope=findings` to share only the curated Findings bucket — the deep-dive and vuln-scan audits plus operator imports — dropping per-repo semgrep/zizmor noise.

When the source repository was scanned from a local directory, the exporter uses that checkout's HTTPS `origin` for `repository` when one is configured. The common SSH origin forms (`git@host:owner/repo` and `ssh://git@host/owner/repo`) are converted to HTTPS for GitHub, GitLab.com, Bitbucket, and Codeberg. The receiving instance therefore imports a remote repository and clones it automatically when verification or another skill first runs, instead of trying to reuse a sender-only `file:///...` path.

A local checkout without a usable origin keeps its `file://` URL and emits a server warning; that fallback embeds the exporting host's local path in the bundle and is not portable. A receiver without that exact path rejects the import, so use `?repo=https://forge/owner/repo` to provide the clone URL explicitly. Reimporting the same previously generated artifact cannot rewrite the repository value stored inside it. Findings also retain their original commit: if a local commit was never pushed to the exported origin, the receiver can clone the repository but cannot resolve that commit until it is pushed.

What travels is the substance of each finding plus the reasoning that justifies it. Alongside title, severity, confidence, CWE, location and the suggested `patch`, the bundle carries the six-step audit narrative (`description` is the trace; `boundary`, `validation`, `prior_art`, `reach` and `rating` are the other five steps), the `reachability` and `quality_tier` verdicts, the comma-joined `sinks`, the cross-party `vid` correlation hash, the patch's base `fix_commit`, and enough provenance — per-finding `commit`, `sub_path` and the full `locations` set — to resolve the location unambiguously on the receiving side. Every field beyond the original seven is emitted only when set, and the importer tolerates bundles produced before they existed, so the shape is backward-compatible in both directions.

Several things stay out of the default share bundle. Instance-local lifecycle the recipient owns (status, CVE/GHSA id, affected packages, fix version, references, assignee) does not travel — the recipient imports the finding, not your team's triage, and triages it independently on their side (in their case management tool of choice). Your internal workspace — notes and communications — stays out too, as does the enrichment and disclosure work product (CVSS, mitigation, disclosure draft, exploited-in-wild). And source `snippet`s are omitted: the recipient usually owns the code, and a snippet would embed verbatim (possibly private) source into a shared artifact. When you are archiving your *own* findings rather than sharing them, `include=all` carries all of that back — see below.

## Archival exports (`include=all`)

A bundle has a second audience: yourself. The same `format=bundle` export, with `&include=all`, produces an archival superset that round-trips a repository's findings losslessly back into your own instance — the natural unit for an encrypted, per-repo backup.

    curl -o findings.archive.age \
      'http://127.0.0.1:8080/api/v1/repositories/1/findings?format=bundle&include=all&encrypt=1'

On top of the default share-safe set it carries the enrichment and disclosure work product — `snippet`, `affected`, `fix_version`, `cve_id`, `ghsa_id`, the `cvss_vector`/`cvss_v4_vector` (scores are recomputed from the vectors on import, never trusted), `mitigation`/`mitigation_semgrep`, the `breaking_change` verdict, `dup_check`, `disclosure_draft`, `exploited_in_wild` — the real `upstream_fix_commit` (kept on its own key because the legacy `fix_commit` already carries the patch's base), and the finding's `notes`, `communications`, and `references` child records with their timestamps.

Re-importing the same archive is idempotent: a finding that already exists bumps its seen-count, and its child records are content-deduped rather than duplicated.

Three things never travel, even under `include=all`. Instance-local lifecycle the receiver owns (status, resolution, assignee) is dropped so imports land fresh — auto-applying a foreign lifecycle state is the real footgun. The per-field change history is provenance of the instance it happened on; the import itself is the new provenance. Release-watch columns and labels are re-derivable or low-value and stay out.

Because `include=all` embeds your notes, communications, and verbatim source, treat an archival bundle as sensitive: encrypt it (`&encrypt=1`) unless it never leaves the host.

## Key types

SSH keys are the default. Age-native X25519 keys also work if you prefer them.

| File | SSH (default) | age-native |
|------|--------------|-----------|
| Recipients | `ssh-ed25519 ...` or `ssh-rsa ...` | `age1...` |
| Identity | PEM private key (`~/.ssh/id_ed25519`) | `AGE-SECRET-KEY-1...` |

Both types can be mixed in a single recipients file. The format is auto-detected per line.

Passphrase-protected SSH keys are supported. When scrutineer detects an encrypted key at startup, it prompts on stderr and reads the passphrase from stdin (echo disabled). The passphrase is validated immediately — a wrong passphrase fails startup, not the first import. If stdin is not a terminal (e.g. systemd, a container), the startup fails with a clear message; use an unencrypted key or an age-native key in headless deployments.

### Age identity plugins

`identity_plugins` is a list of provider-neutral age plugin names using the
data-less identity contract, equivalent to age's `-j NAME` option. The
repeatable CLI equivalent is `-identity-plugin NAME`. Each name is validated
at startup using the age plugin API, passed through verbatim, and maps to an
`age-plugin-NAME` executable. There is no provider-specific SDK, `op`
integration, shell command, or private-key output path in Scrutineer.

Scrutineer does not launch the executable or trigger authentication until
decryption needs it. HTTP imports invoke it on demand. Federation performs one
pass immediately at startup and then hourly, so an encrypted members export or
import can invoke an interactive plugin during those passes. Plugin interactions
are serialized so concurrent requests cannot overlap terminal prompts. The
selected plugin owns prompt duration, authentication, hardware-touch, and
noninteractive behavior; headless deployments must use authentication that the
plugin itself supports. An unanswered prompt holds that serialized interaction
and delays other plugin-backed decryptions until the plugin returns. A missing
executable is reported at the decrypting operation with the plugin name and
expected binary.

Scrutineer refuses `AGEDEBUG=plugin` with configured identity plugins because
age's raw protocol trace can include values entered at secret prompts.
Plugin-supplied operational error text is likewise kept out of both HTTP
responses and logs because an error stanza is not a trusted secret-free
boundary; use the selected plugin's own safe diagnostic workflow when the
provider-neutral `configured identity plugin ... failed` message is not enough.

Identity files and plugins are additive and are supplied to age together, which
supports migration between local key files and plugin-owned keys. Age continues
to another identity only when the prior one reports `ErrIncorrectIdentity`; a
plugin launch, authentication, or protocol failure aborts that decrypt instead
of silently falling through.

This interface intentionally covers plugins that support age's data-less `-j`
mode. Serialized `AGE-PLUGIN-*` identity payloads are not accepted through
`identity_file` today, so a plugin that requires serialized identity data is
outside this interface.

For the 1Password example, install both
[`age-plugin-1p`](https://github.com/Enzime/age-plugin-1p) and the 1Password
`op` CLI separately and make both available through `PATH`. The plugin locates
the SSH key and performs the age identity operation; Scrutineer itself never
receives or writes the SSH private key. Authentication prompts, Touch ID, and
session handling belong to the plugin and 1Password.

If `op` is signed in to more than one account, set `OP_ACCOUNT` in the
environment Scrutineer is launched from so the plugin's `op` calls resolve to
the right one. It accepts an account shorthand, sign-in address, account ID,
or user ID; `op account list` shows the available values:

    OP_ACCOUNT=my.1password.com scrutineer \
      -recipients-file /path/to/recipients.txt \
      -identity-plugin 1p

Keep it in the service or launcher environment rather than `scrutineer.yaml`:
it is a 1Password setting the plugin's own `op` invocation reads, and
Scrutineer's configuration stays provider-neutral.

`age-plugin-1p` can decrypt files encrypted to ordinary `ssh-ed25519` or
`ssh-rsa` recipients, so existing recipients files and ciphertext bundles do
not need to be converted or re-encrypted. Headless operation depends on the
selected plugin's own noninteractive authentication support; Scrutineer does
not add a separate credential or command-execution mechanism.

### Unsupported: FIDO2 / ed25519-sk keys

`sk-ssh-ed25519@openssh.com` keys (YubiKey FIDO2, Windows Hello) **cannot** be used with age encryption. Age decrypts via X25519 key agreement, which requires the raw private key; FIDO2 devices only expose signing and never export key material. This is a fundamental protocol mismatch — the age CLI has the same limitation.

`age-plugin-yubikey` uses the YubiKey PIV applet and serialized plugin identity
data rather than the data-less `-j` contract. Scrutineer's current
`identity_plugins` interface therefore does not support it. This is separate
from the fundamental FIDO2 limitation above.

For headless servers, a dedicated unpassworded ed25519 key with restrictive file permissions is the standard approach:

    ssh-keygen -t ed25519 -N "" -f ~/.ssh/scrutineer
    chmod 600 ~/.ssh/scrutineer

## Managing a team keyring

Keep `recipients.txt` in a git repo the team already reviews:

    security-keys/
      recipients.txt
      README.md

Adding a contributor is a one-line PR; removing one is deleting their line. `git blame` is the audit trail.

Point scrutineer at the local checkout:

    recipients_file: ../security-keys/recipients.txt

When the team rotates, `git pull` and restart (or just re-export; scrutineer loads the file once at startup).

### Key rotation

1. The contributor generates a new SSH key (or age key) and PRs their new public key into `recipients.txt`.
2. Remove the old public key from `recipients.txt` once all in-flight bundles have been consumed.
3. On the decrypt side, update `-identity-file` to point at the new private key.

For age-native identities, the identity file can hold multiple keys (one per line) so old + new both decrypt during the transition. SSH identity files hold one key each.

## What the encryption covers

- The exported artifact is encrypted; the live SQLite database stays plaintext on `127.0.0.1`, already inside the trust boundary.
- It provides confidentiality and integrity, not sender authentication: a recipient can verify the bundle wasn't tampered with, but cannot cryptographically prove who produced it.
- There is no revocation. Removing someone from `recipients.txt` blocks future exports, but anything they already received stays decryptable — offboarding means they keep what they already had.
- age does not auto-add the sender, so your own public key must be in `recipients.txt` or you cannot open your own archived bundles.

## Flags and config

| Flag | Config | Description |
|------|--------|-------------|
| `-recipients-file` | `recipients_file` | Public keys for encrypted export |
| `-identity-file` | `identity_file` | Private key for decrypting imports and encrypted federation feeds |
| `-identity-plugin NAME` (repeatable) | `identity_plugins` | Data-less age identity plugins (`age -j`) for decrypting imports and encrypted federation feeds |

All are optional. When absent the feature is fully disabled and all endpoints behave exactly as before.

## Endpoints

No new routes. The existing endpoints gain three optional parameters:

| Endpoint | Parameter | Effect |
|----------|-----------|--------|
| `GET /api/v1/repositories/{id}/findings` | `format=bundle` | JSON bundle instead of NDJSON |
| `GET /api/v1/repositories/{id}/findings` | `encrypt=1` | Wrap bundle in armored age (requires `format=bundle`) |
| `GET /api/v1/repositories/{id}/findings` | `scope=findings` | Curate the bundle to the Findings bucket, excluding scanner noise (requires `format=bundle`) |
| `GET /api/v1/repositories/{id}/findings` | `include=all` | Promote the bundle to the archival superset — enrichment, disclosure fields, and notes/communications/references — for lossless round-trip into your own instance (requires `format=bundle`) |
| `POST /api/v1/import` | *(none)* | Auto-detects age header and decrypts before parsing |
