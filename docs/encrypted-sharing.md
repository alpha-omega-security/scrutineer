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
      "findings": [
        { "title": "...", "description": "...", "severity": "High", ... }
      ]
    }

The shareable unit is one repository. Severity and status filters apply: `?format=bundle&severity=High` exports only High findings.

Only the substance of each finding travels: title, description, severity, confidence, CWE, location, and suggested patch. Analyst-set triage state (status, CVE/GHSA id, affected packages, fix version, references) is intentionally left out — the recipient imports the finding, not your team's triage, and triages it independently on their side (in their case management tool of choice).

## Key types

SSH keys are the default. Age-native X25519 keys also work if you prefer them.

| File | SSH (default) | age-native |
|------|--------------|-----------|
| Recipients | `ssh-ed25519 ...` or `ssh-rsa ...` | `age1...` |
| Identity | PEM private key (`~/.ssh/id_ed25519`) | `AGE-SECRET-KEY-1...` |

Both types can be mixed in a single recipients file. The format is auto-detected per line.

Passphrase-protected SSH keys are supported. When scrutineer detects an encrypted key at startup, it prompts on stderr and reads the passphrase from stdin (echo disabled). The passphrase is validated immediately — a wrong passphrase fails startup, not the first import. If stdin is not a terminal (e.g. systemd, Docker), the startup fails with a clear message; use an unencrypted key or an age-native key in headless deployments.

### Unsupported: FIDO2 / ed25519-sk keys

`sk-ssh-ed25519@openssh.com` keys (YubiKey FIDO2, Windows Hello) **cannot** be used with age encryption. Age decrypts via X25519 key agreement, which requires the raw private key; FIDO2 devices only expose signing and never export key material. This is a fundamental protocol mismatch — the age CLI has the same limitation.

**YubiKey users who want hardware-backed decryption** can use `age-plugin-yubikey`, which talks to the YubiKey's PIV applet (a separate applet from FIDO2 on the same device). This produces `age1yubikey1...` recipients and requires physical touch per decrypt. See [github.com/str4d/age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey). Note that PIV-based decrypt requires someone physically present at the server for each encrypted import, so it is impractical for headless deployments.

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
| `-identity-file` | `identity_file` | Private key for decrypting imports |

Both are optional. When absent the feature is fully disabled and all endpoints behave exactly as before.

## Endpoints

No new routes. The existing endpoints gain two optional parameters:

| Endpoint | Parameter | Effect |
|----------|-----------|--------|
| `GET /api/v1/repositories/{id}/findings` | `format=bundle` | JSON bundle instead of NDJSON |
| `GET /api/v1/repositories/{id}/findings` | `encrypt=1` | Wrap bundle in armored age (requires `format=bundle`) |
| `POST /api/v1/import` | *(none)* | Auto-detects age header and decrypts before parsing |
