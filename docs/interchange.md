# Interchange and federation

Scrutineer instances (and non-scrutineer tools) can exchange a small set of
federation records without ever exchanging finding bodies. This page documents
the interchange format foundations: the record envelope, the shipped JSON
schema, the salted finding hash, and the claim-check endpoint. Feeds (public
and members-only git repositories), the export/import jobs, and Sigstore
signing are future work and not described here.

## Records

Every record is an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
envelope: `_type`, `subject`, `predicateType`, `predicate`. The
`predicateType` URI names the record kind:

| Kind | `predicateType` | Meaning |
|------|-----------------|---------|
| certificate | `.../scrutineer/interchange/certificate/v1` | An advisory's advertised fix was re-audited on the named repository and held. The local `GET /advisories/{id}/certificate.json` download attests the same audit but in a different, richer format (severity, CVSS, evidence) that is NOT an interchange record and must never be fed into a federation feed. |
| claim | `.../scrutineer/interchange/claim/v1` | The publishing instance holds a finding whose salted hash is the subject digest, plus a contact to coordinate through. |
| optout | `.../scrutineer/interchange/optout/v1` | The repository's maintainer asked federated instances to neither scan the repository nor contact them about it. |
| route | `.../scrutineer/interchange/route/v1` | The validated disclosure route for a repository (email, GHSA URL, registry owner handle, or SECURITY.md URL), so other instances can skip re-deriving it. |

The normative contract is
[`internal/interchange/interchange.schema.json`](../internal/interchange/interchange.schema.json),
embedded into the binary; `interchange.Validate` checks a raw record against
it. Predicate schemas set `additionalProperties: false` on purpose: records
never carry finding bodies, severity, CVSS, or health scores, and a record
that smuggles one in fails validation. The envelope itself stays open so
spec-legal in-toto extensions (subject `uri`, extra digest algorithms, ...)
from non-scrutineer producers validate fine.

## The salted finding hash

Federation members share a secret salt out of band. A finding's federation
identifier is:

```
sha256(salt NUL repo NUL location NUL cwe)   hex-encoded
```

joined with NUL (`0x00`) bytes, where:

- `repo` is the repository URL lowercased, with any trailing `/` and `.git`
  stripped;
- `location` is the repo-root-relative file path: first line only, positional
  suffix stripped (`:42`, `:42:7`, and the `:10-20` range form), backslashes
  normalised to `/`, the scan `sub_path` prepended, lowercased;
- `cwe` is the finding's comma-joined CWE list canonicalised: elements
  trimmed, uppercased, empties dropped, sorted, joined with a bare comma
  (empty stays empty).

Two instances holding the same vulnerability derive the same hash without
coordinating; without the salt the hash reveals nothing enumerable. The
canonicalisation is a wire contract implemented once in
`internal/interchange` and deliberately independent from the internal
fingerprint helpers, so an internal normalisation tweak cannot silently
change published hashes.

## Claim-check endpoint

Before reporting a finding upstream, a federation peer can ask whether this
instance already holds it:

```
POST /claim-check
{"hash": "<64 hex chars>"}
```

Responses:

- `200 {"match": true, "contact": "<federation_contact>"}` -- a non-rejected,
  non-duplicate finding with that hash exists here; coordinate through the
  contact before reporting.
- `200 {"match": false}` -- no such finding; a miss reveals nothing else.
- `400` -- malformed JSON or hash.
- `404` -- `federation_salt` is not configured, or the method is not POST; a
  non-federated instance is indistinguishable from one without the endpoint.

The hash set is cached for up to a minute so request floods cost map lookups
rather than a findings-table scan each time; a match may therefore lag a
freshly written finding by that long.

## Configuration

```yaml
federation_salt: "shared secret distributed out of band"
federation_contact: "security@example.com"
```

Both default to empty; an empty salt disables federation, and startup
refuses a salt without a contact. The salt is deliberately config-file only
(no CLI flag): a secret in argv leaks via `ps` and shell history. The
contact may also be set with `-federation-contact`.

Like the rest of the web surface, `/claim-check` sits behind the loopback
Host check (see [threatmodel.md](../threatmodel.md)). Exposing it to peers is
a deployment decision: front it with a reverse proxy that forwards only
`POST /claim-check` and sets `Host: 127.0.0.1:8080`.
