# Interchange and federation

Scrutineer instances (and non-scrutineer tools) can exchange a small set of
federation records without ever exchanging finding bodies. This page documents
the record envelope, the shipped JSON schema, the on-disk record layout, the
salted finding hash, the claim-check endpoint, and the two feed tiers with the
export and import jobs that keep them in sync. Asking peers before reporting,
and Sigstore signing for the public tier, are future work and not described
here.

## Records

Every record is an
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
envelope: `_type`, `subject`, `predicateType`, `predicate`. The
`predicateType` URI names the record kind:

| Kind | `predicateType` | Meaning |
|------|-----------------|---------|
| certificate | `.../scrutineer/interchange/certificate/v1` | An advisory's advertised fix was re-audited on the named repository and held. `status` is pinned to `fixed`. The local `GET /advisories/{id}/certificate.json` download attests the same audit but in a different, richer format (severity, CVSS, evidence) that is NOT an interchange record and must never be fed into a federation feed. |
| certificate | `.../scrutineer/interchange/certificate/v2` | Same shape, verdict widened to `bypass`, `variant` or `regressed`: the advertised fix did NOT hold. |
| claim | `.../scrutineer/interchange/claim/v1` | The publishing instance holds a finding whose salted hash is the subject digest, plus a contact to coordinate through. |
| optout | `.../scrutineer/interchange/optout/v1` | The repository's maintainer asked federated instances to neither scan the repository nor contact them about it. |
| route | `.../scrutineer/interchange/route/v1` | The validated disclosure route for a repository (email, GHSA URL, registry owner handle, or SECURITY.md URL), so other instances can skip re-deriving it. |

Certificates carry two revisions because the verdict decides which tier may
carry the record, so the split has to be visible in the `predicateType`
alone: a clean certificate says nothing about a live weakness, while a
non-clean one names a repository whose advertised fix does not hold. v1 stays
pinned to the clean case, so a consumer already reading v1 records keeps
handling exactly the values it always has and no coordinated update was
needed to introduce v2. `interchange.NewCertificate` picks the revision from
the verdict, and the schema refuses the crossed pairings in both directions.

The normative contract is
[`internal/interchange/interchange.schema.json`](../internal/interchange/interchange.schema.json),
embedded into the binary; `interchange.Validate` checks a raw record against
it. Predicate schemas set `additionalProperties: false` on purpose: records
never carry finding bodies, severity, CVSS, or health scores, and a record
that smuggles one in fails validation. The envelope itself stays open so
spec-legal in-toto extensions (subject `uri`, extra digest algorithms, ...)
from non-scrutineer producers validate fine.

## Record layout

A set of records is stored as a directory a git remote can serve, one file
per record at `<kind>/<subject-digest>.json`, or
`<kind>/<subject-digest>.json.age` when the set is encrypted. Deriving the
name from the record itself means an unchanged record keeps its own file, so
a commit over such a directory diffs only what actually changed, and a record
that stops applying is deleted rather than left beside its replacement. Files
that are not records (`README`, `LICENSE`, `.git`) are never touched: only
the kind directories are rewritten.

An encrypted record is left alone by comparing plaintexts, not bytes: age
derives a fresh file key per call, so re-encrypting an unchanged record
produces different ciphertext every time and a byte comparison would rewrite
everything on every pass. `interchange.WriteFeed` therefore refuses to write
an encrypted set without an identity as well as recipients: without one it
cannot read back what it published.

Keeping a record's existing ciphertext means access to it is frozen at the
recipient set it was encrypted to, so an encrypted directory also holds a
`.recipients` file: the sha256 of that set, its keys trimmed, lowercased,
sorted, deduplicated and joined with newlines. Nothing in an age file names
its own recipients, so this digest is the only way to notice a membership
change; when it differs from the set in play every record is re-encrypted,
which is what lets a member added to the feed read the records that did not
happen to change since they joined, and takes those same records away from a
member removed. It is written only after every record carries the new set, so
an interrupted rotation is retried rather than recorded as complete. A
recipient whose key cannot be rendered as text is refused outright, since its
removal could not be detected. Only age's own X25519 recipient can render one;
an SSH recipient, which is the documented default, keeps no handle on its key,
so the key is captured where the recipients file is parsed and carried with the
recipient. Its canonical `authorized_keys` form, at that: a trailing comment is
not part of the key and editing one must not read as a new member set.

A directory served this way is a checkout whose contents a peer controls, so
a symlink on a managed path (a kind directory, or a file where a record
belongs) fails the operation instead of being followed: writing and pruning
stay under the directory itself. A record-shaped path that is not a regular
file is still listed as a record, so reading reports it as a failed record
rather than omitting it silently, and an export prunes it, unlinking the entry
itself and never what it points at.

`interchange.Tier` names which kinds a set may carry, enforced at write time
so a misrouted record fails rather than leaking: the public tier takes
opt-outs, routes and clean `certificate/v1` records, the members tier takes
`certificate/v2` only, and claims are on neither, since publishing a hash set
would hand a member something to enumerate offline.

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
  trimmed, uppercased, empties dropped, sorted, deduplicated, joined with a
  bare comma (empty stays empty).

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

## Feeds

Each tier is a git remote serving one record set in the layout above:

| Tier | Remote | Carries |
|------|--------|---------|
| public | `federation_public_feed`, plain git, anyone may clone | `optout`, `route`, and clean `certificate/v1` |
| members | `federation_members_feed`, every record age-encrypted to `recipients_file` | `certificate/v2` only |

The split is about what a record discloses. An opt-out, a disclosure route
and a clean certificate say nothing about a live weakness. A `certificate/v2`
says an advisory's advertised fix does not hold on a named repository, which
is exploitable information, so those records are encrypted with the same age
recipients as [encrypted sharing](encrypted-sharing.md).

Two exclusions apply to every record: an opted-out repository is withdrawn
from the `route` and `certificate` records as well as from scanning, since
republishing a maintainer's disclosure route works against the request not to
contact them, and a local (`file://`) repository is never published at all,
because its URL is a path on the operator's own filesystem. A disclosure
channel with no `disclosure_channel_at` is skipped too: `verified_at` has to
be a timestamp that only moves when the channel does, or every export would
rewrite the whole feed.

### Export and import jobs

Both run hourly from one goroutine, starting with an immediate pass so a
freshly configured feed populates without waiting out a tick. The job is
dormant when no feed is configured. The import runs first: an opt-out landing
this pass withdraws its repository from the `route` and `certificate` records,
and exporting first would keep publishing the disclosure route of a repository
a peer has just said not to contact for another whole tick.

The export syncs each tier's working clone under `<data>/work/feeds/<tier>`,
re-pointing `origin` when the configured remote changed so editing a feed
remote does not keep publishing to the old one, hard-resetting to the branch's remote-tracking ref so local commits that
never landed are discarded rather than accumulating into a permanent push
conflict, rewrites the clone to exactly the records this instance currently
stands behind, and commits and pushes only if that changed something. An
unchanged feed costs a fetch. A clone that died partway leaves a destination
git refuses, so the leftovers are cleared before a re-clone rather than
wedging every later tick.

The import clones each remote in `federation_import_feeds` read-only under
`<data>/work/feeds/import/<digest>` and archives every record into
`interchange_records` exactly as the peer published it, keyed by
`(feed, predicate_type, subject_digest)` so two peers disagreeing about the
same subject each keep their row. A record that fails to decrypt, validate
or decode is logged and skipped: one bad file from a peer must not cost the
rest of the feed.

Two kinds also apply locally. A record is applied once and then stamped
`applied_at`, which is what stops the hourly pass from reinstating what an
operator deliberately cleared. The stamp is written only after the record has
actually been acted on, so a record whose apply failed, or one naming a
repository this instance does not track yet, stays open and is retried on a
later pass: a peer publishing an opt-out before this operator imports the
repository would otherwise have it archived and never honoured. Bytes that
differ from the archived ones clear the stamp, so a peer's correction is
applied too. The stamp records which repository row it was written against,
and deleting that repository clears it: a repository removed and re-added
gets the peer's still-standing opt-out again rather than staying scannable
behind a stamp naming a row that is gone.

- an `optout` sets `federation_opt_out_at` on the matching repository
  whichever peer sent it, since refusing to scan is the conservative
  direction, and then cancels that repository's queued, running and paused
  scans exactly as the repository page does: it is the same maintainer's
  request, so it stops the work already under way rather than only refusing
  the next one;
- a `route` fills `disclosure_channel` only when this instance has none and
  the repository has not opted out, suffixed with the peer feed so an analyst
  can tell a peer's hint from an address the `maintainers` skill read out of
  a verified SECURITY.md. The one channel it also overwrites is the unstamped
  hint this same feed left on an earlier pass, which is what makes a peer
  correcting its own route take effect instead of being archived next to the
  address it replaces; a stamped channel or another feed's hint is left
  alone. It leaves `disclosure_channel_at` unset, which
  keeps the imported string off this instance's own export: republishing it
  would present a hint nobody here validated as a confirmed route, carry the
  peer feed remote into a public record, and make one peer's claim look like
  two independent ones. An analyst editing the channel stamps it and puts it
  on the feed.

The repository row behind each decision is re-read per record rather than
taken from the index, and held under that repository's federation lock while
the record is applied: opt-outs sort before routes, so an opt-out applied
earlier in the same pass has already changed what the route decision turns
on, and the lock is the one the repository page takes to record an opt-out
and the scheduler takes before its network calls, so an opt-out committed
elsewhere cannot land between the read and the write. Repositories are
matched by the same canonical URL the records carry (lowercased, trailing `/`
and `.git` stripped), which is why the lookup is a map built in Go rather
than a SQL join.

## Configuration

```yaml
federation_salt: "shared secret distributed out of band"
federation_contact: "security@example.com"
federation_public_feed: "git@github.com:example/scrutineer-public-feed.git"
federation_members_feed: "git@github.com:example/scrutineer-members-feed.git"
federation_import_feeds:
  - "https://github.com/peer/scrutineer-public-feed.git"
```

Everything defaults to empty, and each part switches on independently: an
empty salt disables the claim-check endpoint, while the feeds are driven by
their own remotes and run without a salt, since no feed record carries a
finding hash. Startup refuses a salt without a contact. The salt is
deliberately config-file only (no CLI flag): a secret in argv leaks via `ps`
and shell history. The contact may also be set with `-federation-contact`,
and the two feed remotes with `-federation-public-feed` /
`-federation-members-feed`. The import list is config-file only: a
repeatable flag would duplicate what a YAML sequence already expresses.

Startup also refuses `federation_members_feed` without `recipients_file` and
at least one decryption source from `identity_file` or `identity_plugins`, the
two tiers sharing one git remote (each would prune what the other publishes),
and any feed remote carrying credentials: the remote reaches the job's error
messages and log fields, so a token in one would end up in the logs. Configure
a git credential helper on the host instead. The refusal itself names the
remote with its userinfo replaced, since that message is what the startup
logger prints.

Federation runs once immediately at startup and then hourly. When an encrypted
members feed uses `identity_plugins`, either the read-back check for an export
or an encrypted imported record can invoke the selected plugin during those
passes. Interactive authentication and hardware-touch requirements belong to
the plugin; headless deployments need the plugin's own noninteractive support.
If an unchanged encrypted export record cannot be decrypted, the pass fails and
leaves its existing ciphertext untouched rather than silently replacing it.

Feed remotes are pushed with the ambient git credentials and
`GIT_TERMINAL_PROMPT=0`, so a remote whose credentials are missing fails the
job fast instead of blocking it on a prompt nobody can answer, and under
`GIT_ALLOW_PROTOCOL=https:ssh:file`, so an ambient `url.<base>.insteadOf` on
the host cannot rewrite a validated feed remote onto a transport (`ext::`,
which hands git a shell command) that startup never approved.

Like the rest of the web surface, `/claim-check` sits behind the loopback
Host check (see [threatmodel.md](../threatmodel.md)). Exposing it to peers is
a deployment decision: front it with a reverse proxy that forwards only
`POST /claim-check` and sets `Host: 127.0.0.1:8080`.
