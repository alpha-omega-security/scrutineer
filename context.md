# Context for the todo backlog

Notes on why the items in todo.md exist and how they fit together. Written so a fresh session can pick up without re-deriving the design. Read alongside todo.md, internal/db/db.go, internal/worker/schema.json, and the mythos repo at ~/code/mythos (spec-deep.md, disclose.md, spec-json.schema.json).

## What scrutineer is becoming

The current build is a local web frontend that queues scans against a repo and stores results in sqlite. The direction it's heading is a CRM for upstream vulnerability disclosure: the finding is the lead, the maintainer is the contact, the disclosure is the deal moving through a pipeline. The audit job is lead generation. CSAF/VEX, OSV records, and disclosure emails are document templates generated at the right pipeline stage.

That reframe means the centre of gravity moves from Finding to Maintainer. One maintainer owns many repos; three findings across two of their repos should batch into one conversation. A maintainer who hasn't responded in 30 days needs a follow-up. A maintainer who's gone silent everywhere routes all their findings to a different path entirely. None of that works if maintainer is just a string on a finding row.

## The job pattern

Every job in the pipeline is one of two kinds. Deterministic jobs call an API or run a tool and store what comes back: metadata, packages, dependents, brief, git-pkgs, sbom, semgrep, zizmor, and the planned advisories/commits/issues lookups. Model-backed jobs gather context deterministically, hand it to claude with a spec prompt, get JSON back conforming to a schema, and parse it into rows. The audit job is the only model-backed one today; there are about six more implied by the workflow.

Each model-backed job is a triple: a gather function in Go, a spec-*.md prompt in mythos, and a *.schema.json contract in mythos that scrutineer embeds. The worker's wrap() already handles the lifecycle uniformly so each new one is the same shape as doClaude.

The model-backed jobs that need to exist, roughly in value order:

exposure: per top-N dependent of a finding, clone the dependent, trace whether the vulnerable call site is reachable with hostile input. Output is `{status: affected|not_affected, justification: <vex enum>, detail}` per dependent, written to a FindingDependent join table. This turns reach from prose into VEX rows and is what makes the CSAF export possible.

route: contact discovery for a repo. Gather SECURITY.md, security.txt, GHSA-enabled check, registry owner, recent github events. Model decides which route is live and who the actual human is. Output `{channel, address, maintainer, confidence, evidence}` to ContactRoute and Maintainer rows. disclose.md's "Find the disclosure path" section is the spec.

health: zombie detection. Gather pushed_at, dependent counts, issue response times, maintainer activity across all their packages. Model distinguishes "feature-complete and stable" from "abandoned". Output `{health: active|stale|abandoned|zombie, reasons[], last_signal}` to Repository.health. A zombie is abandoned plus heavily depended on.

confirm: re-derive a finding's reproduction independently of the audit that produced it. disclose.md's first section. Output confirmed or rejected with the reason.

draft: given a confirmed finding plus its ContactRoute and any prior Communication, propose cvss vector, structured references, verified affected range, and the disclosure text. disclose.md's last two sections. Output goes to proposed_* columns on Finding so a human can edit before approving.

alternatives: given a zombie package, search for forks, successors, and API-equivalent replacements; evaluate whether each is actually maintained and how hard migration is. Output Alternative rows.

migrate: given a zombie finding plus alternatives plus each affected dependent's call site, write a migration guide and per-dependent recommendations (pin below the affected range, move to alternative X, add a guard at the call site, vendor and patch).

fixaudit: given an existing CVE for the repo (from the advisories job), the fix commit, and current code, check whether the fix actually holds. Three questions: does the original reproduction still fail (regression), can the fix be bypassed as written, does the same sink pattern exist elsewhere untouched by the fix commit (variant). Output `{status: fixed|bypass|variant|regressed, evidence, finding?}`. Fixed becomes a public-tier certificate ("CVE-X verified closed at commit Y"). Anything else becomes a new Finding with cwe and prior-art pre-filled from the advisory, entering the normal lifecycle. spec-deep already does this incidentally in its prior-art step (see the lilconfig report's CVE-2024-21537 check); spec-fixaudit makes it the whole job. Re-run on each new release for a regression watch. The set of historical CVEs is also a calibration corpus for spec-deep: known vuln, known location, measure whether a cold audit finds it.

## Finding lifecycle and human gates

Findings get their own job queue. After the audit scan inserts Finding rows, the worker enqueues confirm, dedupe, exposure (one per top-N dependent), route (if not cached for the repo), and draft. Scan grows a nullable FindingID so these are still Scan rows, just finding-scoped.

All of those run automatically and write proposed values. Finding.status is the human gate:

    new -> (enrichment runs) -> enriched -> [human triages] -> triaged -> [human approves draft] -> ready -> [human sends] -> reported -> acknowledged -> fixed -> published
                                     |
                                     +-> rejected | duplicate (terminal)

Three clicks: triage (real? severity right?), approve (draft says what I want?), send. Everything between clicks is automatic. As confidence builds you collapse gates, but the rails exist from the start.

Model-filled fields are stored as proposed_* alongside the accepted column (proposed_cvss vs cvss, proposed_draft vs draft) so re-running a scan doesn't clobber human edits, and so you can diff what the model suggested against what shipped. That diff is the feedback loop for tuning the specs in mythos.

## spec-json and the schema family

mythos/spec-json.schema.json is the replacement for internal/worker/schema.json. Current schema.json is minimal (title, severity, cwe, location, confidence, summary, details). spec-json adds: trust boundaries as a structured list, the full sink inventory as an array with `{id, location, class, primitive, consumes}`, ruled_out entries with `{sinks[], step, reason, summary}`, and the per-finding six-step bodies (trace, boundary, validation, prior_art, reach, rating) as separate markdown fields instead of one details blob. sink.class is a 16-value enum matching spec-deep's Phase 1 list so findings aggregate cleanly across the corpus; the concrete language construct goes in primitive. There's a hand-converted example at mythos/overnight/reports-json/markupsafe.json that validates.

Every model-backed job gets its own schema. They share vocabulary, so mythos grows a defs.schema.json holding the common $defs every other schema references: severity, sink_class, vex_justification, cvss, purl, cwe, reference, health, resolution, maintainer_status, markdown. Change an enum there and every job output and every mirroring DB column moves together.

## CSAF/VEX export

CSAF is an export handler reading from the DB, not something the model emits. `/findings/{id}/csaf.json` joins Finding (title, cwe, cvss, affected, fixed_in, remediation, references) + Package.PURL (product identifier) + FindingDependent rows (per-dependent VEX statements) + internal/web/cwe.json (CWE name lookup) + config (publisher, namespace, tracking id). PURLs are already in the DB from the packages and dependents jobs; CWE names are already embedded.

Mapped against the cnascorecard.org rubric (description+affected+references 50pts, CWE 15, CVSS vector 15, CPE/purl 10, patch reference 10), a fully populated Finding row scores 100. The fields scrutineer doesn't yet have are cvss vector, structured references[] with tags, affected version range, and fixed_in.

CycloneDX is an alternative VEX carrier: scrutineer already emits CycloneDX SBOMs via git-pkgs, and the format has a vulnerabilities block with analysis fields, so per-dependent exposure could ride inside the SBOM the dependent already consumes.

## Zombies

A finding in a maintained repo goes confirmed -> reported -> fixed -> published. A finding in a zombie repo goes confirmed -> nobody-home -> notify-dependents -> GHSA-with-no-fix -> watch-usage-drop. Same Finding row, Finding.resolution picks the path: fix, migrate, workaround, adopt, wontfix.

For migrate, the outreach inverts. The zombie's maintainer isn't the contact; the maintainers of the top affected dependents are. Each FindingDependent with status=affected becomes its own thread with its own Maintainer and Communication rows. Success isn't a fixed_in version, it's dependent_repos dropping over time, which means re-fetching the dependent count periodically and plotting it.

The ask varies per dependent: pin below the affected range if a safe version exists, migrate to an Alternative if one exists, add a guard at the call site (the VEX justification often is the workaround: "you call it with a literal so you're fine; if you call it with user input do X"), vendor and patch, or in the rare case adopt the package. The migrate job writes one guide and N per-dependent recommendations.

Tiering: top handful of dependents get a private heads-up with embargo, then GHSA-no-fix goes out and Dependabot handles the long tail.

## Glasswing and federation

Glasswing is a proposed coordination protocol (Alpha-Omega/OpenSSF adjacent) for the wave of organisations about to start AI-scanning their upstream OSS dependencies. Goals: consistent engagement playbook, support multiple scanning tools, support all forges, k-of-n scanning for high-risk packages, track per-project engagement, provide engineering and funding help to maintainers. Constraints: maintainers have no obligation to participate, and there must be no central per-project risk database. The actual protocol is undefined as of April 2026; what's below is a candidate.

Each member runs their own instance (scrutineer or otherwise) with their own DB, prompts, and scoring. Federation is via an interchange format any tool can implement, defined in mythos/interchange.schema.json. Four record types: certificate (`{repo, commit, date, spec_version, scanner, finding_count}`), claim (`{repo, finding_hash, opened_at, contact}` meaning "I have an active disclosure here, talk to me before opening yours"), optout (`{maintainer, scope, declared_at}`), route (cached contact discovery).

Secrecy splits these into tiers. optout, route, and certificates with finding_count=0 are public; a plain git repo of NDJSON, OSV-style. The clean certificate is also the "scanned, clean at this commit" badge Glasswing floated. Certificates with nonzero count are members-only, in a SOPS/age-encrypted git repo. Claims are not a feed at all because even within the membership an enumerable list of "every package with an open disclosure" is a target list. Instead claims are a point query: before moving a finding to reported, your instance asks each peer `POST /claim-check {hash}` and gets back `{match, contact?}`. No central list, a compromised member can probe for things they already suspect but can't dump everything.

finding_hash is sha256(shared_salt + repo_url + normalised_location + cwe). Without the salt the space is small enough to brute-force (file:line over a known repo times ~1000 CWEs is maybe 10^8 candidates). The salt is a membership secret.

Never in any feed: finding bodies, severity, cvss, health scores, anything that sorts repos into a risk leaderboard.

Prior art: cargo-crev for the git-distributed signed-proofs transport (but crev publishes verdicts, which is the risk score Glasswing rules out). OSV for the many-sources-one-schema-git-transport pattern. in-toto/DSSE for the attestation envelope around certificates, sigstore for signing the public tier. linux-distros@ for the closed-membership embargo norms that the private tier needs regardless of transport. rebuilderd for k-of-n independent verification. None of these have the claim or optout records because nobody has tried to federate pre-disclosure coordination before; existing tools are all post-publication.

scrutineer additions for this: Maintainer.do_not_contact (synced from optout records, suppresses all outbound), Scan.source for k-of-n provenance, finding correlation across scans from different sources, export-feed and import-feeds jobs, and a claim-check endpoint plus an outbound check that fires before any finding moves to reported.

## ossprey

~/code/ossprey (scovetta, Alpha-Omega) predates mythos and is the prior art scrutineer was built in response to. Django, 236k LOC, 36 models, 14 dockerised analyzers, multi-tenant, policy engine with OPA/Rego, Review verdicts (ALLOWED/DISCOURAGED/BANNED), OSV/KEV/EPSS import. It's inward-facing: a downstream org assessing whether its own supply chain is safe.

scrutineer's divergences from it are deliberate. 2.5k lines of Go and sqlite rather than a platform, so one person can read the whole thing. spec-deep is narrow and unscored (first-party sinks only, sink inventory, trace/boundary/validate per sink, no number at the end) where ossprey/prompts/security_review.txt is broad and scored (four phases including deps/config/architecture, overall_security_score 1.0-10.0); the score is the per-project risk metric Glasswing says not to centralise, and spec-deep producing none is on purpose. And scrutineer is outward-facing: ContactRoute, Communication, outbound drafting, do-not-contact, dependent-migration tracking. ossprey has none of that because it's not what it's for.

Where scrutineer should be compatible rather than different: ossprey's assertions framework (assertions/assertion/base.py) wraps everything in in-toto Statement v1, `{_type, subject, predicateType, predicate}`, signed. assertions/assertion/securityreview.py already reads a frontmatter+markdown file and emits it as a predicate, so it can ingest a spec-deep .md report as-is. spec-json should get a predicateType URI and the interchange records (certificate, claim, optout, route) should be in-toto predicates, so anything ossprey-shaped on the other end can consume them without an adapter. Their Finding model's three-tier values (tool / ai_suggested / analyst) and FindingHistory audit table are the established pattern for "model proposes, human disposes, reruns don't clobber"; matching it keeps the data models translatable.

ossprey/prompts/maintainer_osint.txt and triage_finding.txt are worth reading against spec-route and spec-confirm before writing those.

In Glasswing terms: ossprey is what a member runs to assess their own dependencies and decide what needs scanning; scrutineer is what runs the deep audit and manages the upstream conversation; in-toto-wrapped interchange records are how one feeds the other.
