
- [x] produce a summary report of the whole repository after running all the jobs
  - threat model tab covers boundaries, inventory, ruled_out, prior_art, reach from the claude audit

- [x] maintainers table
  - [x] name, email, github username, company, status
  - [x] repositories (many-to-many)
  - [x] populated from commits + packages + model-backed analysis
  - [x] maintainers index, show page, repo tab
  - [ ] finding count per maintainer on the index page

- [x] swap schema.json for spec-json (boundaries, inventory, ruled_out, per-step prose)
  - [x] defs.schema.json shared vocabulary
  - [x] spec-deep.md embedded as default spec
  - [x] backfill sinks from stored reports on startup

- [ ] update findings with:
  - [x] status (new/enriched/triaged/ready/reported/acknowledged/fixed/published/rejected/duplicate)
  - [x] notes
  - [ ] communication log (structured, not just free text)
  - [ ] disclosure draft
  - [ ] fix version / fix commit
  - [ ] CVE ID
  - [ ] cvss vector
  - [ ] affected version range (column exists, not editable in UI)
  - [ ] references[] with tags
  - [ ] resolution (fix|migrate|workaround|adopt|wontfix)

- [ ] contact route per repo (security.md, ghsa, security.txt, registry owner)
  - [ ] route discovery job

- [ ] finding_dependents join (finding_id, dependent_id, status, justification)
- [ ] csaf/vex export per finding

- [ ] zombies
  - [ ] repository.health (active|stale|abandoned|zombie)
  - [ ] health scoring job (dependents x pushed_at x maintainer activity)
  - [ ] alternatives table (purl, fork|successor|equivalent)
  - [ ] migration guide on finding
  - [ ] per-dependent campaign tracking (notified|acked|migrated|declined|silent)
  - [ ] re-fetch dependent counts over time, plot on finding

- [ ] finding-scoped scans
  - [ ] Scan.FindingID (nullable)
  - [ ] enqueueForFinding helper
  - [ ] auto-enqueue after audit inserts findings
  - [x] confirm job: verify button on finding page (placeholder, needs real implementation)
  - [ ] dedupe job: advisories + issue search -> duplicate or continue
  - [ ] exposure job: per top-N dependent, trace call site -> finding_dependents
  - [ ] draft job: cvss, references, affected range, disclosure text -> proposed_* cols

- [ ] fix audits (did existing CVEs actually get fixed)
  - [ ] Advisory model from advisories.ecosyste.ms (done, column exists)
  - [ ] fixaudit job per advisory: original repro, bypass attempt, variant hunt
  - [ ] spec-fixaudit.md + fixaudit.schema.json in mythos
  - [ ] output {status: fixed|bypass|variant|regressed, evidence, finding?}
  - [ ] status=fixed -> public certificate; else -> new Finding pre-filled with cwe + advisory ref
  - [ ] re-run on new releases (regression watch)
  - [ ] use as spec-deep calibration corpus

- [ ] finding lifecycle refinements
  - [ ] three-tier values: tool / model_suggested / analyst (cf ossprey)
  - [ ] FindingHistory table (field, old, new, by, at) instead of proposed_* columns
  - [ ] finding page as review surface: editable fields, inline save
  - [ ] diff model_suggested vs analyst from history for spec tuning feedback

- [ ] mythos spec/schema pairs
  - [x] defs.schema.json (shared $defs)
  - [x] spec-json.schema.json embedded
  - [ ] split disclose.md -> spec-confirm.md + spec-draft.md
  - [ ] spec-exposure.md + exposure.schema.json
  - [ ] spec-route.md + route.schema.json
  - [ ] spec-health.md + health.schema.json
  - [ ] spec-alternatives.md + alternatives.schema.json
  - [ ] spec-migrate.md + migrate.schema.json
  - [ ] spec-fixaudit.md + fixaudit.schema.json
  - [ ] interchange.schema.json
  - [ ] embed new schemas in scrutineer alongside schema.json

- [ ] glasswing alignment
  - [ ] Maintainer.do_not_contact (suppresses all outbound, syncable)
  - [ ] Scan.source (org/person who ran it, for k-of-n provenance)
  - [ ] correlate findings across scans (same location+cwe from N sources)
  - [ ] scan certificate export (repo, commit, date, spec_version, count -- no details)
  - [ ] import external scan certificates (skip already-covered)
  - [ ] offered_help on Communication (pr|funding|adoption, not just reports)

- [ ] interchange (federation between instances / non-scrutineer tools)
  - [ ] envelope: in-toto Statement v1, one predicateType URI per record kind
  - [ ] interchange.schema.json in mythos: certificate, claim, optout, route as predicate schemas
  - [ ] public feed: optout, route, clean certificates (count=0) -- plain git repo
  - [ ] members-only feed: nonzero certificates -- SOPS/age-encrypted git
  - [ ] claims: point-query only, not a feed -- POST /claim-check {hash} -> {match, contact}
  - [ ] finding_hash = sha256(shared_salt + repo + normalised_location + cwe)
  - [ ] export-feed job: write public + encrypted records
  - [ ] import-feeds job: pull peer feeds, mark covered-elsewhere, set do_not_contact
  - [ ] claim-check endpoint + outbound check before status->reported
  - [ ] never in any feed: finding bodies, severity, cvss, health scores
  - [ ] sigstore signing for public tier (later)

---

Lower priority / nice to have:

- [ ] fetch usage in docker images from docker.ecosyste.ms
- [ ] chat with claude about the repo
- [ ] chat with claude about a finding
- [ ] claude summary of dependency tree
- [ ] search (repos, findings, packages)
- [ ] test coverage improvements
- [ ] end of life detection
