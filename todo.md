
- [ ] produce a summary report of the whole repository after running all the jobs

- [ ] update findings with:
  - [ ] status 
  - [ ] communication
  - [ ] disclosure
  - [ ] notes
  - [ ] fix 
  - [ ] CVE ID

- [ ] maintainers table
  - [ ] name
  - [ ] company (if any)
  - [ ] email
  - [ ] github username
  - [ ] repositories
  - [ ] status (active, inactive, unknown)

- [ ] swap schema.json for spec-json (boundaries, inventory, ruled_out, per-step prose)
- [ ] more finding fields
  - [ ] cvss vector
  - [ ] affected version range
  - [ ] references[] with tags
  - [ ] resolution (fix|migrate|workaround|adopt|wontfix)

- [ ] contact route per repo (security.md, ghsa, security.txt, registry owner)
  - [ ] route discovery job

- [ ] finding_dependents join (finding_id, dependent_id, status, justification)
- [ ] csaf/vex export per finding

- [ ] zombies
  - [ ] repository.health (active|stale|abandoned|zombie)
  - [ ] health scoring job (dependents × pushed_at × maintainer activity)
  - [ ] alternatives table (purl, fork|successor|equivalent)
  - [ ] migration guide on finding
  - [ ] per-dependent campaign tracking (notified|acked|migrated|declined|silent)
  - [ ] re-fetch dependent counts over time, plot on finding

- [ ] finding-scoped scans
  - [ ] Scan.FindingID (nullable)
  - [ ] enqueueForFinding helper
  - [ ] auto-enqueue after audit inserts findings
  - [ ] confirm job: re-derive repro independently → confirmed|rejected
  - [ ] dedupe job: advisories + issue search → duplicate or continue
  - [ ] exposure job: per top-N dependent, trace call site → finding_dependents
  - [ ] draft job: cvss, references, affected range, disclosure text → proposed_* cols

- [ ] fix audits (did existing CVEs actually get fixed)
  - [ ] Advisory model from advisories.ecosyste.ms (cve, cwe, affected, fixed_in, fix_commit, refs)
  - [ ] fixaudit job per advisory: original repro, bypass attempt, variant hunt
  - [ ] spec-fixaudit.md + fixaudit.schema.json in mythos
  - [ ] output {status: fixed|bypass|variant|regressed, evidence, finding?}
  - [ ] status=fixed → public certificate; else → new Finding pre-filled with cwe + advisory ref
  - [ ] re-run on new releases (regression watch)
  - [ ] use as spec-deep calibration corpus

- [ ] finding lifecycle
  - [ ] Finding.status enum (new|enriched|triaged|ready|reported|acknowledged|fixed|published|rejected|duplicate)
  - [ ] three-tier values: tool / model_suggested / analyst (cf ossprey severity_level/ai_suggested_severity/analyst_severity_level)
  - [ ] FindingHistory table (field, old, new, by, at) instead of proposed_* columns; is_analyst_modified() guards reruns
  - [ ] human gates: triage, approve draft, send
  - [ ] finding page as review surface: editable fields, scan list, status buttons
  - [ ] diff model_suggested vs analyst from history for spec tuning feedback

- [ ] mythos spec/schema pairs
  - [ ] defs.schema.json (shared $defs: severity, sink_class, vex_justification, cvss, purl, reference, health, resolution, maintainer_status, markdown)
  - [ ] split disclose.md → spec-confirm.md + spec-draft.md
  - [ ] spec-exposure.md + exposure.schema.json
  - [ ] spec-route.md + route.schema.json
  - [ ] spec-health.md + health.schema.json
  - [ ] spec-alternatives.md + alternatives.schema.json
  - [ ] spec-migrate.md + migrate.schema.json
  - [ ] spec-fixaudit.md + fixaudit.schema.json
  - [ ] interchange.schema.json (certificate, claim, optout, route — the federation wire format)
  - [ ] embed schemas in scrutineer alongside schema.json

- [ ] glasswing alignment
  - [ ] Maintainer.do_not_contact (suppresses all outbound, syncable)
  - [ ] Scan.source (org/person who ran it, for k-of-n provenance)
  - [ ] correlate findings across scans (same location+cwe from N sources)
  - [ ] scan certificate export (repo, commit, date, spec_version, count — no details)
  - [ ] import external scan certificates (skip already-covered)
  - [ ] offered_help on Communication (pr|funding|adoption, not just reports)

- [ ] interchange (federation between instances / non-scrutineer tools)
  - [ ] envelope: in-toto Statement v1, one predicateType URI per record kind (matches ossprey assertions/)
  - [ ] interchange.schema.json in mythos: certificate, claim, optout, route as predicate schemas
  - [ ] public feed: optout, route, clean certificates (count=0) — plain git repo
  - [ ] members-only feed: nonzero certificates — SOPS/age-encrypted git
  - [ ] claims: point-query only, not a feed — POST /claim-check {hash} → {match, contact}; no enumerable list
  - [ ] finding_hash = sha256(shared_salt + repo + normalised_location + cwe); salt stops non-member brute force
  - [ ] export-feed job: write public + encrypted records
  - [ ] import-feeds job: pull peer feeds, mark covered-elsewhere, set do_not_contact
  - [ ] claim-check endpoint + outbound check before status→reported
  - [ ] never in any feed: finding bodies, severity, cvss, health scores
  - [ ] prior art: linux-distros@ for closed-group embargo norms; crev for git transport; SOPS/age for encrypted-records-in-git
  - [ ] sigstore signing for public tier (later)

---

Lower priority / nice to have:

- [ ] fetch usage in docker images from https://docker.ecosyste.ms/api/v1/repositories/lookup?url=
- [ ] chat with claude about the repo
- [ ] chat with claude about a finding
- [ ] claude summary of dependency tree
- [ ] search (repos, findings, packages)
- [ ] test coverage
- [ ] end of life
