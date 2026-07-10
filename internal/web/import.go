package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gorm.io/gorm"

	"scrutineer/internal/db"
	"scrutineer/internal/ingest"
)

// importMaxBody caps the upload size. SARIF from large monorepo scans
// can run to a few megabytes; 16 MiB leaves headroom without letting an
// errant POST exhaust memory.
const importMaxBody = 16 << 20

// handleImport ingests an externally-produced report (SARIF or the
// minimal JSON shape) and turns it into Repository + Scan + Finding
// rows. The repository is taken from the report's own provenance when
// present; otherwise the caller must pass ?repo=<url>. Each ingest
// batch becomes one Scan row with Kind "import" so the findings have a
// parent and show up in the scans list alongside skill runs.
//
// Response is JSON regardless of Accept so curl callers get structured
// output; a browser upload form can be layered on later.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importMaxBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeAPIError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("body exceeds %d bytes", importMaxBody))
			return
		}
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("read body: %v", err))
		return
	}
	if len(body) == 0 {
		writeAPIError(w, http.StatusBadRequest, "empty body")
		return
	}
	if body, err = s.maybeDecrypt(body); err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	revalidate, err := importRevalidate(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	results, format, err := ingest.Parse(body)
	if errors.Is(err, ingest.ErrUnrecognised) {
		s.importFallback(w, r, body)
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	repoOverride := r.URL.Query().Get("repo")
	out := make([]map[string]any, 0, len(results))
	for _, res := range results {
		summary, err := s.importResult(res, repoOverride, revalidate)
		if err != nil {
			writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		out = append(out, summary)
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"format":  string(format),
		"results": out,
	})
}

// importRevalidate reads the ?revalidate= toggle that controls whether
// each newly-imported finding is fed into the revalidate -> verify funnel.
// Absent means true: the default behaviour, since an external tool's
// severity is an unvalidated claim worth the cheap pre-sort. An explicit
// false (or 0) imports the findings as-is and enqueues nothing — for
// callers ingesting already-audited findings, such as a trusted sharing
// bundle that already carries the full audit narrative. A malformed value
// is a 400 rather than a silent fall-back to true, so a caller that meant
// to disable the funnel never gets billed for it by a typo.
func importRevalidate(r *http.Request) (bool, error) {
	v := r.URL.Query().Get("revalidate")
	if v == "" {
		return true, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("revalidate: must be true or false, got %q", v)
	}
	return b, nil
}

// ingestSkillName is the skill that normalises reports no deterministic
// parser recognises.
const ingestSkillName = "ingest"

// importFallback routes a payload that matched no supported format to the
// ingest skill. The raw bytes ride on the Scan row and the worker stages
// them into the workspace at import/report, where the skill reads them.
// Nothing parsed, so there is no provenance to take a repository from;
// ?repo= is required.
func (s *Server) importFallback(w http.ResponseWriter, r *http.Request, body []byte) {
	repoURL := r.URL.Query().Get("repo")
	if repoURL == "" {
		writeAPIError(w, http.StatusUnprocessableEntity,
			ingest.ErrUnrecognised.Error()+"; pass ?repo= to route the payload to the ingest skill instead")
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", ingestSkillName, true).First(&skill).Error; err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity,
			ingest.ErrUnrecognised.Error()+"; the ingest skill is not available to take it")
		return
	}
	repo, err := s.ensureImportRepo(repoURL)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	scanID, err := s.enqueueSkillWith(r.Context(), repo.ID, skill.ID, ScanOpts{ImportPayload: body})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Log.Info("import: routed unrecognised payload to ingest skill",
		"repo", repo.URL, "scan", scanID, "bytes", len(body))
	s.enqueueImportedRepoMetadata(context.Background(), repo)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"format":        "unrecognised",
		"repository_id": repo.ID,
		"repository":    repo.URL,
		"scan_id":       scanID,
		"skill":         ingestSkillName,
		"status":        "queued",
	})
}

// ensureImportRepo resolves a repository URL from an import request to a
// Repository row, creating it on first sight.
func (s *Server) ensureImportRepo(repoURL string) (db.Repository, error) {
	input, err := ParseRepoInput(repoURL)
	if err != nil {
		return db.Repository{}, fmt.Errorf("repository %q: %w", repoURL, err)
	}
	if input.Local {
		path := strings.TrimPrefix(input.CloneURL, LocalScheme)
		info, statErr := os.Stat(path)
		if statErr != nil {
			return db.Repository{}, fmt.Errorf(
				"repository %q is a sender-local path unavailable on this host; pass ?repo=https://forge/owner/repo to supply a cloneable repository: %w",
				repoURL, statErr)
		}
		if !info.IsDir() {
			return db.Repository{}, fmt.Errorf("repository %q local path is not a directory", repoURL)
		}
	}
	repo := db.Repository{
		URL:     input.CloneURL,
		Name:    input.Name,
		Owner:   input.Owner,
		HTMLURL: DefaultHTMLURL(input.CloneURL),
	}
	if input.Owner != "" {
		repo.FullName = input.Owner + "/" + input.Name
	}
	if err := s.DB.Where(db.Repository{URL: input.CloneURL}).FirstOrCreate(&repo).Error; err != nil {
		return db.Repository{}, err
	}
	return repo, nil
}

func (s *Server) importResult(res ingest.Result, repoOverride string, revalidate bool) (map[string]any, error) {
	repoURL := res.RepoURL
	if repoOverride != "" {
		repoURL = repoOverride
	}
	if repoURL == "" {
		return nil, fmt.Errorf("repository unknown: report has no provenance and no ?repo= supplied")
	}
	repo, err := s.ensureImportRepo(repoURL)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	scan := db.Scan{
		RepositoryID:  repo.ID,
		Kind:          "import",
		Status:        db.ScanDone,
		SkillName:     res.Tool,
		Commit:        res.Commit,
		StartedAt:     &now,
		FinishedAt:    &now,
		FindingsCount: len(res.Findings),
	}
	scan.StatusPriority = db.StatusPriorityFor(scan.Status)

	var created []db.Finding
	var observed int
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&scan).Error; err != nil {
			return err
		}
		created, observed, err = s.importFindings(tx, &scan, res)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.enqueueImportedRepoMetadata(context.Background(), repo)
	// Imported findings carry an external tool's unvalidated severity
	// claim, so revalidate runs over every newly-imported finding
	// regardless of severity (not just High/Critical, as it does for
	// security-deep-dive output). ?revalidate=false skips this — and the
	// verify it chains into — for callers importing already-audited
	// findings such as a trusted sharing bundle. Enqueued after commit so
	// a rolled-back import never queues work against phantom findings.
	if revalidate {
		for i := range created {
			// Imports have no parent scan and hence no resolved profile to carry;
			// revalidate detects fresh, and its resolved profile then carries into
			// the chained verify (autoChainVerifyAfterRevalidate). See #548.
			s.enqueueRevalidateForFinding(context.Background(), &created[i], "")
		}
	}
	s.Log.Info("import",
		"repo", repo.URL, "tool", res.Tool, "scan", scan.ID,
		"created", len(created), "observed", observed)

	ids := make([]uint, len(created))
	for i, f := range created {
		ids[i] = f.ID
	}
	return map[string]any{
		"repository_id": repo.ID,
		"repository":    repo.URL,
		"scan_id":       scan.ID,
		"tool":          res.Tool,
		"created":       len(created),
		"observed":      observed,
		"finding_ids":   ids,
	}, nil
}

const metadataSkillName = "metadata"

// enqueueImportedRepoMetadata gives a repository created by a findings import
// the same minimum viable onboarding as a repository added through the UI: one
// repository-scoped metadata run. That run populates the otherwise-empty row
// and, through the worker's normal remote-source path, creates the clone cache
// without requiring a manual finding action. Existing hollow rows are repaired
// on reimport. A completed, queued, running, or paused metadata run suppresses a
// duplicate; failed and cancelled runs may be retried by reimporting.
//
// Metadata is best-effort. A deployment without the skill still imports the
// findings, and an enqueue failure is logged without rolling back durable data.
func (s *Server) enqueueImportedRepoMetadata(ctx context.Context, repo db.Repository) {
	if repo.IsLocal() {
		return
	}
	var skill db.Skill
	if err := s.DB.Where("name = ? AND active = ?", metadataSkillName, true).First(&skill).Error; err != nil {
		return
	}
	var existing int64
	if err := s.DB.Model(&db.Scan{}).
		Where("repository_id = ? AND skill_name = ? AND status IN ?", repo.ID, metadataSkillName,
			[]db.ScanStatus{db.ScanQueued, db.ScanRunning, db.ScanPaused, db.ScanDone}).
		Count(&existing).Error; err != nil || existing > 0 {
		return
	}
	if _, err := s.enqueueSkillWith(ctx, repo.ID, skill.ID, ScanOpts{}); err != nil {
		s.Log.Warn("import: enqueue repository metadata", "repo", repo.ID, "err", err)
	}
}

const importBatchSize = 50

// importFindings mirrors the worker's fingerprint-then-upsert loop so an
// import behaves like a scan: re-importing the same report bumps
// SeenCount on existing rows instead of inserting duplicates. Runs inside
// the caller's transaction so a mid-import failure leaves no partial state.
func (s *Server) importFindings(tx *gorm.DB, scan *db.Scan, res ingest.Result) (created []db.Finding, observed int, err error) {
	incoming, relations, fingerprints := buildImportFindings(scan, res)
	if len(incoming) == 0 {
		return nil, 0, nil
	}

	existing, err := existingByFingerprint(tx, scan.RepositoryID, fingerprints)
	if err != nil {
		return nil, 0, fmt.Errorf("lookup existing findings: %w", err)
	}

	// observedRel pairs an already-present finding with the child records this
	// re-import carries for it, attached (deduped) after the seen-count bump.
	type observedRel struct {
		id   uint
		rels importFindingRelations
	}
	var observedIDs []uint
	var observedRels []observedRel
	var history []db.FindingHistory
	var createdRels []importFindingRelations
	for i, f := range incoming {
		if prev, ok := existing[f.Fingerprint]; ok {
			observedIDs = append(observedIDs, prev.ID)
			history = append(history, db.FindingHistory{
				FindingID: prev.ID,
				Field:     "observed",
				NewValue:  fmt.Sprintf("import scan %d (%s)", scan.ID, res.Tool),
				Source:    db.SourceTool,
				By:        res.Tool,
			})
			observedRels = append(observedRels, observedRel{prev.ID, relations[i]})
			continue
		}
		created = append(created, f)
		createdRels = append(createdRels, relations[i])
	}

	if len(created) > 0 {
		if err := tx.CreateInBatches(&created, importBatchSize).Error; err != nil {
			return nil, 0, fmt.Errorf("create findings: %w", err)
		}
		// Brand-new findings have no prior child rows, so attach without the
		// dedup lookup.
		for i := range created {
			if err := attachFindingRelations(tx, created[i].ID, createdRels[i], false); err != nil {
				return nil, 0, err
			}
		}
	}
	if len(observedIDs) > 0 {
		err := tx.Model(&db.Finding{}).Where("id IN ?", observedIDs).Updates(map[string]any{
			"last_seen_scan_id":   scan.ID,
			"last_seen_commit":    scan.Commit,
			"seen_count":          gorm.Expr("seen_count + 1"),
			"missed_count":        0,
			"last_missed_scan_id": 0,
		}).Error
		if err != nil {
			return nil, 0, fmt.Errorf("update observed findings: %w", err)
		}
		if err := tx.CreateInBatches(&history, importBatchSize).Error; err != nil {
			return nil, 0, fmt.Errorf("create finding history: %w", err)
		}
		// Re-importing a bundle onto findings this instance already has appends
		// only the child records it does not already carry, so a repeat import
		// is idempotent rather than piling up duplicate notes.
		for _, o := range observedRels {
			if err := attachFindingRelations(tx, o.id, o.rels, true); err != nil {
				return nil, 0, err
			}
		}
	}
	return created, len(observedIDs), nil
}

// attachFindingRelations writes a finding's carried child records. With dedup
// set (the finding already existed on this instance) it drops any record whose
// content already exists on that finding, so re-importing the same bundle does
// not accumulate duplicate notes/communications/references.
func attachFindingRelations(tx *gorm.DB, findingID uint, rels importFindingRelations, dedup bool) error {
	if rels.empty() {
		return nil
	}
	notes, comms, refs := rels.Notes, rels.Communications, rels.References
	if dedup {
		var have importFindingRelations
		if err := tx.Where("finding_id = ?", findingID).Find(&have.Notes).Error; err != nil {
			return fmt.Errorf("load existing notes: %w", err)
		}
		if err := tx.Where("finding_id = ?", findingID).Find(&have.Communications).Error; err != nil {
			return fmt.Errorf("load existing communications: %w", err)
		}
		if err := tx.Where("finding_id = ?", findingID).Find(&have.References).Error; err != nil {
			return fmt.Errorf("load existing references: %w", err)
		}
		notes = dedupBy(notes, have.Notes, noteKey)
		comms = dedupBy(comms, have.Communications, commKey)
		refs = dedupBy(refs, have.References, refKey)
	}
	for i := range notes {
		notes[i].ID, notes[i].FindingID = 0, findingID
	}
	for i := range comms {
		comms[i].ID, comms[i].FindingID = 0, findingID
	}
	for i := range refs {
		refs[i].ID, refs[i].FindingID = 0, findingID
	}
	if len(notes) > 0 {
		if err := tx.Create(&notes).Error; err != nil {
			return fmt.Errorf("create finding notes: %w", err)
		}
	}
	if len(comms) > 0 {
		if err := tx.Create(&comms).Error; err != nil {
			return fmt.Errorf("create finding communications: %w", err)
		}
	}
	if len(refs) > 0 {
		if err := tx.Create(&refs).Error; err != nil {
			return fmt.Errorf("create finding references: %w", err)
		}
	}
	return nil
}

// dedupBy returns the members of incoming whose key is not already present in
// existing, also collapsing duplicates within incoming.
func dedupBy[T any](incoming, existing []T, key func(T) string) []T {
	have := make(map[string]bool, len(existing))
	for _, e := range existing {
		have[key(e)] = true
	}
	var out []T
	for _, in := range incoming {
		k := key(in)
		if have[k] {
			continue
		}
		have[k] = true
		out = append(out, in)
	}
	return out
}

// noteKey/commKey/refKey identify a child record by its content for idempotent
// re-import. Timestamps are part of the key: scrutineer's own bundle preserves
// them across the round-trip, so the same note keys identically on re-import.
func noteKey(n db.FindingNote) string {
	return strings.Join([]string{n.Body, n.By, n.CreatedAt.UTC().Format(time.RFC3339Nano)}, "\x00")
}

func commKey(c db.FindingCommunication) string {
	return strings.Join([]string{c.Channel, c.Direction, c.Actor, c.Body, c.At.UTC().Format(time.RFC3339Nano)}, "\x00")
}

func refKey(r db.FindingReference) string {
	return strings.Join([]string{r.URL, r.Tags, r.Summary}, "\x00")
}

// buildImportFindings maps ingest.Finding rows onto db.Finding and
// fingerprints them, dropping in-batch duplicates.
func buildImportFindings(scan *db.Scan, res ingest.Result) ([]db.Finding, []importFindingRelations, []string) {
	seen := map[string]bool{}
	incoming := make([]db.Finding, 0, len(res.Findings))
	relations := make([]importFindingRelations, 0, len(res.Findings))
	fingerprints := make([]string, 0, len(res.Findings))
	for _, in := range res.Findings {
		// A bundle may carry a per-finding commit (findings from scans at
		// different revisions); fall back to the scan/bundle commit, which is
		// all the other formats supply.
		commit := firstNonEmpty(in.Commit, scan.Commit)
		f := db.Finding{
			ScanID:         scan.ID,
			RepositoryID:   scan.RepositoryID,
			Commit:         commit,
			SubPath:        in.SubPath,
			Title:          in.Title,
			Severity:       in.Severity,
			Confidence:     firstNonEmpty(in.Confidence, "low"),
			CWE:            in.CWE,
			Location:       in.Location,
			Locations:      in.Locations,
			Sinks:          in.Sinks,
			VID:            in.VID,
			Reachability:   in.Reachability,
			QualityTier:    in.QualityTier,
			Trace:          appendFixDescription(in.Description, in.SuggestedFix, in.FixCommit),
			Boundary:       in.Boundary,
			Validation:     in.Validation,
			PriorArt:       in.PriorArt,
			Reach:          in.Reach,
			Rating:         in.Rating,
			ImportedFrom:   res.Tool,
			LastSeenScanID: scan.ID,
			LastSeenCommit: commit,
			SeenCount:      1,
		}
		// include=all archival fields. Empty for the default bundle and every
		// other format, so those imports write the same columns they always did.
		f.Snippet = in.Snippet
		f.Affected = in.Affected
		f.FixVersion = in.FixVersion
		f.CVEID = in.CVEID
		f.GHSAID = in.GHSAID
		f.Mitigation = in.Mitigation
		f.MitigationSemgrep = in.MitigationSemgrep
		f.BreakingChange = in.BreakingChange
		f.BreakingChangeRationale = in.BreakingChangeRationale
		f.DupCheck = in.DupCheck
		f.DisclosureDraft = in.DisclosureDraft
		f.ExploitedInWild = in.ExploitedInWild
		f.ExploitedInWildEvidence = in.ExploitedInWildEvidence
		// The real upstream fix commit lands in FixCommit; the bundle's legacy
		// fix_commit (the SuggestedFix base) was already folded into Trace above.
		f.FixCommit = in.UpstreamFixCommit
		// CVSS scores are derived, never carried: recompute from the vector so a
		// hand-edited or stale bundle score cannot stick. An empty/invalid
		// vector yields a zero score, matching syncCVSSScore.
		f.CVSSVector = in.CVSSVector
		f.CVSSScore, _ = db.CVSSV3ScoreFromVector(in.CVSSVector)
		f.CVSSv4Vector = in.CVSSv4Vector
		f.CVSSv4Score, _ = db.CVSSV4ScoreFromVector(in.CVSSv4Vector)
		// Include the sub-path so two findings at the same CWE/location/title
		// in different monorepo sub-projects do not collide on one fingerprint.
		// Other formats leave SubPath empty, so their fingerprint is unchanged.
		f.Fingerprint = db.FingerprintFinding(res.Tool, f.SubPath, f.CWE, f.Location, f.Title)
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		incoming = append(incoming, f)
		relations = append(relations, importRelationsFrom(in))
		fingerprints = append(fingerprints, f.Fingerprint)
	}
	return incoming, relations, fingerprints
}

// importFindingRelations holds the child records an import carries for one
// finding. Populated only from an include=all bundle; every other format leaves
// the slices nil, so attachFindingRelations is a no-op there.
type importFindingRelations struct {
	Notes          []db.FindingNote
	Communications []db.FindingCommunication
	References     []db.FindingReference
}

func (r importFindingRelations) empty() bool {
	return len(r.Notes) == 0 && len(r.Communications) == 0 && len(r.References) == 0
}

// importRelationsFrom maps an ingest finding's carried child records onto their
// db rows. IDs are left zero (assigned on insert) and FindingID is set later by
// attachFindingRelations once the parent finding has an id.
func importRelationsFrom(in ingest.Finding) importFindingRelations {
	var rel importFindingRelations
	for _, n := range in.Notes {
		rel.Notes = append(rel.Notes, db.FindingNote{Body: n.Body, By: n.By, CreatedAt: n.CreatedAt})
	}
	for _, c := range in.Communications {
		rel.Communications = append(rel.Communications, db.FindingCommunication{
			Channel:     c.Channel,
			Direction:   c.Direction,
			Actor:       c.Actor,
			Body:        c.Body,
			OfferedHelp: c.OfferedHelp,
			At:          c.At,
			CreatedAt:   c.CreatedAt,
		})
	}
	for _, ref := range in.References {
		rel.References = append(rel.References, db.FindingReference{
			URL:       ref.URL,
			Tags:      ref.Tags,
			Summary:   ref.Summary,
			CreatedAt: ref.CreatedAt,
		})
	}
	return rel
}

// existingByFingerprint fetches all findings for the repository whose
// fingerprint is in the incoming set, keyed by fingerprint. When legacy
// duplicate rows share a fingerprint the lowest-id row wins, matching the
// previous per-row `Order("id").First` behaviour.
func existingByFingerprint(tx *gorm.DB, repoID uint, fingerprints []string) (map[string]db.Finding, error) {
	var rows []db.Finding
	err := tx.Select("id", "fingerprint").
		Where("repository_id = ? AND fingerprint IN ?", repoID, fingerprints).
		Order("id").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[string]db.Finding, len(rows))
	for _, r := range rows {
		if _, ok := out[r.Fingerprint]; !ok {
			out[r.Fingerprint] = r
		}
	}
	return out, nil
}

// maybeDecrypt transparently decrypts an age-encrypted body. If the body
// is not encrypted (no age header), it is returned unchanged — so
// unencrypted imports keep working regardless of whether identities are
// configured.
//
// The live DB stays plaintext by design (it is inside the trust boundary);
// only the exported sharing artifact is encrypted.
//
// No revocation: removing someone from the recipients file only blocks
// future exports; anything they already received stays decryptable.
//
// No sender authentication: a recipient can verify the bundle wasn't
// tampered with, but not cryptographically prove who produced it.
func (s *Server) maybeDecrypt(body []byte) ([]byte, error) {
	const ageBinaryMagic = "age-encryption.org/v1\n"
	var src io.Reader
	switch {
	case bytes.HasPrefix(body, []byte(armor.Header)):
		src = armor.NewReader(bytes.NewReader(body))
	case bytes.HasPrefix(body, []byte(ageBinaryMagic)):
		src = bytes.NewReader(body)
	default:
		return body, nil // not encrypted — pass straight through
	}
	if len(s.EncIdentities) == 0 {
		return nil, errors.New("encrypted import received but no identity configured (-identity-file)")
	}
	r, err := age.Decrypt(src, s.EncIdentities...)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return io.ReadAll(r)
}

// appendFixDescription folds an ingested fix description into the Trace
// markdown rather than writing Finding.SuggestedFix, which is reserved for
// diffs that have passed gatePatch (see finding_patch.go). When the source
// also supplied the base commit the fix applies to, it is noted alongside so
// the operator can rebase before promoting the diff.
func appendFixDescription(desc, fix, fixCommit string) string {
	fix = strings.TrimSpace(fix)
	if fix == "" {
		return desc
	}
	section := "## Suggested fix\n\n"
	if fixCommit = strings.TrimSpace(fixCommit); fixCommit != "" {
		section += "Applies to commit `" + fixCommit + "`.\n\n"
	}
	section += fix
	if desc == "" {
		return section
	}
	return desc + "\n\n" + section
}
